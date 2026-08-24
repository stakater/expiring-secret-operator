/*
Copyright 2025 Stakater.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	testutils "github.com/stakater/expiring-secret-operator/test/utils"
)

// fixedExpiry keeps CollectAndCompare deterministic: a wall-clock value
// would change between runs.
const fixedExpiryUnix = int64(1800000000)

func monitorWithStatus(
	name, namespace, secretName, secretNamespace, service string,
	state expiringsecretv1alpha1.MonitorState,
) *expiringsecretv1alpha1.Monitor {
	monitor := testutils.GenerateFullMonitor(
		types.NamespacedName{Name: name, Namespace: namespace},
		types.NamespacedName{Name: secretName, Namespace: secretNamespace},
		service,
		nil,
	)
	expiresAt := metav1.NewTime(time.Unix(fixedExpiryUnix, 0))
	secondsRemaining := int64(3600)
	monitor.Status.ExpiresAt = &expiresAt
	monitor.Status.SecondsRemaining = &secondsRemaining
	monitor.Status.State = state
	return monitor
}

var _ = Describe("Metric", func() {
	// The gauge vectors are package-level globals shared by every spec, so
	// reset them to keep series counts meaningful.
	BeforeEach(func() {
		SecretValidUntilTimestamp.Reset()
		SecretSecondsUntilExpiry.Reset()
		MonitorStateGauge.Reset()
	})

	Context("label sets", func() {
		It("omits state from the value gauge labels", func() {
			monitor := monitorWithStatus("m", "ns", "s", "", "docker.io",
				expiringsecretv1alpha1.MonitorStateWarning)
			labels := NewMetric(monitor).Labels()

			Expect(labels).NotTo(HaveKey(LabelState))
			Expect(labels[LabelMonitorName]).To(Equal("m"))
			Expect(labels[LabelMonitorNamespace]).To(Equal("ns"))
			Expect(labels[LabelSecretName]).To(Equal("s"))
			// An empty secretRef namespace defaults to the Monitor's own.
			Expect(labels[LabelSecretNamespace]).To(Equal("ns"))
			Expect(labels[LabelSecretService]).To(Equal("docker.io"))
		})

		It("includes state in the state gauge labels", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateInfo)
			labels := NewMetric(monitor).StateLabels()

			Expect(labels[LabelState]).To(Equal("Info"))
			Expect(labels[LabelMonitorName]).To(Equal("m"))
		})

		It("builds deterministic label values without state", func() {
			monitor := monitorWithStatus(
				"label-values-monitor", "label-values-namespace",
				"label-values-secret", "label-values-secret-namespace",
				"quay.io", expiringsecretv1alpha1.MonitorStateInfo)

			expected := `monitor_name="label-values-monitor",` +
				`monitor_namespace="label-values-namespace",` +
				`secret_name="label-values-secret",` +
				`secret_namespace="label-values-secret-namespace",` +
				`secret_service="quay.io"`
			Expect(NewMetric(monitor).LabelValues()).To(Equal(expected))
		})

		It("tolerates a nil monitor and a nil secretRef", func() {
			Expect(NewMetric(nil).Labels()).To(BeEmpty())

			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			monitor.Spec.SecretRef = nil
			labels := NewMetric(monitor).Labels()
			Expect(labels[LabelSecretName]).To(BeEmpty())
			Expect(labels[LabelSecretNamespace]).To(Equal("ns"))
		})
	})

	Context("updates", func() {
		It("rejects incomplete status", func() {
			Expect(NewMetric(nil).Update()).NotTo(Succeed())

			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			monitor.Status.ExpiresAt = nil
			Expect(NewMetric(monitor).Update()).NotTo(Succeed())

			monitor = monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			monitor.Status.SecondsRemaining = nil
			Expect(NewMetric(monitor).Update()).NotTo(Succeed())

			monitor = monitorWithStatus("m", "ns", "s", "ns", "quay.io", "")
			Expect(NewMetric(monitor).Update()).NotTo(Succeed())
		})

		It("publishes all three series", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
			Expect(testutil.CollectAndCount(SecretSecondsUntilExpiry)).To(Equal(1))
			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(1))
		})
	})

	Context("series lifecycle", func() {
		It("leaves exactly one state series across a transition", func() {
			// Regression test: state used to be a label on the value gauges,
			// so each transition minted a new series and abandoned the old.
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			monitor.Status.State = expiringsecretv1alpha1.MonitorStateCritical
			Expect(NewMetric(monitor).Update()).To(Succeed())

			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(1))
			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
			Expect(testutil.CollectAndCount(SecretSecondsUntilExpiry)).To(Equal(1))

			Expect(testutil.ToFloat64(
				MonitorStateGauge.With(NewMetric(monitor).StateLabels()),
			)).To(Equal(1.0))
		})

		It("leaves no orphan when the secretRef is retargeted", func() {
			monitor := monitorWithStatus("m", "ns", "old-secret", "ns",
				"quay.io", expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			monitor.Spec.SecretRef.Name = "new-secret"
			Expect(NewMetric(monitor).Update()).To(Succeed())

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(1))
		})

		It("leaves no orphan when the service changes", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			monitor.Spec.Service = "ghcr.io"
			Expect(NewMetric(monitor).Update()).To(Succeed())

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
		})

		It("does not disturb another Monitor's series", func() {
			first := monitorWithStatus("first", "ns", "s1", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			second := monitorWithStatus("second", "ns", "s2", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(first).Update()).To(Succeed())
			Expect(NewMetric(second).Update()).To(Succeed())

			NewMetric(first).Cleanup()

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(1))
		})

		It("removes every series on cleanup", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			NewMetric(monitor).Cleanup()

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(0))
			Expect(testutil.CollectAndCount(SecretSecondsUntilExpiry)).To(Equal(0))
			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(0))
		})
	})

	Context("error state", func() {
		It("drops the value gauges but keeps the failure alertable", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			monitor.Status.State = expiringsecretv1alpha1.MonitorStateError
			Expect(NewMetric(monitor).SetError()).To(Succeed())

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(0))
			Expect(testutil.CollectAndCount(SecretSecondsUntilExpiry)).To(Equal(0))
			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(1))

			labels := NewMetric(monitor).StateLabels()
			Expect(labels[LabelState]).To(Equal("Error"))
			Expect(testutil.ToFloat64(MonitorStateGauge.With(labels))).To(Equal(1.0))
		})

		It("defaults to the Error state when status carries none", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io", "")
			Expect(NewMetric(monitor).SetError()).To(Succeed())

			labels := NewMetric(monitor).Labels()
			labels[LabelState] = string(expiringsecretv1alpha1.MonitorStateError)
			Expect(testutil.ToFloat64(MonitorStateGauge.With(labels))).To(Equal(1.0))
		})

		It("rejects a nil monitor", func() {
			Expect(NewMetric(nil).SetError()).NotTo(Succeed())
		})
	})

	Context("exposed contract", func() {
		It("exposes the documented names, labels and values", func() {
			monitor := monitorWithStatus(
				"contract-monitor", "contract-ns",
				"contract-secret", "contract-ns",
				"quay.io", expiringsecretv1alpha1.MonitorStateWarning)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			expected := `
# HELP expiringsecrets_monitor_state Current state of the Monitor, always 1 for the active state
# TYPE expiringsecrets_monitor_state gauge
expiringsecrets_monitor_state{monitor_name="contract-monitor",monitor_namespace="contract-ns",secret_name="contract-secret",secret_namespace="contract-ns",secret_service="quay.io",state="Warning"} 1
`
			Expect(testutil.CollectAndCompare(MonitorStateGauge,
				strings.NewReader(expected))).To(Succeed())

			expected = `
# HELP expiringsecrets_monitor_until_expiration_seconds Seconds until secret expires
# TYPE expiringsecrets_monitor_until_expiration_seconds gauge
expiringsecrets_monitor_until_expiration_seconds{monitor_name="contract-monitor",monitor_namespace="contract-ns",secret_name="contract-secret",secret_namespace="contract-ns",secret_service="quay.io"} 3600
`
			Expect(testutil.CollectAndCompare(SecretSecondsUntilExpiry,
				strings.NewReader(expected))).To(Succeed())

			expected = `
# HELP expiringsecrets_monitor_valid_until_timestamp_seconds Secret expiration timestamp
# TYPE expiringsecrets_monitor_valid_until_timestamp_seconds gauge
expiringsecrets_monitor_valid_until_timestamp_seconds{monitor_name="contract-monitor",monitor_namespace="contract-ns",secret_name="contract-secret",secret_namespace="contract-ns",secret_service="quay.io"} 1.8e+09
`
			Expect(testutil.CollectAndCompare(SecretValidUntilTimestamp,
				strings.NewReader(expected))).To(Succeed())
		})
	})
})

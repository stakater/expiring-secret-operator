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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	testutils "github.com/stakater/expiring-secret-operator/test/utils"
)

var _ = Describe("Metric", func() {
	Context("labels", func() {
		It("builds the expected label map", func() {
			monitor := testutils.GenerateFullMonitor(
				types.NamespacedName{Name: "test-monitor", Namespace: "test-namespace"},
				types.NamespacedName{Name: "test-secret", Namespace: ""},
				"docker.io",
				nil,
			)
			monitor.Status.State = expiringsecretv1alpha1.MonitorStateWarning
			labels := NewMetric(monitor).Labels()
			Expect(labels[LabelMonitorName]).To(Equal("test-monitor"))
			Expect(labels[LabelMonitorNamespace]).To(Equal("test-namespace"))
			Expect(labels[LabelSecretName]).To(Equal("test-secret"))
			Expect(labels[LabelSecretNamespace]).To(Equal("test-namespace"))
			Expect(labels[LabelSecretService]).To(Equal("docker.io"))
			Expect(labels[LabelState]).To(Equal(string(expiringsecretv1alpha1.MonitorStateWarning)))
		})

		It("builds deterministic label values", func() {
			monitor := testutils.GenerateFullMonitor(
				types.NamespacedName{Name: "label-values-monitor", Namespace: "label-values-namespace"},
				types.NamespacedName{Name: "label-values-secret", Namespace: "label-values-secret-namespace"},
				"quay.io",
				nil,
			)
			monitor.Status.State = expiringsecretv1alpha1.MonitorStateInfo
			labelValues := NewMetric(monitor).LabelValues()
			expected := `monitor_name="label-values-monitor",monitor_namespace="label-values-namespace",secret_name="label-values-secret",secret_namespace="label-values-secret-namespace",secret_service="quay.io",state="Info"`
			Expect(labelValues).To(Equal(expected))
		})
	})

	Context("updates", func() {
		It("returns errors for missing data", func() {
			err := NewMetric(nil).Update()
			Expect(err).To(HaveOccurred())

			monitor := testutils.GenerateFullMonitor(
				types.NamespacedName{Name: "error-monitor", Namespace: "default"},
				types.NamespacedName{Name: "error-secret", Namespace: "default"},
				"",
				nil,
			)
			monitor.Status.State = expiringsecretv1alpha1.MonitorStateUnknown
			err = NewMetric(monitor).Update()
			Expect(err).To(HaveOccurred())
		})

		It("updates and cleans up metrics", func() {
			monitor := testutils.GenerateFullMonitor(
				types.NamespacedName{Name: "update-monitor", Namespace: "update-namespace"},
				types.NamespacedName{Name: "update-secret", Namespace: "update-secret-namespace"},
				"ghcr.io",
				nil,
			)
			monitor.Status.State = expiringsecretv1alpha1.MonitorStateValid
			expiresAt := metav1.NewTime(time.Now().Add(2 * time.Hour))
			secondsRemaining := int64(7200)
			monitor.Status.ExpiresAt = &expiresAt
			monitor.Status.SecondsRemaining = &secondsRemaining

			metric := NewMetric(monitor)
			Expect(metric.Update()).To(Succeed())

			validUntilGauge, err := SecretValidUntilTimestamp.GetMetricWith(metric.Labels())
			Expect(err).NotTo(HaveOccurred())
			secondsUntilGauge, err := SecretSecondsUntilExpiry.GetMetricWith(metric.Labels())
			Expect(err).NotTo(HaveOccurred())

			Expect(testutil.ToFloat64(validUntilGauge)).To(BeNumerically(">", 0))
			Expect(testutil.ToFloat64(secondsUntilGauge)).To(BeNumerically(">", 0))

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
			metric.Cleanup()
			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(0))
		})
	})
})

/*
Copyright 2026 Stakater.

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

package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
)

type AlertThresholds = expiringsecretv1alpha1.AlertThresholds

func uniqueName() string { return "admission-" + rand.String(8) }

func specWith(t *AlertThresholds) expiringsecretv1alpha1.MonitorSpec {
	return expiringsecretv1alpha1.MonitorSpec{
		Service:         "docker.io",
		SecretRef:       &expiringsecretv1alpha1.SecretReference{Name: "some-secret"},
		AlertThresholds: t,
	}
}

func specWithService(service string) expiringsecretv1alpha1.MonitorSpec {
	s := specWith(nil)
	s.Service = service
	return s
}

func specWithSecretName(name string) expiringsecretv1alpha1.MonitorSpec {
	s := specWith(nil)
	s.SecretRef.Name = name
	return s
}

var _ = Describe("Monitor CRD", func() {
	DescribeTable("Monitor admission", func(spec expiringsecretv1alpha1.MonitorSpec, wantErr bool, want *AlertThresholds) {
		m := &expiringsecretv1alpha1.Monitor{ObjectMeta: metav1.ObjectMeta{Name: uniqueName(), Namespace: "default"}, Spec: spec}
		err := k8sClient.Create(ctx, m)
		if wantErr {
			Expect(err).To(HaveOccurred())
			return
		}
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, m) })
		Expect(m.Spec.AlertThresholds).To(Equal(want))
	},
		Entry("no thresholds are defaulted to 30/14/7", specWith(nil), false, &AlertThresholds{InfoDays: 30, WarningDays: 14, CriticalDays: 7}),
		Entry("empty thresholds object is defaulted", specWith(&AlertThresholds{}), false, &AlertThresholds{InfoDays: 30, WarningDays: 14, CriticalDays: 7}),
		Entry("partial thresholds keep the given value", specWith(&AlertThresholds{CriticalDays: 3}), false, &AlertThresholds{InfoDays: 30, WarningDays: 14, CriticalDays: 3}),
		Entry("inverted thresholds are rejected", specWith(&AlertThresholds{InfoDays: 7, WarningDays: 14, CriticalDays: 30}), true, nil),
		Entry("critical above the default warning is rejected", specWith(&AlertThresholds{CriticalDays: 20}), true, nil),
		Entry("empty service is rejected", specWithService(""), true, nil),
		Entry("empty secret name is rejected", specWithSecretName(""), true, nil),
		Entry("upper-case secret name is rejected", specWithSecretName("Bad-Name"), true, nil),
	)
})

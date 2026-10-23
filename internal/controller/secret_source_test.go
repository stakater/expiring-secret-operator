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
	"errors"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"

	testutils "github.com/stakater/expiring-secret-operator/test/utils"
)

var _ = Describe("parseValidUntil", func() {
	It("should handle a secret missing labels", func() {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "no-label-secret",
				Namespace: MonitorNamespace,
			},
			Data: map[string][]byte{
				TokenKey: []byte("fake-token"),
			},
		}

		expiresAt, err := parseValidUntil(logr.Discard(), secret)
		Expect(err).To(HaveOccurred())
		Expect(expiresAt).To(Equal(time.Time{}))
	})

	It("should handle an invalid date format", func() {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "invalid-date-secret",
				Namespace: MonitorNamespace,
				Labels: map[string]string{
					LabelKey: "not-a-date",
				},
			},
			Data: map[string][]byte{
				TokenKey: []byte("fake-token"),
			},
		}

		expiresAt, err := parseValidUntil(logr.Discard(), secret)
		Expect(err).To(HaveOccurred())
		Expect(err.Reason).To(Equal("SourceLabelInvalid"))
		Expect(expiresAt).To(Equal(time.Time{}))
	})
})

var _ = DescribeTable("secretUpdatePredicate", func(oldLabels, newLabels map[string]string, want bool) {
	old := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Labels: oldLabels}}
	cur := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Labels: newLabels}}
	Expect(secretUpdatePredicate(event.UpdateEvent{ObjectOld: old, ObjectNew: cur})).To(Equal(want))
},
	Entry("label added", nil, map[string]string{LabelKey: "2030-01-01"}, true),
	Entry("label changed", map[string]string{LabelKey: "2030-01-01"}, map[string]string{LabelKey: "2031-01-01"}, true),
	Entry("label removed", map[string]string{LabelKey: "2030-01-01"}, nil, true),
	Entry("unrelated label changed", map[string]string{LabelKey: "2030-01-01", "x": "1"}, map[string]string{LabelKey: "2030-01-01", "x": "2"}, false),
	Entry("no labels either side", nil, nil, false),
)

var _ = Describe("getSourceObject", func() {
	r := func() *MonitorReconciler { return &MonitorReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()} }
	monitorFor := func(secretName string) *reconcileState {
		m := testutils.GenerateMonitor(types.NamespacedName{Name: "meta-monitor", Namespace: MonitorNamespace}, secretName)
		return newReconcileState(ctx, m)
	}

	It("returns the Secret metadata with the validUntil label", func() {
		secret := testutils.GenerateValidStringSecret(
			types.NamespacedName{Name: "meta-only-secret", Namespace: MonitorNamespace}, "2030-01-01")
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ctx, secret)

		obj, err := r().getSourceObject(monitorFor(secret.Name))
		Expect(err).NotTo(HaveOccurred())
		Expect(obj.GetLabels()).To(HaveKeyWithValue(LabelKey, "2030-01-01"))
	})

	It("returns errSecretNotFound for a missing Secret", func() {
		_, err := r().getSourceObject(monitorFor("does-not-exist"))
		Expect(errors.Is(err, errSecretNotFound)).To(BeTrue())
	})
})

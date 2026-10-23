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
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	"github.com/stakater/expiring-secret-operator/internal/utils"
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

	It("never logs the Secret's label map", func() {
		var lines []string
		log := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{Verbosity: 2})
		secret := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "s", Labels: map[string]string{"team": "x"}}}
		_, _ = parseValidUntil(log, secret)
		out := strings.Join(lines, "\n")
		Expect(out).NotTo(ContainSubstring("team"))
		Expect(out).To(Or(BeEmpty(), ContainSubstring(LabelKey)))
	})
})

// reconcileWithLogs runs one reconcile of monitor through c and returns
// every line logged at V(0).
func reconcileWithLogs(c client.Client, monitor *expiringsecretv1alpha1.Monitor) []string {
	var lines []string
	s := newReconcileState(ctx, monitor)
	s.log = funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{})
	DeferCleanup(utils.NewMetric(monitor).Cleanup)
	_, _ = (&MonitorReconciler{Client: c, Scheme: c.Scheme()}).reconcileMonitor(s)
	return lines
}

var _ = Describe("failure logging", func() {
	key := types.NamespacedName{Name: "log-monitor", Namespace: MonitorNamespace}

	It("logs a missing label once, at Info", func() {
		monitor := testutils.GenerateMonitor(key, "unlabelled")
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "unlabelled", Namespace: MonitorNamespace}}
		c := fake.NewClientBuilder().WithScheme(k8sClient.Scheme()).
			WithObjects(monitor, secret).WithStatusSubresource(monitor).Build()

		lines := reconcileWithLogs(c, monitor)
		Expect(lines).To(HaveLen(1))
		Expect(lines[0]).To(ContainSubstring(`"level"=0`))
		Expect(lines[0]).To(ContainSubstring(ReasonSourceLabelNotFound))
	})

	It("logs an API error once, at Error", func() {
		monitor := testutils.GenerateMonitor(key, "any")
		base := fake.NewClientBuilder().WithScheme(k8sClient.Scheme()).
			WithObjects(monitor).WithStatusSubresource(monitor).Build()

		lines := reconcileWithLogs(&errorClient{Client: base, getErr: errors.New("boom")}, monitor)
		Expect(lines).To(HaveLen(1))
		Expect(lines[0]).To(ContainSubstring(`"error"="boom"`))
		Expect(lines[0]).NotTo(ContainSubstring(`"level"=`))
		Expect(lines[0]).To(ContainSubstring(ReasonAPIError))
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

// monitorInA builds a Monitor in namespace "a" referencing secretName.
func monitorInA(name, secretName string) client.Object {
	return testutils.GenerateMonitor(types.NamespacedName{Name: name, Namespace: "a"}, secretName)
}

var _ = DescribeTable("mapSecretToMonitor",
	func(monitors []client.Object, secret types.NamespacedName, listErr error, want []types.NamespacedName) {
		c := fake.NewClientBuilder().WithScheme(k8sClient.Scheme()).WithObjects(monitors...).
			WithIndex(&expiringsecretv1alpha1.Monitor{}, secretRefNameIndex, indexMonitorBySecretName).Build()
		r := &MonitorReconciler{Client: &errorClient{Client: c, listErr: listErr}, Scheme: c.Scheme()}
		obj := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: secret.Name, Namespace: secret.Namespace}}

		requests := r.mapSecretToMonitor(ctx, obj)
		if want == nil { // nil marks the error case: no requests at all
			Expect(requests).To(BeNil())
			return
		}
		var got []types.NamespacedName
		for _, req := range requests {
			got = append(got, req.NamespacedName)
		}
		Expect(got).To(ConsistOf(want))
	},
	Entry("one match",
		[]client.Object{monitorInA("m1", "s"), monitorInA("m2", "other")},
		types.NamespacedName{Namespace: "a", Name: "s"}, nil,
		[]types.NamespacedName{{Namespace: "a", Name: "m1"}}),
	Entry("no match on name",
		[]client.Object{monitorInA("m1", "other")},
		types.NamespacedName{Namespace: "a", Name: "s"}, nil,
		[]types.NamespacedName{}),
	Entry("same name in another namespace",
		[]client.Object{monitorInA("m1", "s"),
			testutils.GenerateMonitor(types.NamespacedName{Name: "m2", Namespace: "b"}, "s")},
		types.NamespacedName{Namespace: "b", Name: "s"}, nil,
		[]types.NamespacedName{{Namespace: "b", Name: "m2"}}),
	Entry("two Monitors on one Secret",
		[]client.Object{monitorInA("m1", "s"), monitorInA("m2", "s")},
		types.NamespacedName{Namespace: "a", Name: "s"}, nil,
		[]types.NamespacedName{{Namespace: "a", Name: "m1"}, {Namespace: "a", Name: "m2"}}),
	Entry("list error",
		[]client.Object{monitorInA("m1", "s")},
		types.NamespacedName{Namespace: "a", Name: "s"}, errors.New("list failed"),
		nil),
)

var _ = Describe("stripSecretMetadata", func() {
	It("drops annotations and managed fields and keeps identity and labels", func() {
		obj := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: "a", Labels: map[string]string{LabelKey: "2030-01-01"},
			Annotations:   map[string]string{"kubectl.kubernetes.io/last-applied-configuration": `{"data":{}}`},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
		}}
		out, err := stripSecretMetadata(obj)
		Expect(err).NotTo(HaveOccurred())
		got := out.(*metav1.PartialObjectMetadata)
		Expect(got.Annotations).To(BeNil())
		Expect(got.ManagedFields).To(BeNil())
		Expect(got.Name).To(Equal("s"))
		Expect(got.Namespace).To(Equal("a"))
		Expect(got.Labels).To(HaveKeyWithValue(LabelKey, "2030-01-01"))
	})

	It("passes other objects through unchanged", func() {
		monitor := &expiringsecretv1alpha1.Monitor{ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{"keep": "me"},
		}}
		out, err := stripSecretMetadata(monitor)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(BeIdenticalTo(monitor))
		Expect(monitor.Annotations).To(HaveKey("keep"))
	})

	It("is installed for Secrets only", func() {
		byObject := SecretCacheOptions().ByObject
		Expect(byObject).To(HaveLen(1))
		for obj, opts := range byObject {
			Expect(obj.GetObjectKind().GroupVersionKind().Kind).To(Equal("Secret"))
			Expect(opts.Transform).NotTo(BeNil())
		}
	})
})

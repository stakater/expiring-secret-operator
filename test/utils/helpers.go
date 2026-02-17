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
	"context"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	//"github.com/stakater/expiring-secret-operator/internal/controller"
)

type TestHelper struct {
	ctx       context.Context
	k8sClient client.Client
}

type ObjectResource struct {
	Name     client.ObjectKey
	Resource client.Object
	F        func() error
}

func NewHelper(ctx context.Context, k8sClient client.Client) *TestHelper {
	return &TestHelper{
		ctx:       ctx,
		k8sClient: k8sClient,
	}
}

//func (h *TestHelper) NewReconciler() reconcile.Reconciler {
//	return reconcile.AsReconciler(h.k8sClient, h.object)
//}

func (h *TestHelper) ReconcileOnce(reconciler reconcile.Reconciler, name types.NamespacedName) (ctrl.Result, error) {
	return reconciler.Reconcile(h.ctx, ctrl.Request{NamespacedName: name})
}

func (h *TestHelper) NsName(name string, namespace string) types.NamespacedName {
	return types.NamespacedName{Name: name, Namespace: namespace}
}

func (h *TestHelper) CheckStatus(
	namespacedName types.NamespacedName,
	condition func(*expiringsecretv1alpha1.Monitor) bool,
) bool {
	found := &expiringsecretv1alpha1.Monitor{}
	err := h.k8sClient.Get(h.ctx, namespacedName, found)
	if err != nil {
		return false
	}
	return condition(found)
}

func (h *TestHelper) ExpectStatusEventually(
	name types.NamespacedName,
	timeout time.Duration,
	interval time.Duration,
	condition func(*expiringsecretv1alpha1.Monitor) bool,
) {
	gomega.Eventually(func() bool {
		return h.CheckStatus(name, condition)
	}, timeout, interval).Should(gomega.BeTrue())
}

// Generate unique namespace name for each test to avoid conflicts
func (h *TestHelper) VerifyNamespaces(namespaces ...client.ObjectKey) {
	names := UniqueNamespaces(namespaces)
	for _, nss := range names {
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: nss},
		}
		err := h.k8sClient.Get(h.ctx, types.NamespacedName{Name: nss}, ns)
		if err != nil && client.IgnoreNotFound(err) == nil {
			ginkgo.By("creating namespace: " + nss)
			err := h.k8sClient.Create(h.ctx, ns)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		} else if err != nil {
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}
	}
}

func (h *TestHelper) CleanupResources(
	timeout time.Duration,
	interval time.Duration,
	resources ...ObjectResource,
) {
	log := log.FromContext(h.ctx)
	for _, r := range resources {
		ginkgo.By("Cleaning up resource: " + r.Name.String())
		err := h.k8sClient.Get(h.ctx, r.Name, r.Resource)
		resourceExists := err == nil
		if err != nil && client.IgnoreNotFound(err) != nil {
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		}

		if resourceExists {
			gomega.Expect(h.k8sClient.Delete(h.ctx, r.Resource)).To(gomega.Succeed())
		}
	}

	ginkgo.By("Checking if resources are completely gone")
	gomega.Eventually(func() bool {
		b := uint(0)
		for _, r := range resources {
			if r.F != nil {
				log.V(2).Info("Executing function for resource", "resource", r.Name)
				if err := r.F(); err != nil {
					log.V(2).Info("Cleanup function failed", "resource", r.Name, "err", err)
					return false
				}
			}
			err := h.k8sClient.Get(h.ctx, r.Name, r.Resource)
			if err != nil && client.IgnoreNotFound(err) == nil {
				continue
			}
			b |= 1 // Resource not deleted
		}
		return b == 0
	}, timeout, interval).Should(gomega.BeTrue())
}

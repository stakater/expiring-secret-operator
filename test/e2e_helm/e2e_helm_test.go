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

package e2e_helm

import (
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	"github.com/stakater/expiring-secret-operator/test/utils"
)

// These specs run against the operator installed from the Helm chart in
// BeforeSuite. They are deliberately a thin functional smoke test: the
// reconciler's full state-machine behaviour is already covered by the
// controller (envtest) suite and the kustomize e2e suite. What this suite
// uniquely proves is that the *packaged chart* — its CRDs, RBAC, Deployment,
// image and probes — yields a running operator that actually reconciles.
var _ = Describe("Operator installed via Helm chart", Ordered, func() {
	const (
		timeout       = time.Second * 120
		interval      = time.Second * 2
		testNamespace = "eso-helm-e2e-workload"
	)

	var h *utils.TestHelper

	BeforeAll(func() {
		h = utils.NewHelper(ctx, k8sClient)

		By("ensuring a clean workload namespace")
		_, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", testNamespace,
			"--ignore-not-found=true", "--timeout=120s"))
		waitForNamespaceGone(testNamespace, timeout, interval)

		By("creating the workload namespace: " + testNamespace)
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
		})).To(Succeed())
	})

	AfterAll(func() {
		By("cleaning up the workload namespace")
		_ = k8sClient.Delete(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
		})
	})

	It("serves the Monitor CRD installed by the chart", func() {
		// If `helm install` did not install the CRD from the chart's crds/
		// directory, creating a Monitor returns a "no matches for kind" error.
		By("creating a Monitor, which requires the chart-installed CRD")
		nsSecret := h.NsName("helm-crd-secret", testNamespace)
		nsMonitor := h.NsName("helm-crd-monitor", testNamespace)

		secret := utils.GenerateValidDaysSecret(nsSecret, 365)
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())

		monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
		Expect(k8sClient.Create(ctx, monitor)).To(Succeed())
	})

	It("reconciles a valid secret to the Valid state", func() {
		nsSecret := h.NsName("helm-reconcile-secret", testNamespace)
		nsMonitor := h.NsName("helm-reconcile-monitor", testNamespace)

		By("creating a secret far from expiry and a Monitor for it")
		secret := utils.GenerateValidDaysSecret(nsSecret, 365)
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
		Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

		By("waiting for the Helm-installed operator to populate status")
		h.ExpectStatusEventually(nsMonitor, timeout, interval,
			func(m *expiringsecretv1alpha1.Monitor) bool {
				return m.Status.State == expiringsecretv1alpha1.MonitorStateValid &&
					m.Status.ExpiresAt != nil &&
					m.Status.SecondsRemaining != nil &&
					m.Status.LastChecked != nil
			})

		found := &expiringsecretv1alpha1.Monitor{}
		Expect(k8sClient.Get(ctx, nsMonitor, found)).To(Succeed())
		Expect(found.Status.State).To(Equal(expiringsecretv1alpha1.MonitorStateValid))
		Expect(*found.Status.SecondsRemaining).To(BeNumerically(">", 0))
	})

	It("reconciles an expired secret to the Expired state", func() {
		nsSecret := h.NsName("helm-expired-secret", testNamespace)
		nsMonitor := h.NsName("helm-expired-monitor", testNamespace)

		By("creating a secret past expiry and a Monitor for it")
		secret := utils.GenerateValidDaysSecret(nsSecret, -5)
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
		Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

		By("waiting for the operator to detect the expired state")
		h.ExpectStatusEventually(nsMonitor, timeout, interval,
			func(m *expiringsecretv1alpha1.Monitor) bool {
				return m.Status.State == expiringsecretv1alpha1.MonitorStateExpired
			})

		found := &expiringsecretv1alpha1.Monitor{}
		Expect(k8sClient.Get(ctx, nsMonitor, found)).To(Succeed())
		Expect(*found.Status.SecondsRemaining).To(BeNumerically("<", 0))
	})
})

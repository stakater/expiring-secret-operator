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

package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secrets/api/v1alpha1"
	"github.com/stakater/expiring-secrets/test/utils"
)

var _ = Describe("Expiring Secrets Operator E2E", Ordered, func() {
	var (
		k8sClient client.Client
		ctx       context.Context
	)

	BeforeAll(func() {
		ctx = context.Background()
		By("setting up kubernetes client")
		cfg, err := config.GetConfig()
		Expect(err).NotTo(HaveOccurred())

		err = expiringsecretv1alpha1.AddToScheme(scheme.Scheme)
		Expect(err).NotTo(HaveOccurred())

		k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
		Expect(err).NotTo(HaveOccurred())

		//By("creating manager namespace")
		//cmd := exec.Command("kubectl", "create", "ns", namespace)
		//_, _ = utils.Run(cmd)
	})

	AfterAll(func() {
		//By("removing manager namespace")
		//cmd := exec.Command("kubectl", "delete", "ns", namespace)
		//_, _ = utils.Run(cmd)
	})

	Context("Monitor Resource Functionality", func() {
		var testNamespace string

		BeforeEach(func() {
			// Generate unique namespace name for each test to avoid conflicts
			testNamespace = fmt.Sprintf("e2e-test-%d", time.Now().UnixNano())
			By("creating test namespace: " + testNamespace)
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
			}
			err := k8sClient.Create(ctx, ns)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			By("cleaning up test namespace")
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
			}
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should monitor a secret with a valid expiration date", func() {
			nsSecret := types.NamespacedName{
				Name:      "test-secret-valid",
				Namespace: testNamespace,
			}
			nsMonitor := types.NamespacedName{
				Name:      "test-monitor-valid",
				Namespace: testNamespace,
			}

			By("creating a secret with future expiration date")
			futureDate := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateSecret(nsSecret, futureDate, []byte("fake-registry-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource")
			monitor := utils.GenerateMonitor(nsMonitor, "docker.io", nsSecret, &expiringsecretv1alpha1.AlertThresholds{
				InfoDays:     30,
				WarningDays:  14,
				CriticalDays: 7,
			})
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor status to be updated")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateValid &&
					monitor.Status.ExpiresAt != nil &&
					monitor.Status.SecondsRemaining != nil &&
					monitor.Status.LastChecked != nil
			}, 180*time.Second, 10*time.Second).Should(BeTrue())

			By("verifying monitor status details")
			Expect(string(monitor.Status.State)).To(Equal(string(expiringsecretv1alpha1.MonitorStateValid)))
			Expect(monitor.Status.Message).To(Equal(fmt.Sprintf("Secret is valid until %s", futureDate)))
			Expect(*monitor.Status.SecondsRemaining).To(BeNumerically(">", 0))
		})

		It("should monitor a secret with an expiration date coming up", func() {
			nsSecret := types.NamespacedName{
				Name:      "test-secret-expires-soon",
				Namespace: testNamespace,
			}
			nsMonitor := types.NamespacedName{
				Name:      "test-monitor-expires-soon",
				Namespace: testNamespace,
			}

			By("creating a secret with future expiration date")
			futureDate := time.Now().Add(20 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateSecret(nsSecret, futureDate, []byte("fake-registry-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource")
			monitor := utils.GenerateMonitor(nsMonitor, "docker.io", nsSecret, &expiringsecretv1alpha1.AlertThresholds{
				InfoDays:     30,
				WarningDays:  14,
				CriticalDays: 7,
			})
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor status to be updated")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateInfo &&
					monitor.Status.ExpiresAt != nil &&
					monitor.Status.SecondsRemaining != nil &&
					monitor.Status.LastChecked != nil
			}, 30*time.Second, 2*time.Second).Should(BeTrue())

			By("verifying monitor status details")
			Expect(string(monitor.Status.State)).To(Equal(string(expiringsecretv1alpha1.MonitorStateInfo)))
			Expect(monitor.Status.Message).To(Equal(
				fmt.Sprintf("Secret expires in less than %d days", monitor.Spec.AlertThresholds.InfoDays)))
			Expect(*monitor.Status.SecondsRemaining).To(BeNumerically(">", 0))
		})

		It("should handle a secret without a validUntil label", func() {
			nsSecret := types.NamespacedName{
				Name:      "test-secret-valid",
				Namespace: testNamespace,
			}
			nsMonitor := types.NamespacedName{
				Name:      "test-monitor-valid",
				Namespace: testNamespace,
			}

			By("creating a secret with future expiration date")
			//futureDate := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateSecret(nsSecret, "", []byte("fake-registry-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource")
			monitor := utils.GenerateMonitor(nsMonitor, "docker.io", nsSecret, &expiringsecretv1alpha1.AlertThresholds{
				InfoDays:     30,
				WarningDays:  14,
				CriticalDays: 7,
			})
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor status to be updated")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateError
			}, 180*time.Second, 10*time.Second).Should(BeTrue())

			By("verifying monitor status details")
			Expect(string(monitor.Status.State)).To(Equal(string(expiringsecretv1alpha1.MonitorStateError)))
			Expect(monitor.Status.Message).To(
				Equal(fmt.Sprintf("Secret does not have %s label", utils.ValidUntilLabel)))
		})

		It("should handle expired secrets correctly", func() {
			nsSecret := types.NamespacedName{
				Name:      "test-secret-expired",
				Namespace: testNamespace,
			}
			nsMonitor := types.NamespacedName{
				Name:      "test-monitor-expired",
				Namespace: testNamespace,
			}

			By("creating a secret with past expiration date")
			pastDate := time.Now().Add(-5 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateSecret(nsSecret, pastDate, []byte("expired-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource")
			monitor := utils.GenerateMonitor(nsMonitor, "quay.io", nsSecret, nil)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to detect expired state")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateExpired
			}, 30*time.Second, 2*time.Second).Should(BeTrue())

			By("verifying expired status details")
			Expect(string(monitor.Status.State)).To(Equal(string(expiringsecretv1alpha1.MonitorStateExpired)))
			Expect(monitor.Status.Message).To(Equal(fmt.Sprintf("Secret expired on %s", pastDate)))
			Expect(*monitor.Status.SecondsRemaining).To(BeNumerically("<", 0))
		})

		It("should handle missing secrets gracefully", func() {
			nsMonitor := types.NamespacedName{
				Name:      "test-monitor-missing",
				Namespace: testNamespace,
			}
			nsSecret := types.NamespacedName{
				Name:      "non-existent-secret",
				Namespace: testNamespace,
			}

			By("creating a monitor resource referencing non-existent secret")
			monitor := utils.GenerateMonitor(nsMonitor, "ghcr.io", nsSecret, nil)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to detect error state")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateError
			}, 30*time.Second, 2*time.Second).Should(BeTrue())

			By("verifying error status")
			Expect(string(monitor.Status.State)).To(Equal(string(expiringsecretv1alpha1.MonitorStateError)))
			Expect(monitor.Status.Message).To(Equal("Referenced secret not found"))
		})

		It("should handle critical threshold correctly", func() {
			nsSecret := types.NamespacedName{
				Name:      "test-secret-critical",
				Namespace: testNamespace,
			}
			nsMonitor := types.NamespacedName{
				Name:      "test-monitor-critical",
				Namespace: testNamespace,
			}

			By("creating a secret expiring in 3 days")
			criticalDate := time.Now().Add(3 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateSecret(nsSecret, criticalDate, []byte("critical-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor with 7-day critical threshold")
			monitor := utils.GenerateMonitor(
				nsMonitor, "registry.k8s.io", nsSecret,
				&expiringsecretv1alpha1.AlertThresholds{
					CriticalDays: 7,
				},
			)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to detect critical state")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateCritical
			}, 30*time.Second, 2*time.Second).Should(BeTrue())

			By("verifying critical status")
			Expect(string(monitor.Status.State)).To(Equal(string(expiringsecretv1alpha1.MonitorStateCritical)))
			Expect(monitor.Status.Message).To(ContainSubstring("expires in less than"))
		})
	})

	Context("Monitor Resource Functionality Cross-Namespace", func() {
		var (
			monitorNamespace string
			secretNamespace  string
		)

		BeforeEach(func() {
			// Generate unique namespace name for each test to avoid conflicts
			By("creating unique namespace names")
			now := time.Now()
			monitorNamespace = fmt.Sprintf("e2e-test-%d", now.UnixNano())
			secretNamespace = fmt.Sprintf("secret-ns-%d", now.UnixNano())

			By("creating monitor namespace: " + monitorNamespace)
			monitorNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: monitorNamespace},
			}
			err := k8sClient.Create(ctx, monitorNS)
			Expect(err).NotTo(HaveOccurred())

			By("creating secret namespace")
			secretNs := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: secretNamespace},
			}
			err = k8sClient.Create(ctx, secretNs)
			if client.IgnoreAlreadyExists(err) != nil {
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() {
			By("cleaning up secret namespace")
			secretNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: secretNamespace},
			}
			_ = k8sClient.Delete(ctx, secretNS)

			By("cleaning up monitor namespace")
			monitorNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: monitorNamespace},
			}
			_ = k8sClient.Delete(ctx, monitorNS)
		})

		It("should handle cross-namespace secret references", func() {
			nsSecret := types.NamespacedName{
				Name:      "cross-ns-secret",
				Namespace: secretNamespace,
			}
			nsMonitor := types.NamespacedName{
				Name:      "test-monitor-cross-ns",
				Namespace: monitorNamespace,
			}
			By("creating secret in different namespace")
			futureDate := time.Now().Add(25 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateSecret(nsSecret, futureDate, []byte("cross-namespace-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating monitor that references cross-namespace secret")
			monitor := utils.GenerateMonitor(nsMonitor, "docker.io", nsSecret, nil)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to process cross-namespace secret")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateInfo &&
					monitor.Status.ExpiresAt != nil
			}, 30*time.Second, 2*time.Second).Should(BeTrue())

			err := k8sClient.Get(ctx, nsMonitor, monitor)
			Expect(err).NotTo(HaveOccurred())

			Expect(string(monitor.Status.State)).To(Equal(string(expiringsecretv1alpha1.MonitorStateInfo)))
			Expect(monitor.Status.Message).To(
				Equal(fmt.Sprintf("Secret expires in less than %d days", monitor.Spec.AlertThresholds.InfoDays)))
			Expect(*monitor.Status.SecondsRemaining).To(BeNumerically(">", 0))
		})
	})

	Context("Prometheus Metrics", func() {
		var (
			testNamespace string
			nsPrefix      = "test-e2e-metrics"
			projectName   = "expiring-secrets"
			namespace     = fmt.Sprintf("%s-system", projectName)
			svcName       = fmt.Sprintf("%s-controller-manager-metrics-service", projectName)
			crbName       = fmt.Sprintf("%s-metrics-binding", projectName)
		)

		BeforeEach(func() {
			// Generate unique namespace name for each test to avoid conflicts
			testNamespace = fmt.Sprintf("%s-%d", nsPrefix, time.Now().UnixNano())

			By("creating test namespace: " + testNamespace)
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
			}
			err := k8sClient.Create(ctx, ns)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			By("cleaning up test namespace")
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
			}
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should expose metrics endpoint", func() {
			validSecret := types.NamespacedName{Name: "valid-secret", Namespace: testNamespace}
			validMonitor := types.NamespacedName{Name: "valid-monitor", Namespace: testNamespace}

			By("creating a secret with future expiration date")
			futureDate := time.Now().Add(20 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateSecret(validSecret, futureDate, []byte("fake-registry-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource")
			monitor := utils.GenerateMonitor(validMonitor, "docker.io", validSecret, &expiringsecretv1alpha1.AlertThresholds{
				InfoDays:     30,
				WarningDays:  14,
				CriticalDays: 7,
			})
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor status to be updated")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, validMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateInfo &&
					monitor.Status.ExpiresAt != nil &&
					monitor.Status.SecondsRemaining != nil &&
					monitor.Status.LastChecked != nil
			}, 30*time.Second, 2*time.Second).Should(BeTrue())

			/////////

			expiredSecret := types.NamespacedName{Name: "expired-secret", Namespace: testNamespace}
			expiredMonitor := types.NamespacedName{Name: "expired-monitor", Namespace: testNamespace}

			By("creating a secret with past expiration date")
			pastDate := time.Now().Add(-5 * 24 * time.Hour).Format("2006-01-02")
			secret = utils.GenerateSecret(expiredSecret, pastDate, []byte("expired-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource for secret with past expiration date")
			monitor = utils.GenerateMonitor(expiredMonitor, "quay.io", expiredSecret, nil)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to detect expired state")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, expiredMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateExpired
			}, 30*time.Second, 2*time.Second).Should(BeTrue())

			/////////

			By("creating cluster role binding for metrics access")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding",
				crbName,
				fmt.Sprintf("--clusterrole=%s-metrics-reader", projectName),
				fmt.Sprintf("--serviceaccount=%s:%s-controller-manager", namespace, projectName),
			)
			_, _ = utils.Run(cmd)

			By("creating serviceaccount token for authentication")
			cmd = exec.Command("kubectl", "create", "token",
				fmt.Sprintf("%s-controller-manager", projectName),
				"-n", namespace,
			)
			token, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("curling metrics endpoint using serviceaccount token")
			curlCommand := fmt.Sprintf("curl -k -H \"Authorization: Bearer %s\" "+
				"https://%s.%s.svc.cluster.local:8443/metrics",
				string(token), svcName, namespace)

			cmd = exec.Command("kubectl", "run", "curl-metrics",
				"--rm",
				"-it",
				"--restart=Never",
				"--image=curlimages/curl:7.87.0",
				"-n", namespace,
				"--", "/bin/sh", "-c",
				curlCommand,
			)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty())

			Expect(string(output)).To(ContainSubstring("expiringsecret_monitor_valid_until_timestamp_seconds"))
			Expect(string(output)).To(ContainSubstring("expiringsecret_monitor_until_expiration_seconds"))
		})
	})
})

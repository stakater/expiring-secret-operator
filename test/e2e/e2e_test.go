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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	internalutils "github.com/stakater/expiring-secret-operator/internal/utils"
	"github.com/stakater/expiring-secret-operator/test/utils"
)

var _ = Describe("Expiring Secrets Operator E2E", Ordered, func() {
	const (
		timeout  = time.Second * 120
		interval = time.Second * 2

		//timeout  = time.Second * 30
		//interval = time.Second * 10
		cleanUpTimeout  = time.Second * 60
		cleanUpInterval = time.Second * 1
	)
	var h *utils.TestHelper

	Context("Monitor Resource Functionality", func() {
		nsSecret := h.NsName("test-secret", "my-test-namespace")
		nsMonitor := h.NsName("test-monitor", "my-test-namespace")

		BeforeEach(func() {
			h = utils.NewHelper(ctx, k8sClient)
			h.VerifyNamespaces(nsSecret, nsMonitor)

			By("Checking if the custom resource is removed")
			monitor := &expiringsecretv1alpha1.Monitor{}
			err := k8sClient.Get(ctx, nsMonitor, monitor)
			if err != nil && client.IgnoreNotFound(err) != nil {
				Expect(err).NotTo(HaveOccurred())
			}

			By("Checking if the secret is removed")
			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, nsSecret, secret)
			if err != nil && client.IgnoreNotFound(err) != nil {
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() {
			h.CleanupResources(cleanUpTimeout, cleanUpInterval,
				utils.ObjectResource{
					Name:     nsMonitor,
					Resource: &expiringsecretv1alpha1.Monitor{},
				},
				utils.ObjectResource{
					Name:     nsSecret,
					Resource: &corev1.Secret{},
				},
			)
		})

		It("should monitor a secret with a valid expiration date", func() {
			By("creating a secret with future expiration date")
			futureDate := time.Now().Add(365 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateValidDaysSecret(nsSecret, 365)
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			log.Info("Created secret with valid expiration date", "secret", nsSecret, "validUntil", futureDate)

			By("creating a monitor resource")
			monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())
			log.Info("Created monitor resource", "monitor", monitor)

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
			}, timeout, interval).Should(BeTrue())

			By("verifying monitor status details")
			Expect(monitor.Status.State).To(Equal(expiringsecretv1alpha1.MonitorStateValid))
			Expect(monitor.Status.Message).To(Equal(fmt.Sprintf("Secret is valid until %s", futureDate)))
			Expect(*monitor.Status.SecondsRemaining).To(BeNumerically(">", 0))
		})

		It("should monitor a secret with an expiration date coming up", func() {
			By("creating a secret with future expiration date")
			secret := utils.GenerateValidDaysSecret(nsSecret, 20)
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource")
			monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			monitor = &expiringsecretv1alpha1.Monitor{}
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
			}, timeout, interval).Should(BeTrue())

			monitor = &expiringsecretv1alpha1.Monitor{}
			err := k8sClient.Get(ctx, nsMonitor, monitor)
			Expect(err).NotTo(HaveOccurred())

			By("verifying monitor status details")
			log.Info("Verifying monitor", "monitor", monitor)
			By("monitor.Status.State")
			Expect(monitor.Status.State).To(Equal(expiringsecretv1alpha1.MonitorStateInfo))
			By("monitor.Status.Message")
			Expect(monitor.Status.Message).To(Equal(
				fmt.Sprintf("Secret expires in less than %d days", monitor.Spec.AlertThresholds.InfoDays)))
			By("monitor.Status.SecondsRemaining")
			Expect(*monitor.Status.SecondsRemaining).To(BeNumerically(">", 0))
		})

		It("should handle a secret without a validUntil label", func() {
			By("creating a secret with future expiration date")
			secret := utils.GeneratePayloadSecret(nsSecret, []byte("fake-registry-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource")
			monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
			//Expect(k8sClient.Create(ctx, monitor)).To(Succeed())
			err := k8sClient.Create(ctx, monitor)
			if err != nil {
				getErr := k8sClient.Get(ctx, nsMonitor, monitor)
				if getErr != nil {
					log.Info("Monitor get failed", "err", getErr)
				} else {
					log.Info("Monitor", "mon", monitor)
				}
			}
			Expect(err).To(Succeed())

			By("waiting for monitor status to be updated")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateError
			}, timeout, interval).Should(BeTrue())

			By("verifying monitor status details")
			Expect(monitor.Status.State).To(Equal(expiringsecretv1alpha1.MonitorStateError))
			Expect(monitor.Status.Message).To(
				ContainSubstring(fmt.Sprintf("Source object does not have any labels, expected %s label", utils.ValidUntilLabel)))
		})

		It("should handle expired secrets correctly", func() {
			By("creating a secret with past expiration date")
			pastDate := time.Now().Add(-5 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateValidDaysSecret(nsSecret, -5)
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource")
			monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to detect expired state")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateExpired
			}, timeout, interval).Should(BeTrue())

			By("verifying expired status details")
			Expect(monitor.Status.State).To(Equal(expiringsecretv1alpha1.MonitorStateExpired))
			Expect(monitor.Status.Message).To(Equal(fmt.Sprintf("Secret expired on %s", pastDate)))
			Expect(*monitor.Status.SecondsRemaining).To(BeNumerically("<", 0))
		})

		It("should handle missing secrets gracefully", func() {
			By("creating a monitor resource referencing non-existent secret")
			monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to detect error state")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateError
			}, timeout, interval).Should(BeTrue())

			By("verifying error status")
			Expect(monitor.Status.State).
				To(Equal(expiringsecretv1alpha1.MonitorStateError))
			Expect(monitor.Status.Message).
				To(Equal("Failed to get source Secret: referenced secret not found"))
		})

		It("should handle critical threshold correctly", func() {
			By("creating a secret expiring in 3 days")
			criticalDate := time.Now().Add(3 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateFullSecret(nsSecret, criticalDate, []byte("critical-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor")
			monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to detect critical state")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateCritical
			}, timeout, interval).Should(BeTrue())

			By("verifying critical status")
			Expect(monitor.Status.State).To(Equal(expiringsecretv1alpha1.MonitorStateCritical))
			Expect(monitor.Status.Message).To(ContainSubstring("expires in less than"))
		})

		It("should handle warning threshold correctly", func() {
			By("creating a secret expiring in 10 days")
			warningDate := time.Now().Add(10 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateFullSecret(nsSecret, warningDate, []byte("warning-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor")
			monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to detect warning state")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateWarning &&
					monitor.Status.ExpiresAt != nil &&
					monitor.Status.SecondsRemaining != nil &&
					monitor.Status.LastChecked != nil
			}, timeout, interval).Should(BeTrue())

			By("verifying warning status")
			Expect(monitor.Status.State).To(Equal(expiringsecretv1alpha1.MonitorStateWarning))
			Expect(monitor.Status.Message).To(ContainSubstring("expires in less than"))
		})
	})

	Context("Monitor Resource Functionality Cross-Namespace", func() {
		monitorNamespace := "e2e-test"
		secretNamespace := "secret-ns"

		BeforeEach(func() {
			h = utils.NewHelper(ctx, k8sClient)

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
			nsSecret := h.NsName("cross-ns-secret", secretNamespace)
			nsMonitor := h.NsName("test-monitor-cross-ns", monitorNamespace)

			By("creating secret in different namespace")
			futureDate := time.Now().Add(25 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateFullSecret(nsSecret, futureDate, []byte("cross-namespace-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating monitor that references cross-namespace secret")
			monitor := utils.GenerateMonitor(nsMonitor, nsSecret)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to process cross-namespace secret")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, nsMonitor, monitor)
				if err != nil {
					return false
				}
				return monitor.Status.State == expiringsecretv1alpha1.MonitorStateInfo &&
					monitor.Status.ExpiresAt != nil
			}, timeout, interval).Should(BeTrue())

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
			testNamespace = "test-e2e-metrics"
			projectName   = "expiring-secret-operator"
			namespace     = fmt.Sprintf("%s-system", projectName)
			svcName       = fmt.Sprintf("%s-controller-manager-metrics-service", projectName)
			crbName       = fmt.Sprintf("%s-metrics-binding", projectName)
			managerName   = fmt.Sprintf("%s-controller-manager", projectName)

			validSecret    types.NamespacedName
			validMonitor   types.NamespacedName
			expiredSecret  types.NamespacedName
			expiredMonitor types.NamespacedName
		)

		validUntilMetricName := fmt.Sprintf(
			"%s_%s_%s",
			internalutils.PrometheusNamespace,
			internalutils.PrometheusSubsystem,
			internalutils.ValidUntilMetricName)
		untilExpiryMetricName := fmt.Sprintf(
			"%s_%s_%s",
			internalutils.PrometheusNamespace,
			internalutils.PrometheusSubsystem,
			internalutils.UntilExpiryMetricName)

		BeforeEach(func() {
			h = utils.NewHelper(ctx, k8sClient)
			By("creating test namespace: " + testNamespace)
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
			}
			err := k8sClient.Create(ctx, ns)
			Expect(err).NotTo(HaveOccurred())

			validSecret = h.NsName("valid-secret", testNamespace)
			validMonitor = h.NsName("valid-monitor", testNamespace)

			By("creating a secret with future expiration date")
			futureDate := time.Now().Add(20 * 24 * time.Hour).Format("2006-01-02")
			secret := utils.GenerateFullSecret(validSecret, futureDate, []byte("fake-registry-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource")
			monitor := utils.GenerateMonitor(validMonitor, validSecret)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor status to be updated")
			h.ExpectStatusEventually(validMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateInfo &&
						found.Status.ExpiresAt != nil &&
						found.Status.SecondsRemaining != nil &&
						found.Status.LastChecked != nil
				})

			expiredSecret = h.NsName("expired-secret", testNamespace)
			expiredMonitor = h.NsName("expired-monitor", testNamespace)

			By("creating a secret with past expiration date")
			pastDate := time.Now().Add(-5 * 24 * time.Hour).Format("2006-01-02")
			secret = utils.GenerateFullSecret(expiredSecret, pastDate, []byte("expired-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a monitor resource for secret with past expiration date")
			monitor = utils.GenerateMonitor(expiredMonitor, expiredSecret)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("waiting for monitor to detect expired state")
			h.ExpectStatusEventually(expiredMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateExpired
				})
		})

		AfterEach(func() {
			By("cleaning up test namespace")
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
			}
			_ = k8sClient.Delete(ctx, ns)
		})

		curl := func(url string) []byte {
			cmd := exec.Command("kubectl", "run", "curl-metrics",
				"--rm",
				"-it",
				"--restart=Never",
				"--image=curlimages/curl:7.87.0",
				"-n", namespace,
				"--", "/bin/sh", "-c",
				url,
			)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).NotTo(BeEmpty())
			return output
		}

		It("should expose metrics endpoint", func() {
			By("creating cluster role binding for metrics access")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding",
				crbName,
				fmt.Sprintf("--clusterrole=%s-metrics-reader", projectName),
				fmt.Sprintf("--serviceaccount=%s:%s-controller-manager", namespace, projectName),
			)
			_, _ = utils.Run(cmd)

			By("creating serviceaccount token for authentication")
			cmd = exec.Command("kubectl", "create", "token", managerName,
				"-n", namespace,
				"--duration=10m",
			)
			token, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("curling metrics endpoint using serviceaccount token")
			curlCommand := fmt.Sprintf("curl -k -H \"Authorization: Bearer %s\" "+
				"https://%s.%s.svc.cluster.local:8443/metrics",
				string(token), svcName, namespace)

			output := curl(curlCommand)

			dir, err := os.Getwd()
			Expect(err).NotTo(HaveOccurred())
			file := filepath.Join(dir, "metrics_output.txt")
			writeErr := os.WriteFile(file, output, 0644)
			Expect(writeErr).NotTo(HaveOccurred())

			outputStr := string(output)

			By("verifying that metrics output contains expected metric " + validUntilMetricName)
			Expect(outputStr).To(
				ContainSubstring(validUntilMetricName))

			By("verifying that metrics output contains expected metric " + untilExpiryMetricName)
			Expect(outputStr).To(
				ContainSubstring(untilExpiryMetricName))

			// Cleanup created resources

			By("removing cluster role binding for metrics access")
			cmd = exec.Command("kubectl", "delete", "clusterrolebinding",
				crbName,
			)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

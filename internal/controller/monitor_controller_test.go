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

package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secrets/api/v1alpha1"
)

var _ = Describe("Monitor Controller", func() {
	Context("When reconciling a Monitor resource", func() {
		const (
			MonitorName      = "test-monitor"
			MonitorNamespace = "default"
			SecretName       = "test-secret"
			SecretNamespace  = "default"
			Service          = "docker.io"
			ValidUntilLabel  = "expiringsecret.stakater.com/validUntil"

			timeout  = time.Second * 10
			duration = time.Second * 10
			interval = time.Millisecond * 250
		)

		ctx := context.Background()
		logger := log.FromContext(ctx)

		typeNamespacedName := types.NamespacedName{
			Name:      MonitorName,
			Namespace: MonitorNamespace,
		}

		BeforeEach(func() {
			By("Creating the custom resource for the Kind Monitor")
			monitor := &expiringsecretv1alpha1.Monitor{}
			err := k8sClient.Get(ctx, typeNamespacedName, monitor)
			if err != nil && client.IgnoreNotFound(err) != nil {
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() {
			By("Cleanup the specific resource instance Monitor")
			monitor := &expiringsecretv1alpha1.Monitor{}
			err := k8sClient.Get(ctx, typeNamespacedName, monitor)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the Secret")
			secret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: SecretName, Namespace: SecretNamespace}, secret)
			if err == nil {
				Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			}

			Expect(k8sClient.Delete(ctx, monitor)).To(Succeed())
		})

		It("should successfully reconcile a valid Monitor with expiring secret", func() {
			By("Creating a secret with validUntil label")
			// Set expiration to 15 days from now
			futureTime := time.Now().Add(15 * 24 * time.Hour)
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Labels: map[string]string{
						// Use RFC3339 date format (YYYY-MM-DD) - user-friendly and label-safe
						ValidUntilLabel: futureTime.Format("2006-01-02"),
					},
				},
				Data: map[string][]byte{
					"token": []byte("fake-token"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource")
			monitor := &expiringsecretv1alpha1.Monitor{
				ObjectMeta: metav1.ObjectMeta{
					Name:      MonitorName,
					Namespace: MonitorNamespace,
				},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					Service: Service,
					SecretRef: expiringsecretv1alpha1.SecretReference{
						Name:      SecretName,
						Namespace: SecretNamespace,
					},
					AlertThresholds: &expiringsecretv1alpha1.AlertThresholds{
						InfoDays:     30,
						WarningDays:  14,
						CriticalDays: 7,
					},
				},
			}
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Checking if the Monitor was successfully created")
			Eventually(func() error {
				found := &expiringsecretv1alpha1.Monitor{}
				return k8sClient.Get(ctx, typeNamespacedName, found)
			}, timeout, interval).Should(Succeed())

			By("Reconciling the created resource")
			controllerReconciler := &MonitorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking the Monitor status is updated correctly")
			Eventually(func() bool {
				found := &expiringsecretv1alpha1.Monitor{}
				err := k8sClient.Get(ctx, typeNamespacedName, found)
				if err != nil {
					logger.Error(err, "Got error", "error", err)
					return false
				}

				logger.Info("Current state: ",
					"Spec", found.Spec,
					"State", found.Status.State,
					"ExpiresAt", found.Status.ExpiresAt,
					"SecondsRemaining", found.Status.SecondsRemaining,
					"LastChecked", found.Status.LastChecked)

				return found.Status.State == "Info" && // 15 days should be in Info state (between 30 and 14 days)
					found.Status.ExpiresAt != nil &&
					found.Status.SecondsRemaining != nil &&
					found.Status.LastChecked != nil
			}, timeout, interval).Should(BeTrue())
		})

		It("should handle missing secret gracefully", func() {
			By("Creating the Monitor resource without creating the secret")
			monitor := &expiringsecretv1alpha1.Monitor{
				ObjectMeta: metav1.ObjectMeta{
					Name:      MonitorName,
					Namespace: MonitorNamespace,
				},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					Service: Service,
					SecretRef: expiringsecretv1alpha1.SecretReference{
						Name:      "non-existent-secret",
						Namespace: SecretNamespace,
					},
				},
			}
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			controllerReconciler := &MonitorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking the Monitor status shows error")
			Eventually(func() bool {
				found := &expiringsecretv1alpha1.Monitor{}
				err := k8sClient.Get(ctx, typeNamespacedName, found)
				if err != nil {
					return false
				}
				return found.Status.State == "Error" &&
					found.Status.Message == "Referenced secret not found"
			}, timeout, interval).Should(BeTrue())
		})

		It("should handle secret without validUntil label", func() {
			By("Creating a secret without validUntil label")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
				},
				Data: map[string][]byte{
					"token": []byte("fake-token"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource")
			monitor := &expiringsecretv1alpha1.Monitor{
				ObjectMeta: metav1.ObjectMeta{
					Name:      MonitorName,
					Namespace: MonitorNamespace,
				},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					Service: Service,
					SecretRef: expiringsecretv1alpha1.SecretReference{
						Name:      SecretName,
						Namespace: SecretNamespace,
					},
				},
			}
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			controllerReconciler := &MonitorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking the Monitor status shows error")
			Eventually(func() bool {
				found := &expiringsecretv1alpha1.Monitor{}
				err := k8sClient.Get(ctx, typeNamespacedName, found)
				if err != nil {
					return false
				}
				return found.Status.State == "Error" &&
					found.Status.Message != ""
			}, timeout, interval).Should(BeTrue())
		})

		It("should handle expired secrets correctly", func() {
			By("Creating a secret with past validUntil label")
			pastTime := time.Now().Add(-5 * 24 * time.Hour) // 5 days ago
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Labels: map[string]string{
						// Use RFC3339 date format (YYYY-MM-DD) - user-friendly and label-safe
						ValidUntilLabel: pastTime.Format("2006-01-02"),
					},
				},
				Data: map[string][]byte{
					"token": []byte("fake-token"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource")
			monitor := &expiringsecretv1alpha1.Monitor{
				ObjectMeta: metav1.ObjectMeta{
					Name:      MonitorName,
					Namespace: MonitorNamespace,
				},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					Service: Service,
					SecretRef: expiringsecretv1alpha1.SecretReference{
						Name:      SecretName,
						Namespace: SecretNamespace,
					},
				},
			}
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			controllerReconciler := &MonitorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking the Monitor status shows expired")
			Eventually(func() bool {
				found := &expiringsecretv1alpha1.Monitor{}
				err := k8sClient.Get(ctx, typeNamespacedName, found)
				if err != nil {
					return false
				}
				return found.Status.State == "Expired"
			}, timeout, interval).Should(BeTrue())
		})

		It("should handle critical threshold correctly", func() {
			By("Creating a secret expiring in 5 days")
			futureTime := time.Now().Add(5 * 24 * time.Hour)
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Labels: map[string]string{
						// Use RFC3339 date format (YYYY-MM-DD) - user-friendly and label-safe
						ValidUntilLabel: futureTime.Format("2006-01-02"),
					},
				},
				Data: map[string][]byte{
					"token": []byte("fake-token"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource with 7-day critical threshold")
			monitor := &expiringsecretv1alpha1.Monitor{
				ObjectMeta: metav1.ObjectMeta{
					Name:      MonitorName,
					Namespace: MonitorNamespace,
				},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					Service: Service,
					SecretRef: expiringsecretv1alpha1.SecretReference{
						Name:      SecretName,
						Namespace: SecretNamespace,
					},
					AlertThresholds: &expiringsecretv1alpha1.AlertThresholds{
						CriticalDays: 7,
					},
				},
			}
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			controllerReconciler := &MonitorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Checking the Monitor status shows critical")
			Eventually(func() bool {
				found := &expiringsecretv1alpha1.Monitor{}
				err := k8sClient.Get(ctx, typeNamespacedName, found)
				if err != nil {
					return false
				}
				return found.Status.State == "Critical"
			}, timeout, interval).Should(BeTrue())
		})
	})

	Context("When testing state calculation logic", func() {
		var reconciler *MonitorReconciler

		BeforeEach(func() {
			reconciler = &MonitorReconciler{}
		})

		It("should calculate Valid state correctly", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				Spec: expiringsecretv1alpha1.MonitorSpec{
					AlertThresholds: &expiringsecretv1alpha1.AlertThresholds{
						CriticalDays: 7,
						WarningDays:  14,
					},
				},
			}
			// 30 days remaining
			secondsRemaining := float64(30 * 24 * 60 * 60)
			state := reconciler.calculateState(monitor, secondsRemaining)
			Expect(state).To(Equal("Valid"))
		})

		It("should calculate Warning state correctly", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				Spec: expiringsecretv1alpha1.MonitorSpec{
					AlertThresholds: &expiringsecretv1alpha1.AlertThresholds{
						CriticalDays: 7,
						WarningDays:  14,
					},
				},
			}
			// 10 days remaining (between 7 and 14)
			secondsRemaining := float64(10 * 24 * 60 * 60)
			state := reconciler.calculateState(monitor, secondsRemaining)
			Expect(state).To(Equal("Warning"))
		})

		It("should calculate Critical state correctly", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				Spec: expiringsecretv1alpha1.MonitorSpec{
					AlertThresholds: &expiringsecretv1alpha1.AlertThresholds{
						CriticalDays: 7,
						WarningDays:  14,
					},
				},
			}
			// 3 days remaining (less than 7)
			secondsRemaining := float64(3 * 24 * 60 * 60)
			state := reconciler.calculateState(monitor, secondsRemaining)
			Expect(state).To(Equal("Critical"))
		})

		It("should calculate Expired state correctly", func() {
			monitor := &expiringsecretv1alpha1.Monitor{}
			// -5 days (expired 5 days ago)
			secondsRemaining := float64(-5 * 24 * 60 * 60)
			state := reconciler.calculateState(monitor, secondsRemaining)
			Expect(state).To(Equal("Expired"))
		})

		It("should use default thresholds when not specified", func() {
			monitor := &expiringsecretv1alpha1.Monitor{}
			// 10 days remaining (should be Warning with default 14-day threshold)
			secondsRemaining := float64(10 * 24 * 60 * 60)
			state := reconciler.calculateState(monitor, secondsRemaining)
			Expect(state).To(Equal("Warning"))
		})
	})
})

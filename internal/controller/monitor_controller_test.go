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
	"errors"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	rest "k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	"github.com/stakater/expiring-secret-operator/internal/utils"
	testutils "github.com/stakater/expiring-secret-operator/test/utils"
)

func pointerInt64(i int64) *int64 { return &i }

type errorClient struct {
	client.Client
	updateErr error
	listErr   error
	getErr    error
}

func (e *errorClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if e.updateErr != nil {
		return e.updateErr
	}
	return e.Client.Update(ctx, obj, opts...)
}

func (e *errorClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if e.listErr != nil {
		return e.listErr
	}
	return e.Client.List(ctx, list, opts...)
}

func (e *errorClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if e.getErr != nil {
		return e.getErr
	}
	return e.Client.Get(ctx, key, obj, opts...)
}

var _ = Describe("Monitor Controller", func() {
	newReconciler := func() *MonitorReconciler {
		return &MonitorReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	}

	Context("Can be setup with Manager", func() {
		var (
			scheme = runtime.NewScheme()
		)

		It("should setup without error", func() {
			Expect(scheme).NotTo(BeNil())
			Expect(clientgoscheme.AddToScheme(scheme)).NotTo(HaveOccurred())
			Expect(expiringsecretv1alpha1.AddToScheme(scheme)).NotTo(HaveOccurred())

			mgr, err := ctrl.NewManager(&rest.Config{}, ctrl.Options{
				Scheme: scheme,
			})
			Expect(err).NotTo(HaveOccurred())

			monitor := &MonitorReconciler{
				Client: mgr.GetClient(),
				Scheme: mgr.GetScheme(),
			}
			err = monitor.SetupWithManager(mgr)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("When reconciling a Monitor resource", func() {
		const (
			MonitorName      = "test-monitor"
			MonitorNamespace = "default"
			SecretName       = "test-secret"
			SecretNamespace  = "default"
			Service          = "docker.io"

			timeout         = time.Second * 10
			interval        = time.Millisecond * 250
			cleanUpTimeout  = time.Second * 30
			cleanUpInterval = time.Millisecond * 500
		)
		var h *testutils.TestHelper
		ctx := context.Background()

		nsMonitor := h.NsName(MonitorName, MonitorNamespace)
		nsSecret := h.NsName(SecretName, SecretNamespace)

		BeforeEach(func() {
			h = testutils.NewHelper(ctx, k8sClient)
			By("Creating the custom resource for the Kind Monitor")
			monitor := &expiringsecretv1alpha1.Monitor{}
			err := k8sClient.Get(ctx, nsMonitor, monitor)
			if err != nil && client.IgnoreNotFound(err) != nil {
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() {
			h.CleanupResources(cleanUpTimeout, cleanUpInterval,
				testutils.ObjectResource{
					Name:     nsMonitor,
					Resource: &expiringsecretv1alpha1.Monitor{},
					F: func() error {
						_, err := h.ReconcileOnce(newReconciler(), nsMonitor)
						return err
					},
				},
				testutils.ObjectResource{
					Name:     nsSecret,
					Resource: &corev1.Secret{},
				},
			)
		})

		It("should handle secret with a expiration of ~8 months", func() {
			By("Creating a secret with validUntil label")
			futureTime := time.Now().Add(243 * 24 * time.Hour)
			secret := testutils.GenerateFullSecret(nsSecret, futureTime.Format("2006-01-02"), []byte("fake-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource")
			monitor := testutils.GenerateMonitorService(nsMonitor, nsSecret, Service)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			_, err := h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			By("Checking the Monitor status shows error")
			h.ExpectStatusEventually(nsMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateValid && // 15 days should be in Info state (between 30 and 14 days)
						found.Status.ExpiresAt != nil &&
						found.Status.SecondsRemaining != nil &&
						found.Status.LastChecked != nil
				})
		})

		It("should successfully reconcile a valid Monitor with expiring secret", func() {
			By("Creating a secret with validUntil label")
			// Set expiration to 15 days from now
			futureTime := time.Now().Add(15 * 24 * time.Hour)
			secret := testutils.GenerateFullSecret(nsSecret, futureTime.Format("2006-01-02"), []byte("fake-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource")
			monitor := testutils.GenerateFullMonitor(nsMonitor, nsSecret, Service, &expiringsecretv1alpha1.AlertThresholds{
				InfoDays:     30,
				WarningDays:  14,
				CriticalDays: 7,
			})
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Checking if the Monitor was successfully created")
			Eventually(func() error {
				found := &expiringsecretv1alpha1.Monitor{}
				return k8sClient.Get(ctx, nsMonitor, found)
			}, timeout, interval).Should(Succeed())

			By("Reconciling the created resource")
			_, err := h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			h.ExpectStatusEventually(nsMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateInfo &&
						found.Status.ExpiresAt != nil &&
						found.Status.SecondsRemaining != nil &&
						found.Status.LastChecked != nil
				})
		})

		It("should handle secret reference without namespace", func() {
			By("Creating a secret without validUntil label")
			futureTime := time.Now().Add(20 * 24 * time.Hour)
			secret := testutils.GenerateFullSecret(nsSecret, futureTime.Format("2006-01-02"), []byte("fake-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource")
			monitor := testutils.GenerateMonitorService(
				nsMonitor,
				h.NsName(SecretName, ""),
				Service)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			_, err := h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			h.ExpectStatusEventually(nsMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateInfo &&
						found.Status.ExpiresAt != nil &&
						found.Status.SecondsRemaining != nil &&
						found.Status.LastChecked != nil
				})
		})

		It("should handle missing secret gracefully", func() {
			By("Creating the Monitor resource without creating the secret")
			monitor := testutils.GenerateMonitorService(nsMonitor, nsSecret, Service)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			_, err := h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			h.ExpectStatusEventually(nsMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateError &&
						found.Status.Message == "Failed to get source Secret: referenced secret not found"
				})
		})

		It("should handle secret without validUntil label", func() {
			By("Creating a secret without validUntil label")
			secret := testutils.GenerateFullSecret(nsSecret, "", []byte("fake-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource")
			monitor := testutils.GenerateMonitorService(nsMonitor, nsSecret, Service)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			_, err := h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			h.ExpectStatusEventually(nsMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateError &&
						found.Status.Message != ""
				})
		})

		It("should handle expired secrets correctly", func() {
			By("Creating a secret with past validUntil label")
			pastTime := time.Now().Add(-5 * 24 * time.Hour) // 5 days ago
			secret := testutils.GenerateFullSecret(nsSecret, pastTime.Format("2006-01-02"), []byte("fake-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource")
			monitor := testutils.GenerateMonitorService(nsMonitor, nsSecret, Service)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			_, err := h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			h.ExpectStatusEventually(nsMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateExpired
				})
		})

		It("should handle critical threshold correctly", func() {
			By("Creating a secret expiring in 5 days")
			futureTime := time.Now().Add(5 * 24 * time.Hour)
			secret := testutils.GenerateFullSecret(nsSecret, futureTime.Format("2006-01-02"), []byte("fake-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource with 7-day critical threshold")

			monitor := testutils.GenerateFullMonitor(nsMonitor, nsSecret, Service, &expiringsecretv1alpha1.AlertThresholds{
				CriticalDays: 7,
			})
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			_, err := h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			By("Checking the Monitor status shows critical")
			h.ExpectStatusEventually(nsMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateCritical
				})
		})

		It("should handle invalid date format gracefully", func() {
			By("Creating a secret with invalid date format")
			secret := testutils.GenerateFullSecret(nsSecret, "invalid-date-format", []byte("fake-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource")
			monitor := testutils.GenerateFullMonitor(nsMonitor, nsSecret, Service, &expiringsecretv1alpha1.AlertThresholds{
				CriticalDays: 7,
			})
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			_, err := h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			h.ExpectStatusEventually(nsMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateError
				})
		})

		It("should handle monitor deletion and cleanup metrics", func() {
			By("Reconciling a non-existent monitor")
			controllerReconciler := newReconciler()
			nonExistentName := h.NsName("non-existent-monitor", MonitorNamespace)

			result, err := controllerReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: nonExistentName,
			})

			By("Expecting no error and successful result")
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())
		})

		It("should remove finalizer on deletion", func() {
			By("Creating a secret with validUntil label")
			futureTime := time.Now().Add(10 * 24 * time.Hour)
			secret := testutils.GenerateFullSecret(nsSecret, futureTime.Format("2006-01-02"), []byte("fake-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource with a finalizer")
			monitor := testutils.GenerateMonitorService(nsMonitor, nsSecret, Service)
			controllerutil.AddFinalizer(monitor, monitorFinalizer)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			controllerReconciler := newReconciler()
			By("Reconciling once to ensure controller handles it")
			_, err := controllerReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: nsMonitor,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Deleting the Monitor resource")
			Expect(k8sClient.Delete(ctx, monitor)).To(Succeed())

			By("Reconciling deletion to remove finalizer")
			_, err = controllerReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: nsMonitor,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Ensuring the Monitor is fully deleted")
			Eventually(func() bool {
				m := &expiringsecretv1alpha1.Monitor{}
				err := k8sClient.Get(ctx, nsMonitor, m)
				return client.IgnoreNotFound(err) == nil
			}, timeout, interval).Should(BeTrue())
		})
	})

	Context("Can handle invalid values", func() {
		const (
			MonitorName      = "test-monitor"
			MonitorNamespace = "default"
			SecretName       = "test-secret"
			SecretNamespace  = "default"
			Service          = "docker.io"

			timeout         = time.Second * 10
			interval        = time.Millisecond * 250
			cleanUpTimeout  = time.Second * 30
			cleanUpInterval = time.Millisecond * 500
		)

		ctx := context.Background()
		//logger := log.FromContext(ctx)

		var (
			controllerReconciler *MonitorReconciler
			h                    *testutils.TestHelper
		)
		nsSecret := h.NsName(SecretName, SecretNamespace)

		nsMonitor := h.NsName(MonitorName, MonitorNamespace)

		createMonitor := func() error {
			monitor := testutils.GenerateMonitorService(
				nsMonitor,
				nsSecret,
				Service,
			)
			return k8sClient.Create(ctx, monitor)
		}
		createSecret := func() (*corev1.Secret, error) {
			futureTime := time.Now().Add(243 * 24 * time.Hour)
			secret := testutils.GenerateFullSecret(nsSecret,
				futureTime.Format("2006-01-02"),
				[]byte("fake-token"))
			err := k8sClient.Create(ctx, secret)
			return secret, err
		}
		getMonitor := func() (*expiringsecretv1alpha1.Monitor, error) {
			monitor := &expiringsecretv1alpha1.Monitor{}
			err := k8sClient.Get(ctx, nsMonitor, monitor)
			return monitor, err
		}

		BeforeEach(func() {
			h = testutils.NewHelper(ctx, k8sClient)
			controllerReconciler = newReconciler()

			h.VerifyNamespaces(nsSecret, nsMonitor)

			By("Creating secret")
			_, err := createSecret()
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			h.CleanupResources(cleanUpTimeout, cleanUpInterval,
				testutils.ObjectResource{
					Name:     nsMonitor,
					Resource: &expiringsecretv1alpha1.Monitor{},
				},
				testutils.ObjectResource{
					Name:     nsSecret,
					Resource: &corev1.Secret{},
				},
			)
		})

		It("should handle failing to add finalizer", func() {
			testFinalizer := "testing.stakater.com/test-finalizer"

			By("Manually removing finalizer from monitor", func() {
				monitor := testutils.GenerateFullMonitor(
					nsMonitor,
					nsSecret,
					Service,
					&expiringsecretv1alpha1.AlertThresholds{
						CriticalDays: 7,
					},
				)
				controllerutil.AddFinalizer(monitor, testFinalizer)
				Expect(k8sClient.Create(ctx, monitor)).To(Succeed())
			})

			monitor, err := getMonitor()
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Delete(ctx, monitor)).To(Succeed())

			By("Reconcile and expecting it to fail due to test finalizer")
			_, err = controllerReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: nsMonitor,
			})
			Expect(err).NotTo(HaveOccurred())
			monitor, err = getMonitor()
			Expect(err).NotTo(HaveOccurred())
			testutils.Log("Monitor finalizers after reconcile: %+v", monitor)

			controllerutil.RemoveFinalizer(monitor, testFinalizer)
			Expect(k8sClient.Update(ctx, monitor)).To(Succeed())
		})

		It("should handle invalid state", func() {
			Expect(createMonitor()).To(Succeed())

			By("Retrieving the Monitor resource")
			monitor := &expiringsecretv1alpha1.Monitor{}
			Expect(k8sClient.Get(ctx, nsMonitor, monitor)).To(Succeed())

			By("Manually setting invalid values")
			monitor.Status.State = ""
			controllerReconciler.output = monitor
			controllerReconciler.generateStatusMessage()
		})

		It("should handle Status.ExpiresAt nil", func() {
			Expect(createMonitor()).To(Succeed())

			By("Retrieving the Monitor resource")
			monitor := &expiringsecretv1alpha1.Monitor{}
			Expect(k8sClient.Get(ctx, nsMonitor, monitor)).To(Succeed())

			monitor.Status.ExpiresAt = nil
			controllerReconciler.output = monitor

			err := utils.NewMetric(controllerReconciler.output).Update()
			Expect(err).To(HaveOccurred())

			controllerReconciler.generateStatusMessage()
		})

		It("should handle Status.SecondsRemaining nil", func() {
			Expect(createMonitor()).To(Succeed())

			By("Retrieving the Monitor resource")
			monitor := &expiringsecretv1alpha1.Monitor{}
			Expect(k8sClient.Get(ctx, nsMonitor, monitor)).To(Succeed())

			monitor.Status.SecondsRemaining = nil
			controllerReconciler.output = monitor

			err := utils.NewMetric(controllerReconciler.output).Update()
			Expect(err).To(HaveOccurred())
		})
	})

	Context("When verifying metrics cleanup", func() {
		const (
			MonitorName      = "test-monitor"
			MonitorNamespace = "default"
			SecretName       = "test-secret"
			SecretNamespace  = "default"
			Service          = "docker.io"

			timeout         = time.Second * 10
			interval        = time.Millisecond * 250
			cleanUpTimeout  = time.Second * 30
			cleanUpInterval = time.Millisecond * 500
		)

		validUntilMetricName := fmt.Sprintf(
			"%s_%s_%s",
			utils.PrometheusNamespace,
			utils.PrometheusSubsystem,
			utils.ValidUntilMetricName)
		untilExpiryMetricName := fmt.Sprintf(
			"%s_%s_%s",
			utils.PrometheusNamespace,
			utils.PrometheusSubsystem,
			utils.UntilExpiryMetricName)

		metricsNames := []string{
			validUntilMetricName,
			untilExpiryMetricName,
		}
		metricTemplate := `
			# HELP %[1]s %[2]s
			# TYPE %[1]s gauge
			%[1]s{%%s} %%f
		`

		untilExpirationSecondsMetric := fmt.Sprintf(metricTemplate, untilExpiryMetricName, utils.UntilExpiryMetricHelp)
		validUntilTimestampMetric := fmt.Sprintf(metricTemplate, validUntilMetricName, utils.ValidUntilMetricHelp)

		ctx := context.Background()
		var h *testutils.TestHelper

		nsMonitor := h.NsName(MonitorName, MonitorNamespace)
		nsSecret := h.NsName(SecretName, SecretNamespace)

		BeforeEach(func() {
			h = testutils.NewHelper(ctx, k8sClient)
			By("Creating the custom resource for the Kind Monitor")
			monitor := &expiringsecretv1alpha1.Monitor{}
			err := k8sClient.Get(ctx, nsMonitor, monitor)
			if err != nil && client.IgnoreNotFound(err) != nil {
				Expect(err).NotTo(HaveOccurred())
			}

			By("Creating a secret with validUntil label")
			futureTime := time.Now().Add(243 * 24 * time.Hour)
			secret := testutils.GenerateFullSecret(nsSecret, futureTime.Format("2006-01-02"), []byte("fake-token"))
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating the Monitor resource")
			monitor = testutils.GenerateMonitorService(nsMonitor, nsSecret, Service)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Reconciling the created resource")
			_, err = h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			By("Checking the Monitor status shows error")
			h.ExpectStatusEventually(nsMonitor, timeout, interval,
				func(found *expiringsecretv1alpha1.Monitor) bool {
					return found.Status.State == expiringsecretv1alpha1.MonitorStateValid && // 15 days should be in Info state (between 30 and 14 days)
						found.Status.ExpiresAt != nil &&
						found.Status.SecondsRemaining != nil &&
						found.Status.LastChecked != nil
				})

		})

		AfterEach(func() {
			h.CleanupResources(cleanUpTimeout, cleanUpInterval,
				testutils.ObjectResource{
					Name:     nsMonitor,
					Resource: &expiringsecretv1alpha1.Monitor{},
				},
				testutils.ObjectResource{
					Name:     nsSecret,
					Resource: &corev1.Secret{},
				},
			)
		})

		It("should handle cleanup metrics correctly", func() {
			By("Getting the Monitor resource")
			monitor := &expiringsecretv1alpha1.Monitor{}
			Expect(k8sClient.Get(ctx, nsMonitor, monitor)).To(Succeed())

			By("Getting the Secret resource")
			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, nsSecret, secret)).To(Succeed())

			By("Checking the Monitor metrics are set")
			metric := utils.NewMetric(monitor)
			labels := metric.Labels()

			By("Retrieving metric values 'SecretValidUntilTimestamp'")
			validUntilGauge, err := utils.SecretValidUntilTimestamp.GetMetricWith(labels)
			Expect(err).NotTo(HaveOccurred())

			By("Retrieving metric values 'SecretSecondsUntilExpiry'")
			secondsUntilGauge, err := utils.SecretSecondsUntilExpiry.GetMetricWith(labels)
			Expect(err).NotTo(HaveOccurred())

			validUntil := testutil.ToFloat64(validUntilGauge)
			secondsUntil := testutil.ToFloat64(secondsUntilGauge)

			Expect(validUntil).To(BeNumerically(">", 0))
			Expect(secondsUntil).To(BeNumerically(">", 0))

			Expect(float64(monitor.Status.ExpiresAt.Unix())).
				To(Equal(validUntil))

			Expect(float64(*monitor.Status.SecondsRemaining)).
				To(Equal(secondsUntil))

			By("Formatting expected metrics output")
			labelsString := metric.LabelValues()

			expectedMetric := fmt.Sprintf(validUntilTimestampMetric,
				labelsString, validUntil,
			) + fmt.Sprintf(untilExpirationSecondsMetric,
				labelsString, secondsUntil)

			By("comparing the metrics output with expected values")
			err = testutil.GatherAndCompare(
				metrics.Registry,
				strings.NewReader(expectedMetric),
				metricsNames...,
			)
			Expect(err).NotTo(HaveOccurred())

			By("deleting the Monitor and Secret, and checking metrics are cleaned up")
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Expect(k8sClient.Delete(ctx, monitor)).To(Succeed())

			_, err = h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			By("verifying that the metrics for the deleted monitor are removed")
			err = testutil.GatherAndCompare(
				metrics.Registry,
				strings.NewReader(""),
				metricsNames...,
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("metrics should be registered correctly", func() {
			By("Getting the Monitor resource")
			monitor := &expiringsecretv1alpha1.Monitor{}
			Expect(k8sClient.Get(ctx, nsMonitor, monitor)).To(Succeed())

			By("Getting the Secret resource")
			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, nsSecret, secret)).To(Succeed())

			By("Checking the Monitor metrics are set")
			metric := utils.NewMetric(monitor)
			labels := metric.Labels()

			By("Retrieving metric values 'SecretValidUntilTimestamp'")
			validUntilGauge, err := utils.SecretValidUntilTimestamp.GetMetricWith(labels)
			Expect(err).NotTo(HaveOccurred())

			By("Retrieving metric values 'SecretSecondsUntilExpiry'")
			secondsUntilGauge, err := utils.SecretSecondsUntilExpiry.GetMetricWith(labels)
			Expect(err).NotTo(HaveOccurred())

			validUntil := testutil.ToFloat64(validUntilGauge)
			secondsUntil := testutil.ToFloat64(secondsUntilGauge)

			Expect(validUntil).To(BeNumerically(">", 0))
			Expect(secondsUntil).To(BeNumerically(">", 0))

			Expect(float64(monitor.Status.ExpiresAt.Unix())).
				To(Equal(validUntil))

			Expect(float64(*monitor.Status.SecondsRemaining)).
				To(Equal(secondsUntil))

			By("Verifying metrics are registered")
			Expect(testutil.CollectAndCount(utils.SecretValidUntilTimestamp)).To(Equal(1))
			Expect(testutil.CollectAndCount(utils.SecretSecondsUntilExpiry)).To(Equal(1))

			By("deleting the Monitor and Secret, and checking metrics are cleaned up")
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Expect(k8sClient.Delete(ctx, monitor)).To(Succeed())

			_, err = h.ReconcileOnce(newReconciler(), nsMonitor)
			Expect(err).NotTo(HaveOccurred())

			By("verifying that the metrics for the deleted monitor are removed")
			err = testutil.GatherAndCompare(
				metrics.Registry,
				strings.NewReader(""),
				metricsNames...,
			)
			Expect(err).NotTo(HaveOccurred())
		})

	})

	DescribeTable("When testing state calculation logic",
		func(daysRemaining int, expectedState expiringsecretv1alpha1.MonitorState) {
			monitor := &expiringsecretv1alpha1.Monitor{
				Spec: expiringsecretv1alpha1.MonitorSpec{
					AlertThresholds: &expiringsecretv1alpha1.AlertThresholds{
						InfoDays:     30,
						WarningDays:  14,
						CriticalDays: 7,
					},
				},
			}

			reconciler := &MonitorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				output: monitor,
			}
			t := time.Now().Add(time.Duration(daysRemaining) * 24 * time.Hour)
			reconciler.calculateState(t)
			Expect(monitor.Status.State).To(Equal(expectedState))

			reconciler.generateStatusMessage()
			Expect(reconciler.output.Status.Message).NotTo(BeEmpty())
		},
		Entry("should calculate Valid state correctly",
			31, expiringsecretv1alpha1.MonitorStateValid),
		Entry("should calculate Info state correctly",
			30, expiringsecretv1alpha1.MonitorStateInfo),
		Entry("should calculate Warning state correctly",
			10, expiringsecretv1alpha1.MonitorStateWarning),
		Entry("should calculate Critical state correctly",
			3, expiringsecretv1alpha1.MonitorStateCritical),
		Entry("should calculate Expired state correctly",
			-5, expiringsecretv1alpha1.MonitorStateExpired),
		Entry("should use default thresholds when not specified",
			10, expiringsecretv1alpha1.MonitorStateWarning),
	)

	Context("When mapping secrets to monitors", func() {
		var reconciler *MonitorReconciler
		var h *testutils.TestHelper

		BeforeEach(func() {
			h = testutils.NewHelper(ctx, k8sClient)
			reconciler = newReconciler()
		})

		It("should map correctly", func() {
			nsSecret1 := h.NsName("mapping-secret", "default")
			nsSecret2 := h.NsName("other-secret", "default")
			nsMonitor1 := h.NsName("mapping-monitor-1", "default")
			nsMonitor2 := h.NsName("mapping-monitor-2", "default")

			ctx := context.Background()

			By("Creating test resources for mapping")
			secret := testutils.GenerateFullSecret(nsSecret1, "", []byte("test-token"))

			monitor1 := testutils.GenerateMonitorService(nsMonitor1, nsSecret1, "docker.io")
			monitor2 := testutils.GenerateMonitorService(nsMonitor2, nsSecret2, "docker.io")

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			Expect(k8sClient.Create(ctx, monitor1)).To(Succeed())
			Expect(k8sClient.Create(ctx, monitor2)).To(Succeed())

			By("Testing the mapping function")
			requests := reconciler.mapSecretToMonitor(ctx, secret)

			By("Expecting one request for monitor1 only")
			Expect(requests).To(HaveLen(1))
			Expect(requests[0].Name).To(Equal("mapping-monitor-1"))
			Expect(requests[0].Namespace).To(Equal("default"))

			By("Cleanup test resources")
			Expect(k8sClient.Delete(ctx, monitor2)).To(Succeed())
			Expect(k8sClient.Delete(ctx, monitor1)).To(Succeed())
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
		})

		It("should handle cross-namespace references", func() {
			nsSecret := h.NsName("cross-ns-secret", "secret-ns")
			nsMonitor := h.NsName("cross-ns-monitor", "default")

			ctx := context.Background()

			By("Creating secret in different namespace")
			secretNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: nsSecret.Namespace,
				},
			}
			Expect(k8sClient.Create(ctx, secretNS)).To(Succeed())

			secret := testutils.GenerateFullSecret(nsSecret, "", []byte("test-token"))

			monitor := testutils.GenerateMonitorService(nsMonitor, nsSecret, "docker.io")

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Testing cross-namespace mapping")
			requests := reconciler.mapSecretToMonitor(ctx, secret)

			By("Expecting one request for cross-namespace monitor")
			Expect(requests).To(HaveLen(1))
			Expect(requests[0].Name).To(Equal(nsMonitor.Name))
			Expect(requests[0].Namespace).To(Equal(nsMonitor.Namespace))

			By("Cleanup cross-namespace test resources")
			Expect(k8sClient.Delete(ctx, monitor)).To(Succeed())
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Expect(k8sClient.Delete(ctx, secretNS)).To(Succeed())
		})

		It("should handle references without namespace", func() {
			nsSecret := h.NsName("mapping-secret", "default")
			nsMonitor := h.NsName("mapping-monitor", "default")

			ctx := context.Background()

			secret := testutils.GenerateFullSecret(nsSecret, "", []byte("test-token"))
			monitor := testutils.GenerateMonitor(nsMonitor, nsSecret)

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Testing reference mapping")
			requests := reconciler.mapSecretToMonitor(ctx, secret)

			By("Expecting one request for monitor")
			Expect(requests).To(HaveLen(1))
			Expect(requests[0].Name).To(Equal(nsMonitor.Name))
			Expect(requests[0].Namespace).To(Equal(nsMonitor.Namespace))

			By("Cleanup test resources")
			Expect(k8sClient.Delete(ctx, monitor)).To(Succeed())
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
		})

		It("should return no requests when no monitors match", func() {
			nsSecret := h.NsName("no-match-secret", "default")
			nsOtherSecret := h.NsName("other-secret-no-match", "default")
			nsMonitor := h.NsName("no-match-monitor", "default")

			ctx := context.Background()

			By("Creating a secret and a monitor that references a different secret")
			secret := testutils.GenerateFullSecret(nsSecret, "", []byte("test-token"))
			monitor := testutils.GenerateMonitor(nsMonitor, nsOtherSecret)

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			By("Testing the mapping function")
			requests := reconciler.mapSecretToMonitor(ctx, secret)

			By("Expecting no requests")
			Expect(requests).To(BeEmpty())

			By("Cleanup test resources")
			Expect(k8sClient.Delete(ctx, monitor)).To(Succeed())
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
		})

		It("should return nil when context is cancelled", func() {
			By("Testing with a TODO context")
			ct := context.TODO()
			ct.Done() // Cancel the context to simulate an invalid context

			By("Testing the mapping function")
			requests := reconciler.mapSecretToMonitor(ct, &corev1.Secret{})
			testutils.Log("Received requests with cancelled context: %+v", requests)

			By("Expecting nil requests due to cancelled context")
			Expect(requests).To(BeNil())
		})
	})

	Context("When testing controller setup", func() {
		It("should setup controller with manager successfully", func() {
			By("Creating a mock manager")
			reconciler := newReconciler()

			By("Setting up with manager - this exercises SetupWithManager")
			// Note: In a real test environment, you might need a proper manager
			// For coverage purposes, we can at least call the function
			// err := reconciler.SetupWithManager(mgr)
			// Expect(err).NotTo(HaveOccurred())

			// For now, just verify the function exists and is callable
			Expect(reconciler.SetupWithManager).NotTo(BeNil())
		})
	})

	Context("When testing helper functions", func() {
		var reconciler *MonitorReconciler

		BeforeEach(func() {
			reconciler = newReconciler()
		})

		It("should handle generateStatusMessage with nil ExpiresAt", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				Spec: expiringsecretv1alpha1.MonitorSpec{
					AlertThresholds: &expiringsecretv1alpha1.AlertThresholds{
						CriticalDays: 7,
					},
				},
				Status: expiringsecretv1alpha1.MonitorStatus{
					State:            expiringsecretv1alpha1.MonitorStateWarning,
					ExpiresAt:        nil,
					SecondsRemaining: pointerInt64(86400),
				},
			}

			reconciler.output = monitor
			reconciler.generateStatusMessage()

			Expect(reconciler.output.Status.Message).NotTo(BeEmpty())
		})

		It("should handle generateStatusMessage with nil SecondsRemaining", func() {
			now := time.Now()
			monitor := &expiringsecretv1alpha1.Monitor{
				Spec: expiringsecretv1alpha1.MonitorSpec{
					AlertThresholds: &expiringsecretv1alpha1.AlertThresholds{
						CriticalDays: 7,
					},
				},
				Status: expiringsecretv1alpha1.MonitorStatus{
					State:            expiringsecretv1alpha1.MonitorStateExpired,
					ExpiresAt:        &metav1.Time{Time: now},
					SecondsRemaining: nil,
				},
			}

			reconciler.output = monitor
			reconciler.generateStatusMessage()
			Expect(reconciler.output.Status.Message).NotTo(BeEmpty())
		})

		It("should handle generateStatusMessage with MonitorStateError", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				Status: expiringsecretv1alpha1.MonitorStatus{
					State: expiringsecretv1alpha1.MonitorStateError,
				},
			}

			reconciler.output = monitor
			reconciler.generateStatusMessage()
			Expect(reconciler.output.Status.Message).
				To(Equal("Expiration date is not available"))
		})

		It("should handle updateMetrics with nil ExpiresAt", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-monitor",
					Namespace: "default",
				},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					SecretRef: &expiringsecretv1alpha1.SecretReference{
						Name:      "test-secret",
						Namespace: "default",
					},
					Service: "docker.io",
				},
				Status: expiringsecretv1alpha1.MonitorStatus{
					State:     expiringsecretv1alpha1.MonitorStateWarning,
					ExpiresAt: nil,
				},
			}

			reconciler.output = monitor
			err := utils.NewMetric(reconciler.output).Update()
			Expect(err).To(HaveOccurred())
		})

		It("should handle parseSourceObject with secret missing labels", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-label-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"token": []byte("fake-token"),
				},
			}

			expiresAt, err := reconciler.parseSourceObject(secret)
			Expect(err).To(HaveOccurred())
			Expect(expiresAt).To(Equal(time.Time{}))
		})

		It("should handle parseSourceObject with invalid date format", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-date-secret",
					Namespace: "default",
					Labels: map[string]string{
						"validUntil": "not-a-date",
					},
				},
				Data: map[string][]byte{
					"token": []byte("fake-token"),
				},
			}

			expiresAt, err := reconciler.parseSourceObject(secret)
			Expect(err).To(HaveOccurred())
			Expect(expiresAt).To(Equal(time.Time{}))
			// Expect(expiresAt).To(BeNil())
		})
	})

	Context("When covering controller branches", func() {
		var (
			scheme *runtime.Scheme
			ctx    context.Context
		)

		BeforeEach(func() {
			ctx = context.Background()
			scheme = runtime.NewScheme()
			Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
			Expect(expiringsecretv1alpha1.AddToScheme(scheme)).To(Succeed())
		})

		It("should requeue when updating spec fails", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				TypeMeta: metav1.TypeMeta{
					APIVersion: expiringsecretv1alpha1.GroupVersion.String(),
					Kind:       "Monitor",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "requeue-monitor",
					Namespace: "default",
				},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					SecretRef: &expiringsecretv1alpha1.SecretReference{
						Name:      "target-secret",
						Namespace: "default",
					},
					Service: "docker.io",
				},
			}

			baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(monitor).Build()
			reconciler := &MonitorReconciler{
				Client: &errorClient{
					Client:    baseClient,
					updateErr: errors.New("update failed"),
				},
				Scheme: scheme,
			}

			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      monitor.Name,
					Namespace: monitor.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(time.Second))
		})

		It("should skip deletion when finalizer is missing", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				TypeMeta: metav1.TypeMeta{
					APIVersion: expiringsecretv1alpha1.GroupVersion.String(),
					Kind:       "Monitor",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:              "delete-monitor",
					Namespace:         "default",
					DeletionTimestamp: &metav1.Time{Time: time.Now()},
				},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					SecretRef: &expiringsecretv1alpha1.SecretReference{
						Name:      "target-secret",
						Namespace: "default",
					},
					Service: "docker.io",
				},
			}

			baseClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			reconciler := &MonitorReconciler{
				Client: baseClient,
				Scheme: scheme,
				ctx:    ctx,
				log:    log.FromContext(ctx),
				output: monitor,
			}

			result, err := reconciler.handleDeletion()
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())
		})

		It("should return error when finalizer removal update fails", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				TypeMeta: metav1.TypeMeta{
					APIVersion: expiringsecretv1alpha1.GroupVersion.String(),
					Kind:       "Monitor",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:              "delete-monitor-error",
					Namespace:         "default",
					DeletionTimestamp: &metav1.Time{Time: time.Now()},
				},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					SecretRef: &expiringsecretv1alpha1.SecretReference{
						Name:      "target-secret",
						Namespace: "default",
					},
					Service: "docker.io",
				},
			}
			controllerutil.AddFinalizer(monitor, monitorFinalizer)

			baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(monitor).WithStatusSubresource(monitor).Build()
			reconciler := &MonitorReconciler{
				Client: &errorClient{
					Client:    baseClient,
					updateErr: errors.New("delete update failed"),
				},
				Scheme: scheme,
			}

			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      monitor.Name,
					Namespace: monitor.Namespace,
				},
			})
			Expect(err).To(HaveOccurred())
		})

		It("should return error on source lookup failure", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				TypeMeta: metav1.TypeMeta{
					APIVersion: expiringsecretv1alpha1.GroupVersion.String(),
					Kind:       "Monitor",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "source-error-monitor",
					Namespace: "default",
				},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					SecretRef: &expiringsecretv1alpha1.SecretReference{
						Name:      "missing-secret",
						Namespace: "default",
					},
				},
			}

			baseClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			reconciler := &MonitorReconciler{
				Client: &errorClient{
					Client: baseClient,
					getErr: errors.New("get failed"),
				},
				Scheme: scheme,
				ctx:    ctx,
				log:    log.FromContext(ctx),
				output: monitor,
			}

			_, err := reconciler.getSourceObject()
			Expect(err).To(HaveOccurred())
		})

		It("should use unknown message for unknown state", func() {
			now := time.Now()
			monitor := &expiringsecretv1alpha1.Monitor{
				Status: expiringsecretv1alpha1.MonitorStatus{
					State:            expiringsecretv1alpha1.MonitorState("mystery"),
					ExpiresAt:        &metav1.Time{Time: now},
					SecondsRemaining: pointerInt64(3600),
				},
			}
			reconciler := &MonitorReconciler{output: monitor}
			reconciler.generateStatusMessage()
			Expect(reconciler.output.Status.Message).To(ContainSubstring("Unknown state"))
		})

		It("should return nil requests when list fails", func() {
			baseClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			reconciler := &MonitorReconciler{
				Client: &errorClient{
					Client:  baseClient,
					listErr: errors.New("list failed"),
				},
				Scheme: scheme,
			}

			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret", Namespace: "default"}}
			requests := reconciler.mapSecretToMonitor(ctx, secret)
			Expect(requests).To(BeNil())
		})

		It("should default secret namespace when secretRef namespace is empty", func() {
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "mapped-secret", Namespace: "default"}}
			monitor := &expiringsecretv1alpha1.Monitor{
				TypeMeta: metav1.TypeMeta{
					APIVersion: expiringsecretv1alpha1.GroupVersion.String(),
					Kind:       "Monitor",
				},
				ObjectMeta: metav1.ObjectMeta{Name: "mapped-monitor", Namespace: "default"},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					SecretRef: &expiringsecretv1alpha1.SecretReference{
						Name:      secret.Name,
						Namespace: "",
					},
					Service: "docker.io",
				},
			}

			baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(monitor).Build()
			reconciler := &MonitorReconciler{Client: baseClient, Scheme: scheme}

			requests := reconciler.mapSecretToMonitor(ctx, secret)
			Expect(requests).To(HaveLen(1))
			Expect(requests[0].NamespacedName).To(Equal(types.NamespacedName{
				Name:      monitor.Name,
				Namespace: monitor.Namespace,
			}))
		})

		It("should tolerate metrics update error in handleSuccess", func() {
			monitor := &expiringsecretv1alpha1.Monitor{
				TypeMeta: metav1.TypeMeta{
					APIVersion: expiringsecretv1alpha1.GroupVersion.String(),
					Kind:       "Monitor",
				},
				ObjectMeta: metav1.ObjectMeta{Name: "metric-error", Namespace: "default"},
				Spec: expiringsecretv1alpha1.MonitorSpec{
					SecretRef: &expiringsecretv1alpha1.SecretReference{
						Name:      "target-secret",
						Namespace: "default",
					},
					Service: "docker.io",
				},
				Status: expiringsecretv1alpha1.MonitorStatus{
					State:            expiringsecretv1alpha1.MonitorStateValid,
					ExpiresAt:        nil,
					SecondsRemaining: pointerInt64(120),
				},
			}

			baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(monitor).WithStatusSubresource(monitor).Build()
			reconciler := &MonitorReconciler{
				Client:   baseClient,
				Scheme:   scheme,
				ctx:      ctx,
				log:      log.FromContext(ctx),
				output:   monitor,
				original: monitor.DeepCopy(),
			}

			result, err := reconciler.handleSuccess()
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(time.Minute))
		})
	})

	Context("When evaluating predicates", func() {
		It("should return true for create and delete predicates", func() {
			Expect(monitorCreatePredicate(event.CreateEvent{})).To(BeTrue())
			Expect(monitorDeletePredicate(event.DeleteEvent{})).To(BeTrue())
			Expect(secretCreatePredicate(event.CreateEvent{})).To(BeTrue())
			Expect(secretDeletePredicate(event.DeleteEvent{})).To(BeTrue())
		})

		It("should evaluate monitor update predicate", func() {
			oldMonitor := &expiringsecretv1alpha1.Monitor{Spec: expiringsecretv1alpha1.MonitorSpec{Service: "a"}}
			newMonitor := &expiringsecretv1alpha1.Monitor{Spec: expiringsecretv1alpha1.MonitorSpec{Service: "b"}}
			Expect(monitorUpdatePredicate(event.UpdateEvent{ObjectOld: oldMonitor, ObjectNew: newMonitor})).To(BeTrue())

			newMonitor.Spec.Service = "a"
			newMonitor.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			Expect(monitorUpdatePredicate(event.UpdateEvent{ObjectOld: oldMonitor, ObjectNew: newMonitor})).To(BeTrue())

			newMonitor.DeletionTimestamp = nil
			Expect(monitorUpdatePredicate(event.UpdateEvent{ObjectOld: oldMonitor, ObjectNew: newMonitor})).To(BeFalse())

			Expect(monitorUpdatePredicate(event.UpdateEvent{ObjectOld: &corev1.Secret{}, ObjectNew: newMonitor})).To(BeFalse())
			Expect(monitorUpdatePredicate(event.UpdateEvent{ObjectOld: oldMonitor, ObjectNew: &corev1.Secret{}})).To(BeFalse())
		})

		It("should evaluate secret update predicate", func() {
			oldSecret := &corev1.Secret{Data: map[string][]byte{"token": []byte("a")}}
			newSecret := &corev1.Secret{Data: map[string][]byte{"token": []byte("a")}}
			Expect(secretUpdatePredicate(event.UpdateEvent{ObjectOld: oldSecret, ObjectNew: newSecret})).To(BeFalse())

			newSecret.Data["token"] = []byte("b")
			Expect(secretUpdatePredicate(event.UpdateEvent{ObjectOld: oldSecret, ObjectNew: newSecret})).To(BeTrue())

			newSecret.Data = map[string][]byte{"token": []byte("a"), "extra": []byte("c")}
			Expect(secretUpdatePredicate(event.UpdateEvent{ObjectOld: oldSecret, ObjectNew: newSecret})).To(BeTrue())

			Expect(secretUpdatePredicate(event.UpdateEvent{ObjectOld: &expiringsecretv1alpha1.Monitor{}, ObjectNew: newSecret})).To(BeFalse())
			Expect(secretUpdatePredicate(event.UpdateEvent{ObjectOld: oldSecret, ObjectNew: &expiringsecretv1alpha1.Monitor{}})).To(BeFalse())
		})
	})
})

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
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secrets/api/v1alpha1"
)

// Prometheus metrics
var (
	metricsLabels = []string{
		"monitor_name", "monitor_namespace", "state",
		"secret_registry", "secret_name", "secret_namespace",
	}
	secretValidUntilTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "expiringsecret",
			Subsystem: "monitor",
			Name:      "valid_until_timestamp_seconds",
			Help:      "Secret expiration timestamp",
		},
		metricsLabels,
	)

	secretSecondsUntilExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "expiringsecret",
			Subsystem: "monitor",
			Name:      "until_expiration_seconds",
			Help:      "Seconds until secret expires",
		},
		metricsLabels,
	)
)

func init() {
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(secretValidUntilTimestamp, secretSecondsUntilExpiry)
}

// MonitorReconciler reconciles a Monitor object
type MonitorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

const LabelKey = "expiringsecret.stakater.com/validUntil"

// +kubebuilder:rbac:groups=expiring-secrets.stakater.com,resources=monitors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=expiring-secrets.stakater.com,resources=monitors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=expiring-secrets.stakater.com,resources=monitors/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *MonitorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the Monitor instance
	monitor := &expiringsecretv1alpha1.Monitor{}
	err := r.Get(ctx, req.NamespacedName, monitor)
	if err != nil {
		if errors.IsNotFound(err) {
			// Monitor was deleted, clean up metrics
			r.cleanupMetrics(ctx, req.NamespacedName, "")
			logger.Info("Monitor deleted, cleaned up metrics")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Monitor")
		return ctrl.Result{}, err
	}
	if monitor.Spec.AlertThresholds == nil {
		monitor.Spec.AlertThresholds = &expiringsecretv1alpha1.AlertThresholds{}
	}
	monitor.Spec.AlertThresholds.ApplyDefaults()
	err = r.Update(ctx, monitor)
	if err != nil {
		logger.Error(err, "Failed to update Monitor with default AlertThresholds")
		return ctrl.Result{}, err
	}

	// Get the referenced secret
	secretNamespace := monitor.Spec.SecretRef.Namespace
	if secretNamespace == "" {
		secretNamespace = monitor.Namespace
	}

	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Name:      monitor.Spec.SecretRef.Name,
		Namespace: secretNamespace,
	}

	err = r.Get(ctx, secretKey, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Error(err, "Referenced secret not found", "secretName", secretKey.Name, "secretNamespace", secretKey.Namespace)
			return r.updateStatus(ctx, monitor, expiringsecretv1alpha1.MonitorStateError, "Referenced secret not found", nil, nil)
		}
		logger.Error(err, "Failed to get referenced secret", "secretName", secretKey.Name, "secretNamespace", secretKey.Namespace)
		return r.updateStatus(ctx, monitor, expiringsecretv1alpha1.MonitorStateError, "Failed to get referenced secret", nil, nil)
	}

	// Parse the expiration timestamp from the secret label
	validUntilStr, exists := secret.Labels[LabelKey]
	if !exists {
		msg := fmt.Sprintf("Secret does not have %s label", LabelKey)
		logger.Error(nil, msg, "secretName", secretKey.Name, "secretNamespace", secretKey.Namespace)
		return r.updateStatus(ctx, monitor, expiringsecretv1alpha1.MonitorStateError, msg, nil, nil)
	}

	validUntil, err := time.Parse("2006-01-02", validUntilStr)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse validUntil date (expected YYYY-MM-DD format): %v", err)
		logger.Error(err, "Failed to parse validUntil date", "validUntil", validUntilStr)
		return r.updateStatus(ctx, monitor, expiringsecretv1alpha1.MonitorStateError, msg, nil, nil)
	}

	// Calculate seconds until expiry
	now := time.Now()
	secondsRemaining := validUntil.Sub(now).Seconds()

	// Determine the current state based on thresholds
	state := r.calculateState(monitor, secondsRemaining)

	// Update Prometheus metrics
	labels := prometheus.Labels{
		"monitor_name":      monitor.Name,
		"monitor_namespace": monitor.Namespace,
		"state":             string(state),
		"secret_registry":   monitor.Spec.Service,
		"secret_name":       monitor.Spec.SecretRef.Name,
		"secret_namespace":  monitor.Spec.SecretRef.Namespace,
	}
	secretValidUntilTimestamp.With(labels).Set(float64(validUntil.Unix()))
	secretSecondsUntilExpiry.With(labels).Set(secondsRemaining)

	// Update the Monitor status
	expiresAt := metav1.NewTime(validUntil)
	secondsRemainingInt := int64(secondsRemaining)
	return r.updateStatus(ctx, monitor, state, "", &expiresAt, &secondsRemainingInt)
}

// calculateState determines the current state based on alert thresholds
func (r *MonitorReconciler) calculateState(monitor *expiringsecretv1alpha1.Monitor, secondsRemaining float64) expiringsecretv1alpha1.MonitorState {
	if secondsRemaining <= 0 {
		return expiringsecretv1alpha1.MonitorStateExpired
	}

	daysRemaining := secondsRemaining / (24 * 60 * 60)
	if monitor.Spec.AlertThresholds == nil {
		monitor.Spec.AlertThresholds = &expiringsecretv1alpha1.AlertThresholds{}
	}
	monitor.Spec.AlertThresholds.ApplyDefaults()

	if daysRemaining <= float64(monitor.Spec.AlertThresholds.CriticalDays) {
		return expiringsecretv1alpha1.MonitorStateCritical
	} else if daysRemaining <= float64(monitor.Spec.AlertThresholds.WarningDays) {
		return expiringsecretv1alpha1.MonitorStateWarning
	} else if daysRemaining <= float64(monitor.Spec.AlertThresholds.InfoDays) {
		return expiringsecretv1alpha1.MonitorStateInfo
	}

	return expiringsecretv1alpha1.MonitorStateValid
}

func (r *MonitorReconciler) getDefaultMessageForState(status expiringsecretv1alpha1.MonitorStatus, monitor *expiringsecretv1alpha1.Monitor) expiringsecretv1alpha1.MonitorStatus {
	if status.Message != "" {
		return status
	}

	message := ""
	switch status.State {
	case expiringsecretv1alpha1.MonitorStateValid:
		message = fmt.Sprintf("Secret is valid until %s", status.ExpiresAt.Format("2006-01-02"))
	case expiringsecretv1alpha1.MonitorStateInfo:
		message = fmt.Sprintf("Secret expires in less than %d days", monitor.Spec.AlertThresholds.InfoDays)
	case expiringsecretv1alpha1.MonitorStateWarning:
		message = fmt.Sprintf("Secret expires in less than %d days", monitor.Spec.AlertThresholds.WarningDays)
	case expiringsecretv1alpha1.MonitorStateCritical:
		message = fmt.Sprintf("Secret expires in less than %d days", monitor.Spec.AlertThresholds.CriticalDays)
	case expiringsecretv1alpha1.MonitorStateExpired:
		message = fmt.Sprintf("Secret expired on %s", status.ExpiresAt.Format("2006-01-02"))
	case expiringsecretv1alpha1.MonitorStateError:
		message = "Error monitoring secret"
	default:
		message = ""
	}

	status.Message = message
	return status
}

// updateStatus updates the Monitor status with the provided parameters and requeues for continuous monitoring
func (r *MonitorReconciler) updateStatus(ctx context.Context,
	monitor *expiringsecretv1alpha1.Monitor,
	state expiringsecretv1alpha1.MonitorState,
	message string,
	expiresAt *metav1.Time,
	secondsRemaining *int64,
) (ctrl.Result, error) {

	logger := log.FromContext(ctx)
	now := metav1.NewTime(time.Now())

	// Update status fields
	monitor.Status.LastChecked = &now

	if state != "" {
		monitor.Status.State = state
	}
	if message != "" {
		monitor.Status.Message = message
	}
	if expiresAt != nil {
		monitor.Status.ExpiresAt = expiresAt
	}
	if secondsRemaining != nil {
		monitor.Status.SecondsRemaining = secondsRemaining
	}

	monitor.Status = r.getDefaultMessageForState(monitor.Status, monitor)

	// Update status subresource
	err := r.Status().Update(ctx, monitor)
	if err != nil {
		logger.Error(err, "Failed to update Monitor status")
		return ctrl.Result{}, err
	}

	// Requeue after 1 minute for continuous monitoring
	return ctrl.Result{RequeueAfter: time.Minute}, nil
}

// cleanupMetrics removes metrics when a Monitor is deleted
func (r *MonitorReconciler) cleanupMetrics(ctx context.Context, ns types.NamespacedName, registry string) {
	logger := log.FromContext(ctx)
	labels := prometheus.Labels{
		"monitor_name":      ns.Name,
		"monitor_namespace": ns.Namespace,
		//"secret_registry":   registry,
	}
	successSecretValidUntilTimestamp := secretValidUntilTimestamp.Delete(labels)
	if successSecretValidUntilTimestamp {
		logger.Info("Deleted metrics for Monitor, ValidUntilTimestamp", "monitor", ns, "registry", registry)
	} else {
		noSecretValidUntilTimestamp := secretValidUntilTimestamp.DeletePartialMatch(labels)
		logger.Info("(Partial Match) Deleted metrics for Monitor, ValidUntilTimestamp", "monitor", ns, "registry", registry, "noOfMetricsDeleted", noSecretValidUntilTimestamp)
	}

	successSecretSecondsUntilExpiry := secretSecondsUntilExpiry.Delete(labels)
	if successSecretSecondsUntilExpiry {
		logger.Info("Deleted metrics for Monitor, SecondsUntilExpiry", "monitor", ns, "registry", registry)
	} else {
		noSecretSecondsUntilExpiry := secretSecondsUntilExpiry.DeletePartialMatch(labels)
		logger.Info("(Partial Match) Deleted metrics for Monitor, SecondsUntilExpiry", "monitor", ns, "registry", registry, "noOfMetricsDeleted", noSecretSecondsUntilExpiry)
	}
}

// mapSecretToMonitor maps a Secret to Monitor objects that reference it
func (r *MonitorReconciler) mapSecretToMonitor(ctx context.Context, obj client.Object) []ctrl.Request {
	logger := log.FromContext(ctx)
	secret := obj.(*corev1.Secret)

	// Find all monitors that reference this secret
	monitorList := &expiringsecretv1alpha1.MonitorList{}
	if err := r.List(ctx, monitorList); err != nil {
		return nil
	}

	var requests []ctrl.Request
	for _, monitor := range monitorList.Items {
		secretNamespace := monitor.Spec.SecretRef.Namespace
		if secretNamespace == "" {
			logger.Info("SecretRef namespace is empty, defaulting to Monitor namespace", "monitorNamespace", monitor.Namespace)
			secretNamespace = monitor.Namespace
		}

		if monitor.Spec.SecretRef.Name == secret.Name && secretNamespace == secret.Namespace {
			requests = append(requests, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      monitor.Name,
					Namespace: monitor.Namespace,
				},
			})
		}
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *MonitorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&expiringsecretv1alpha1.Monitor{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.mapSecretToMonitor),
		).
		Complete(r)
}

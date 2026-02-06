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
	secretValidUntilTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "secretmonitor_valid_until_timestamp",
			Help: "PAT expiration timestamp (unix)",
		},
		[]string{"registry", "name", "namespace"},
	)

	secretSecondsUntilExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "secretmonitor_seconds_until_expiry",
			Help: "Seconds until PAT expires",
		},
		[]string{"registry", "name", "namespace"},
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

// +kubebuilder:rbac:groups=expiringsecret.stakater.com,resources=monitors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=expiringsecret.stakater.com,resources=monitors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=expiringsecret.stakater.com,resources=monitors/finalizers,verbs=update
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
			r.cleanupMetrics(req.NamespacedName, "")
			logger.Info("Monitor deleted, cleaned up metrics")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Monitor")
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
			logger.Info("Referenced secret not found", "secret", secretKey)
			return r.updateStatus(ctx, monitor, expiringsecretv1alpha1.MonitorStateError, "Referenced secret not found", nil, nil)
		}
		logger.Error(err, "Failed to get referenced secret", "secret", secretKey)
		return r.updateStatus(ctx, monitor, expiringsecretv1alpha1.MonitorStateError, "Failed to get referenced secret", nil, nil)
	}

	// Parse the expiration timestamp from the secret label
	validUntilStr, exists := secret.Labels["expiringsecret.stakater.com/validUntil"]
	if !exists {
		msg := "Secret does not have expiringsecret.stakater.com/validUntil label"
		logger.Info(msg, "secret", secretKey)
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

	// Update Prometheus metrics
	labels := prometheus.Labels{
		"registry":  monitor.Spec.Service,
		"name":      monitor.Name,
		"namespace": monitor.Namespace,
	}
	secretValidUntilTimestamp.With(labels).Set(float64(validUntil.Unix()))
	secretSecondsUntilExpiry.With(labels).Set(secondsRemaining)

	// Determine the current state based on thresholds
	state := r.calculateState(monitor, secondsRemaining)

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

	// Use default thresholds if not specified
	infoDays := int32(30)
	warningDays := int32(14)
	criticalDays := int32(7)

	if monitor.Spec.AlertThresholds != nil {
		if monitor.Spec.AlertThresholds.InfoDays > 0 {
			infoDays = monitor.Spec.AlertThresholds.InfoDays
		}
		if monitor.Spec.AlertThresholds.WarningDays > 0 {
			warningDays = monitor.Spec.AlertThresholds.WarningDays
		}
		if monitor.Spec.AlertThresholds.CriticalDays > 0 {
			criticalDays = monitor.Spec.AlertThresholds.CriticalDays
		}
	}

	if daysRemaining <= float64(criticalDays) {
		return expiringsecretv1alpha1.MonitorStateCritical
	} else if daysRemaining <= float64(warningDays) {
		return expiringsecretv1alpha1.MonitorStateWarning
	} else if daysRemaining <= float64(infoDays) {
		return expiringsecretv1alpha1.MonitorStateInfo
	}

	return expiringsecretv1alpha1.MonitorStateValid
}

// updateStatus updates the Monitor status with multiple possible parameters
func (r *MonitorReconciler) updateStatus(ctx context.Context, monitor *expiringsecretv1alpha1.Monitor, state expiringsecretv1alpha1.MonitorState, message string, expiresAt *metav1.Time, secondsRemaining *int64) (ctrl.Result, error) {
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

	// Update status subresource
	err := r.Status().Update(ctx, monitor)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Requeue after 1 minute for continuous monitoring
	return ctrl.Result{RequeueAfter: time.Minute}, nil
}

// cleanupMetrics removes metrics when a Monitor is deleted
func (r *MonitorReconciler) cleanupMetrics(ns types.NamespacedName, registry string) {
	labels := prometheus.Labels{
		"registry":  registry,
		"name":      ns.Name,
		"namespace": ns.Namespace,
	}
	secretValidUntilTimestamp.Delete(labels)
	secretSecondsUntilExpiry.Delete(labels)
}

// mapSecretToMonitor maps a Secret to Monitor objects that reference it
func (r *MonitorReconciler) mapSecretToMonitor(ctx context.Context, obj client.Object) []ctrl.Request {
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

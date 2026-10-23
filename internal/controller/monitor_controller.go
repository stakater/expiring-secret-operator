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

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	"github.com/stakater/expiring-secret-operator/internal/utils"
)

// MonitorReconciler reconciles a Monitor object
type MonitorReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	ctx context.Context
	log logr.Logger

	output *expiringsecretv1alpha1.Monitor
	// original holds a deep copy used for status patching
	original *expiringsecretv1alpha1.Monitor
}

const (
	monitorFinalizer        = "expiring-secrets.stakater.com/monitor-finalizer"
	LabelKey                = "expiring-secrets.stakater.com/validUntil"
	sourceLabelNotAvailable = "sourceLabelNotAvailable"
)

type MonitorErrorReasonMessage struct {
	Reason  string
	Message string
}

func (e *MonitorErrorReasonMessage) Error() string { return e.Message }

// +kubebuilder:rbac:groups=expiring-secrets.stakater.com,resources=monitors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=expiring-secrets.stakater.com,resources=monitors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=expiring-secrets.stakater.com,resources=monitors/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// func (r *MonitorReconciler) Reconcile(ctx context.Context, req *expiringsecretv1alpha1.Monitor) (ctrl.Result, error) {
func (r *MonitorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.ctx = ctx
	r.log = log.FromContext(ctx)

	r.log.Info("Reconciling Monitor", "namespace", req.Namespace, "name", req.Name)

	r.output = &expiringsecretv1alpha1.Monitor{}
	if err := r.Get(ctx, req.NamespacedName, r.output); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	r.original = r.output.DeepCopy()

	// Handle deletion
	r.log.Info("Is deleted?", "res", r.output.DeletionTimestamp)
	if r.output.DeletionTimestamp != nil {
		r.log.Info("Handling deletion of Monitor", "namespace", req.Namespace, "name", req.Name)
		return r.handleDeletion()
	}

	// Ensure finalizer and default alert thresholds in a single update
	needsUpdate := false

	if !controllerutil.ContainsFinalizer(r.output, monitorFinalizer) {
		r.log.Info("Adding finalizer to Monitor", "namespace", req.Namespace, "name", req.Name)
		controllerutil.AddFinalizer(r.output, monitorFinalizer)
		needsUpdate = true
	}

	if applyDefaultAlertThresholds(r.output) {
		r.log.Info("Applying default alert thresholds to Monitor", "namespace", req.Namespace, "name", req.Name)
		needsUpdate = true
	}

	if needsUpdate {
		if err := r.Update(r.ctx, r.output); err != nil {
			r.log.Info("Conflict updating Monitor spec, requeueing", "error", err)
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		// Re-fetch after spec update to work with latest version
		r.output = &expiringsecretv1alpha1.Monitor{}
		if err := r.Get(ctx, req.NamespacedName, r.output); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Resolve and load source object
	sourceObj, err := r.getSourceObject()
	if err != nil {
		r.log.Error(err, "Failed to get source Secret", "reference", r.output.Spec.SecretRef)
		return r.handleError(err, "SourceNotAvailable", "Failed to get source Secret")
	}

	validUntil, parseErr := r.parseSourceObject(sourceObj)
	if parseErr != nil {
		r.log.Error(parseErr, "Failed to parse source Secret", "reference", r.output.Spec.SecretRef)
		return r.handleError(parseErr, parseErr.Reason, parseErr.Message)
	}

	// Determine the current state based on thresholds
	calculateState(r.output, validUntil, time.Now())

	// Generate a user-friendly status message
	setStatusMessage(r.output)

	r.output.Status.ObservedGeneration = r.output.Generation
	r.output.Status.LastSourceResourceVersion = sourceObj.GetResourceVersion()

	return r.handleSuccess()
}

func (r *MonitorReconciler) handleSuccess() (ctrl.Result, error) {
	// Update Prometheus metrics now that status is fully populated
	if err := utils.NewMetric(r.output).Update(); err != nil {
		r.log.Error(err, "Failed to update metrics", "monitor", r.output.Name)
		// Don't fail reconciliation on metrics error, just log it
	}

	setCondition(r.output, expiringsecretv1alpha1.MonitorConditionSourceAvailable,
		"True",
		"SourceAvailable",
		"Source Secret is available")
	setCondition(r.output, expiringsecretv1alpha1.MonitorConditionSourceLabelFound,
		"True",
		"SourceLabelFound",
		"Source label has been found")
	setCondition(r.output, expiringsecretv1alpha1.MonitorConditionReady,
		"True",
		"Ready",
		"Monitor is ready")

	return ctrl.Result{
		// Requeue after 1 minute for continuous monitoring
		RequeueAfter: time.Minute,
	}, r.Status().Patch(r.ctx, r.output, client.MergeFrom(r.original))
}

func (r *MonitorReconciler) handleError(err error, reason string, message string) (ctrl.Result, error) {
	detailedMessage := message
	if err != nil {
		detailedMessage = detailedMessage + ": " + err.Error()
	}
	r.output.Status.State = expiringsecretv1alpha1.MonitorStateError
	r.output.Status.Message = detailedMessage // Set the error message in status

	r.log.Info("Handling Monitor error", "reason", reason, "message", detailedMessage)

	// Drop the value gauges, whose expiry is unknown, but keep publishing the
	// state so a failing Monitor stays alertable rather than going silent.
	if err := utils.NewMetric(r.output).WithLogger(r.log).SetError(); err != nil {
		r.log.Error(err, "Failed to publish error state metric", "monitor", r.output.Name)
	}

	// Always set Ready condition to False on error
	setCondition(r.output, expiringsecretv1alpha1.MonitorConditionReady, "False", reason, detailedMessage)

	// Make sure SourceAvailable and ServiceAccountSynced are marked False when we fail
	if reason == "SourceNotAvailable" || reason == "SourceDataInvalid" {
		setCondition(r.output, expiringsecretv1alpha1.MonitorConditionSourceAvailable, "False", reason, detailedMessage)
	}

	// sourceLabelNotAvailable indicates that the expected label is missing,
	// while SourceLabelInvalid indicates that the label value is not in the
	// expected format.
	// Both conditions should be set accordingly based on the error reason.
	if reason == sourceLabelNotAvailable {
		setCondition(r.output, expiringsecretv1alpha1.MonitorConditionSourceLabelFound, "False", reason, detailedMessage)
	}
	if reason == "SourceLabelInvalid" {
		setCondition(r.output, expiringsecretv1alpha1.MonitorConditionSourceLabelValid, "False", reason, detailedMessage)
	}

	return ctrl.Result{}, r.Status().Patch(r.ctx, r.output, client.MergeFrom(r.original))
}

func (r *MonitorReconciler) handleDeletion() (ctrl.Result, error) {
	r.log.Info("Handling Monitor deletion", "name", r.output.Name)

	if !controllerutil.ContainsFinalizer(r.output, monitorFinalizer) {
		return ctrl.Result{}, nil
	}

	utils.NewMetric(r.output).WithLogger(r.log).Cleanup()

	controllerutil.RemoveFinalizer(r.output, monitorFinalizer)
	if err := r.Update(r.ctx, r.output); err != nil {
		return ctrl.Result{}, err
	}

	r.log.Info("Delete complete", "name", r.output.Name)
	return ctrl.Result{}, nil
}

func (r *MonitorReconciler) getSourceObject() (client.Object, error) {
	// Get the referenced secret
	secretNamespace := r.output.Spec.SecretRef.Namespace
	if secretNamespace == "" {
		secretNamespace = r.output.Namespace
	}

	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Name:      r.output.Spec.SecretRef.Name,
		Namespace: secretNamespace,
	}

	err := r.Get(r.ctx, secretKey, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("referenced secret not found")
		}
		return nil, err
	}

	return secret, nil
}

// Parses the expiration timestamp from the secret label
func (r *MonitorReconciler) parseSourceObject(sourceObj client.Object) (time.Time, *MonitorErrorReasonMessage) {
	validUntil := time.Time{}
	labels := sourceObj.GetLabels()
	if labels == nil {
		msg := fmt.Sprintf("Source object does not have any labels, expected %s label", LabelKey)
		r.log.Error(nil, msg, "name", sourceObj.GetName(), "namespace", sourceObj.GetNamespace())
		return validUntil, &MonitorErrorReasonMessage{
			Reason:  sourceLabelNotAvailable,
			Message: msg,
		}
	}
	validUntilStr, exists := labels[LabelKey]
	if !exists {
		msg := fmt.Sprintf("Source object does not have %s label", LabelKey)
		r.log.Error(nil, msg,
			"name", sourceObj.GetName(),
			"namespace", sourceObj.GetNamespace(),
			"availableLabels", labels,
			"expectedLabel", LabelKey,
		)
		return validUntil, &MonitorErrorReasonMessage{
			Reason:  sourceLabelNotAvailable,
			Message: msg,
		}
	}

	validUntil, err := time.Parse("2006-01-02", validUntilStr)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse validUntil date (expected YYYY-MM-DD format): %v", err)
		r.log.Error(err, "Failed to parse validUntil date", "validUntil", validUntilStr)
		return validUntil, &MonitorErrorReasonMessage{
			Reason:  "SourceLabelInvalid",
			Message: msg,
		}
	}

	return validUntil, nil
}

// mapSecretToMonitor maps a Secret to Monitor objects that reference it
func (r *MonitorReconciler) mapSecretToMonitor(ctx context.Context, obj client.Object) []ctrl.Request {
	r.ctx = ctx
	r.log = log.FromContext(ctx)
	secret := obj.(*corev1.Secret)

	// Find all monitors that reference this secret
	monitorList := &expiringsecretv1alpha1.MonitorList{}
	r.log.Info("Mapping Secret to Monitors", "result", monitorList)
	if err := r.List(r.ctx, monitorList); err != nil {
		return nil
	}

	var requests []ctrl.Request
	for _, monitor := range monitorList.Items {
		secretNamespace := monitor.Spec.SecretRef.Namespace
		if secretNamespace == "" {
			r.log.Info(
				"SecretRef namespace is empty, defaulting to Monitor namespace",
				"monitorNamespace", monitor.Namespace)
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

func monitorCreatePredicate(_ event.CreateEvent) bool {
	return true
}

func monitorDeletePredicate(_ event.DeleteEvent) bool {
	return true
}

func monitorUpdatePredicate(e event.UpdateEvent) bool {
	old, ok := e.ObjectOld.(*expiringsecretv1alpha1.Monitor)
	if !ok {
		return false
	}
	new, ok := e.ObjectNew.(*expiringsecretv1alpha1.Monitor)
	if !ok {
		return false
	}
	// Reconcile if spec changed
	if !equality.Semantic.DeepEqual(old.Spec, new.Spec) {
		return true
	}
	// Reconcile if deletion timestamp was added (deletion triggered)
	if old.DeletionTimestamp == nil && new.DeletionTimestamp != nil {
		return true
	}
	return false
}

func secretCreatePredicate(_ event.CreateEvent) bool {
	return true
}

func secretDeletePredicate(_ event.DeleteEvent) bool {
	return true
}

func secretUpdatePredicate(e event.UpdateEvent) bool {
	// Reconcile if secret data changed
	oldSecret, ok := e.ObjectOld.(*corev1.Secret)
	if !ok {
		return false
	}
	newSecret, ok := e.ObjectNew.(*corev1.Secret)
	if !ok {
		return false
	}

	// Check if data changed
	if len(oldSecret.Data) != len(newSecret.Data) {
		return true
	}
	for k, v := range oldSecret.Data {
		if string(newSecret.Data[k]) != string(v) {
			return true
		}
	}
	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *MonitorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&expiringsecretv1alpha1.Monitor{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc: monitorCreatePredicate,
			UpdateFunc: monitorUpdatePredicate,
			DeleteFunc: monitorDeletePredicate,
		})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.mapSecretToMonitor),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc: secretCreatePredicate,
				UpdateFunc: secretUpdatePredicate,
				DeleteFunc: secretDeletePredicate,
			}),
		).
		Named("monitor").
		Complete(r)
}

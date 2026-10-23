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
	"cmp"
	"context"
	"errors"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	"github.com/stakater/expiring-secret-operator/internal/utils"
)

// MonitorReconciler reconciles a Monitor object. It holds no per-request
// state, so Reconcile and the Secret mapper may run concurrently.
type MonitorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// reconcileState carries everything one reconcile needs.
type reconcileState struct {
	ctx     context.Context
	log     logr.Logger
	monitor *expiringsecretv1alpha1.Monitor
	// original holds a deep copy used for status patching
	original *expiringsecretv1alpha1.Monitor
}

func newReconcileState(ctx context.Context, m *expiringsecretv1alpha1.Monitor) *reconcileState {
	return &reconcileState{ctx: ctx, log: log.FromContext(ctx), monitor: m, original: m.DeepCopy()}
}

// legacyFinalizer was added by earlier releases. Nothing adds it any more;
// Reconcile strips it so those Monitors can be deleted.
const legacyFinalizer = "expiring-secrets.stakater.com/monitor-finalizer"

type MonitorErrorReasonMessage struct {
	Reason  string
	Message string
}

func (e *MonitorErrorReasonMessage) Error() string { return e.Message }

// +kubebuilder:rbac:groups=expiring-secrets.stakater.com,resources=monitors,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=expiring-secrets.stakater.com,resources=monitors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *MonitorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log.FromContext(ctx).Info("Reconciling Monitor", "namespace", req.Namespace, "name", req.Name)

	monitor := &expiringsecretv1alpha1.Monitor{}
	if err := r.Get(ctx, req.NamespacedName, monitor); err != nil {
		if apierrors.IsNotFound(err) {
			utils.CleanupMonitor(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	return r.reconcileMonitor(newReconcileState(ctx, monitor))
}

func (r *MonitorReconciler) reconcileMonitor(s *reconcileState) (ctrl.Result, error) {
	if stripped, err := r.stripLegacyFinalizer(s); err != nil {
		return ctrl.Result{}, err
	} else if stripped {
		// The Update moved the object on; patch status against its new state.
		s.original = s.monitor.DeepCopy()
	}
	if s.monitor.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	s.monitor.Status.ObservedGeneration = s.monitor.Generation
	return r.observeSource(s)
}

// stripLegacyFinalizer removes the finalizer earlier releases added and
// reports whether it did.
func (r *MonitorReconciler) stripLegacyFinalizer(s *reconcileState) (bool, error) {
	if !controllerutil.RemoveFinalizer(s.monitor, legacyFinalizer) {
		return false, nil
	}
	s.log.Info("Removing legacy finalizer from Monitor")
	return true, r.Update(s.ctx, s.monitor)
}

// observeSource reads the source Secret and records its expiry in the status.
func (r *MonitorReconciler) observeSource(s *reconcileState) (ctrl.Result, error) {
	sourceObj, err := r.getSourceObject(s)
	if err != nil {
		s.log.Error(err, "Failed to get source Secret", "reference", s.monitor.Spec.SecretRef)
		return r.handleSourceError(s, err)
	}

	validUntil, parseErr := parseValidUntil(s.log, sourceObj)
	if parseErr != nil {
		s.log.Error(parseErr, "Failed to parse source Secret", "reference", s.monitor.Spec.SecretRef)
		return r.handleError(s, parseErr, parseErr.Reason, parseErr.Message)
	}

	calculateState(s.monitor, validUntil, time.Now())
	setStatusMessage(s.monitor)
	return r.handleSuccess(s)
}

func (r *MonitorReconciler) handleSuccess(s *reconcileState) (ctrl.Result, error) {
	// Update Prometheus metrics now that status is fully populated
	if err := utils.NewMetric(s.monitor).Update(); err != nil {
		s.log.Error(err, "Failed to update metrics", "monitor", s.monitor.Name)
		// Don't fail reconciliation on metrics error, just log it
	}

	applyConditions(s.monitor, ReasonReady, "Monitor is ready")

	return ctrl.Result{
		// Requeue after 1 minute for continuous monitoring
		RequeueAfter: time.Minute,
	}, r.Status().Patch(s.ctx, s.monitor, client.MergeFrom(s.original))
}

// handleSourceError reports a failed Secret lookup: a missing Secret is a
// user error, anything else an API error.
func (r *MonitorReconciler) handleSourceError(s *reconcileState, err error) (ctrl.Result, error) {
	reason := ReasonAPIError
	if errors.Is(err, errSecretNotFound) {
		reason = ReasonSourceNotAvailable
	}
	return r.handleError(s, err, reason, "Failed to get source Secret")
}

// handleError records the failure in status. User errors are re-checked
// after a minute; an API error is returned so the controller backs off.
func (r *MonitorReconciler) handleError(s *reconcileState, cause error, reason, message string) (ctrl.Result, error) {
	if cause != nil {
		message = message + ": " + cause.Error()
	}
	s.monitor.Status.State = expiringsecretv1alpha1.MonitorStateError
	s.monitor.Status.Message = message
	s.log.Info("Handling Monitor error", "reason", reason, "message", message)

	// Drop the value gauges, whose expiry is unknown, but keep publishing the
	// state so a failing Monitor stays alertable rather than going silent.
	if err := utils.NewMetric(s.monitor).WithLogger(s.log).SetError(); err != nil {
		s.log.Error(err, "Failed to publish error state metric", "monitor", s.monitor.Name)
	}
	applyConditions(s.monitor, reason, message)

	patchErr := r.Status().Patch(s.ctx, s.monitor, client.MergeFrom(s.original))
	if reason == ReasonAPIError { // never (Result{}, nil): that would drop the retry
		return ctrl.Result{}, errors.Join(cmp.Or(cause, errors.New(message)), patchErr)
	}
	return ctrl.Result{RequeueAfter: time.Minute}, patchErr
}

// SetupWithManager sets up the controller with the Manager.
func (r *MonitorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := indexMonitors(mgr); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&expiringsecretv1alpha1.Monitor{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc: monitorCreatePredicate, UpdateFunc: monitorUpdatePredicate, DeleteFunc: monitorDeletePredicate,
		})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.mapSecretToMonitor),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc: secretCreatePredicate, UpdateFunc: secretUpdatePredicate, DeleteFunc: secretDeletePredicate,
			}),
			builder.OnlyMetadata,
		).
		WithOptions(controller.Options{RateLimiter: newRateLimiter()}).
		Named("monitor").
		Complete(r)
}

// indexMonitors registers the secretRefNameIndex that mapSecretToMonitor uses.
func indexMonitors(mgr ctrl.Manager) error {
	return mgr.GetFieldIndexer().IndexField(context.Background(),
		&expiringsecretv1alpha1.Monitor{}, secretRefNameIndex, indexMonitorBySecretName)
}

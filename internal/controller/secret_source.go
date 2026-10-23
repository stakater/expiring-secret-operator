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
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
)

// LabelKey is the Secret label holding the expiry date (YYYY-MM-DD).
const LabelKey = "expiring-secrets.stakater.com/validUntil"

func (r *MonitorReconciler) getSourceObject(s *reconcileState) (client.Object, error) {
	// Get the referenced secret
	secretNamespace := s.monitor.Spec.SecretRef.Namespace
	if secretNamespace == "" {
		secretNamespace = s.monitor.Namespace
	}

	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Name:      s.monitor.Spec.SecretRef.Name,
		Namespace: secretNamespace,
	}

	err := r.Get(s.ctx, secretKey, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("referenced secret not found")
		}
		return nil, err
	}

	return secret, nil
}

// parseValidUntil parses the expiration timestamp from the secret label
func parseValidUntil(log logr.Logger, sourceObj client.Object) (time.Time, *MonitorErrorReasonMessage) {
	validUntil := time.Time{}
	labels := sourceObj.GetLabels()
	if labels == nil {
		msg := fmt.Sprintf("Source object does not have any labels, expected %s label", LabelKey)
		log.Error(nil, msg, "name", sourceObj.GetName(), "namespace", sourceObj.GetNamespace())
		return validUntil, &MonitorErrorReasonMessage{
			Reason:  sourceLabelNotAvailable,
			Message: msg,
		}
	}
	validUntilStr, exists := labels[LabelKey]
	if !exists {
		msg := fmt.Sprintf("Source object does not have %s label", LabelKey)
		log.Error(nil, msg,
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
		log.Error(err, "Failed to parse validUntil date", "validUntil", validUntilStr)
		return validUntil, &MonitorErrorReasonMessage{
			Reason:  "SourceLabelInvalid",
			Message: msg,
		}
	}

	return validUntil, nil
}

// mapSecretToMonitor maps a Secret to Monitor objects that reference it
func (r *MonitorReconciler) mapSecretToMonitor(ctx context.Context, obj client.Object) []ctrl.Request {
	logger := log.FromContext(ctx)
	secret := obj.(*corev1.Secret)

	// Find all monitors that reference this secret
	monitorList := &expiringsecretv1alpha1.MonitorList{}
	logger.Info("Mapping Secret to Monitors", "result", monitorList)
	if err := r.List(ctx, monitorList); err != nil {
		return nil
	}

	var requests []ctrl.Request
	for _, monitor := range monitorList.Items {
		secretNamespace := monitor.Spec.SecretRef.Namespace
		if secretNamespace == "" {
			logger.Info(
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

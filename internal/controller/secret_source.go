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
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
)

// LabelKey is the Secret label holding the expiry date (YYYY-MM-DD).
const LabelKey = "expiring-secrets.stakater.com/validUntil"

// errSecretNotFound reports that the referenced Secret does not exist.
var errSecretNotFound = errors.New("referenced secret not found")

// getSourceObject reads only the metadata of the referenced Secret, never its payload.
func (r *MonitorReconciler) getSourceObject(s *reconcileState) (*metav1.PartialObjectMetadata, error) {
	// A Monitor may only watch a Secret in its own namespace.
	secret := &metav1.PartialObjectMetadata{}
	secret.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
	secretKey := types.NamespacedName{
		Name:      s.monitor.Spec.SecretRef.Name,
		Namespace: s.monitor.Namespace,
	}

	if err := r.Get(s.ctx, secretKey, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, errSecretNotFound
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
			Reason:  ReasonSourceLabelNotFound,
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
			Reason:  ReasonSourceLabelNotFound,
			Message: msg,
		}
	}

	validUntil, err := time.Parse("2006-01-02", validUntilStr)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse validUntil date (expected YYYY-MM-DD format): %v", err)
		log.Error(err, "Failed to parse validUntil date", "validUntil", validUntilStr)
		return validUntil, &MonitorErrorReasonMessage{
			Reason:  ReasonSourceLabelInvalid,
			Message: msg,
		}
	}

	return validUntil, nil
}

// secretRefNameIndex indexes Monitors by the name of the Secret they reference.
const secretRefNameIndex = "spec.secretRef.name"

// indexMonitorBySecretName extracts the secretRefNameIndex value of a Monitor.
func indexMonitorBySecretName(o client.Object) []string {
	monitor, ok := o.(*expiringsecretv1alpha1.Monitor)
	if !ok || monitor.Spec.SecretRef == nil {
		return nil
	}
	return []string{monitor.Spec.SecretRef.Name}
}

// mapSecretToMonitor maps a Secret to the Monitors in its namespace that reference it.
func (r *MonitorReconciler) mapSecretToMonitor(ctx context.Context, obj client.Object) []ctrl.Request {
	monitorList := &expiringsecretv1alpha1.MonitorList{}
	err := r.List(ctx, monitorList,
		client.InNamespace(obj.GetNamespace()),
		client.MatchingFields{secretRefNameIndex: obj.GetName()})
	if err != nil {
		log.FromContext(ctx).Error(err, "Failed to list Monitors for Secret", "secret", client.ObjectKeyFromObject(obj))
		return nil
	}

	requests := make([]ctrl.Request, 0, len(monitorList.Items))
	for _, monitor := range monitorList.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&monitor)})
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

// secretUpdatePredicate fires when the validUntil label changes.
func secretUpdatePredicate(e event.UpdateEvent) bool {
	return e.ObjectOld.GetLabels()[LabelKey] != e.ObjectNew.GetLabels()[LabelKey]
}

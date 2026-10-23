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
	"fmt"
	"time"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
)

// Condition reasons a Monitor reports.
const (
	ReasonReady               = "Ready"
	ReasonSourceNotAvailable  = "SourceNotAvailable"
	ReasonSourceLabelNotFound = "SourceLabelNotFound"
	ReasonSourceLabelInvalid  = "SourceLabelInvalid"
	ReasonAPIError            = "APIError"
)

const (
	secretIsValid   = "Secret is valid until %s"
	secretExpiresIn = "Secret expires in less than %d days"
	secretExpiredOn = "Secret expired on %s"
)

// setCondition sets or updates one status condition on m.
func setCondition(m *expiringsecretv1alpha1.Monitor, t expiringsecretv1alpha1.MonitorConditionType, status metav1.ConditionStatus, reason, message string) {
	apimeta.SetStatusCondition(&m.Status.Conditions, metav1.Condition{
		Type:               string(t),
		Status:             status,
		ObservedGeneration: m.Generation,
		Reason:             reason,
		Message:            message,
	})
}

// conditionSet holds the status of each condition a Monitor reports.
type conditionSet struct {
	Ready, SourceAvailable, SourceLabelFound, SourceLabelValid metav1.ConditionStatus
}

// conditionsFor maps a reason to the four condition statuses. A check that
// never ran because an earlier one failed is Unknown.
func conditionsFor(reason string) conditionSet {
	const t, f, u = metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionUnknown
	switch reason {
	case ReasonReady:
		return conditionSet{t, t, t, t}
	case ReasonSourceNotAvailable:
		return conditionSet{f, f, u, u}
	case ReasonSourceLabelNotFound:
		return conditionSet{f, t, f, u}
	case ReasonSourceLabelInvalid:
		return conditionSet{f, t, t, f}
	default:
		return conditionSet{f, u, u, u}
	}
}

// applyConditions writes all four conditions for reason. A True condition
// carries its own type as reason and a fixed message.
func applyConditions(m *expiringsecretv1alpha1.Monitor, reason, message string) {
	set := conditionsFor(reason)
	for _, c := range []struct {
		t       expiringsecretv1alpha1.MonitorConditionType
		status  metav1.ConditionStatus
		trueMsg string
	}{
		{expiringsecretv1alpha1.MonitorConditionReady, set.Ready, "Monitor is ready"},
		{expiringsecretv1alpha1.MonitorConditionSourceAvailable, set.SourceAvailable, "Source Secret is available"},
		{expiringsecretv1alpha1.MonitorConditionSourceLabelFound, set.SourceLabelFound, "Source label has been found"},
		{expiringsecretv1alpha1.MonitorConditionSourceLabelValid, set.SourceLabelValid, "Source label is valid"},
	} {
		if c.status == metav1.ConditionTrue {
			setCondition(m, c.t, c.status, string(c.t), c.trueMsg)
		} else {
			setCondition(m, c.t, c.status, reason, message)
		}
	}
}

// calculateState determines the current state based on alert thresholds
func calculateState(m *expiringsecretv1alpha1.Monitor, validUntil, now time.Time) {
	// Update the Monitor status
	lastchecked := metav1.NewTime(now)
	secondsRemaining := validUntil.Sub(now).Seconds()
	expiresAt := metav1.NewTime(validUntil)
	secondsRemainingInt := int64(secondsRemaining)

	// Update status fields
	m.Status.LastChecked = &lastchecked
	m.Status.ExpiresAt = &expiresAt
	m.Status.SecondsRemaining = &secondsRemainingInt

	if secondsRemaining <= 0 {
		m.Status.State = expiringsecretv1alpha1.MonitorStateExpired
		return
	}

	m.Status.State = expiringsecretv1alpha1.MonitorStateValid

	daysRemaining := secondsRemaining / (24 * 60 * 60)

	if daysRemaining <= float64(m.Spec.AlertThresholds.CriticalDays) {
		m.Status.State = expiringsecretv1alpha1.MonitorStateCritical
	} else if daysRemaining <= float64(m.Spec.AlertThresholds.WarningDays) {
		m.Status.State = expiringsecretv1alpha1.MonitorStateWarning
	} else if daysRemaining <= float64(m.Spec.AlertThresholds.InfoDays) {
		m.Status.State = expiringsecretv1alpha1.MonitorStateInfo
	}
}

// setStatusMessage creates a user-friendly message based on the current
// state and thresholds
func setStatusMessage(m *expiringsecretv1alpha1.Monitor) {
	if m.Status.ExpiresAt == nil {
		m.Status.Message = "Expiration date is not available"
		return
	}
	if m.Status.SecondsRemaining == nil {
		m.Status.Message = "Seconds until expiration is not available"
		return
	}
	message := ""
	switch m.Status.State {
	case expiringsecretv1alpha1.MonitorStateValid:
		message = fmt.Sprintf(secretIsValid,
			m.Status.ExpiresAt.Format("2006-01-02"))
	case expiringsecretv1alpha1.MonitorStateInfo:
		message = fmt.Sprintf(secretExpiresIn,
			m.Spec.AlertThresholds.InfoDays)
	case expiringsecretv1alpha1.MonitorStateWarning:
		message = fmt.Sprintf(secretExpiresIn,
			m.Spec.AlertThresholds.WarningDays)
	case expiringsecretv1alpha1.MonitorStateCritical:
		message = fmt.Sprintf(secretExpiresIn,
			m.Spec.AlertThresholds.CriticalDays)
	case expiringsecretv1alpha1.MonitorStateExpired:
		message = fmt.Sprintf(secretExpiredOn,
			m.Status.ExpiresAt.Format("2006-01-02"))
	case expiringsecretv1alpha1.MonitorStateError:
		message = "Error monitoring secret"
	default:
		message = fmt.Sprintf("Unknown state: %s", m.Status.State)
	}

	m.Status.Message = message
}

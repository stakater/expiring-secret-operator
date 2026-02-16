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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json:"-" or json:"foo" tags for the field to be exposed.

type MonitorState string

const (
	// Secret is valid and not close to expiration
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	MonitorStateValid MonitorState = "Valid"
	// Secret is valid but approaching expiration (e.g., between 30 and 14 days)
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	MonitorStateInfo MonitorState = "Info"
	// Secret is valid but close to expiration (e.g., between 14 and 7 days)
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	MonitorStateWarning MonitorState = "Warning"
	// Secret is valid but very close to expiration (e.g., less than 7 days)
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	MonitorStateCritical MonitorState = "Critical"
	// Secret has expired
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	MonitorStateExpired MonitorState = "Expired"
	// An error occurred while checking the secret (e.g., non-existent secret, API error)
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	MonitorStateError MonitorState = "Error"
	// Something totally unknown happened (should be used very rarely, if at all)
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	MonitorStateUnknown MonitorState = "Unknown"
)

// MonitorConditionType represents the condition type for Monitor.
type MonitorConditionType string

const (
	// MonitorConditionReady indicates that the output is ready.
	MonitorConditionReady MonitorConditionType = "Ready"
	// MonitorConditionSourceAvailable indicates that the source Secret is available.
	MonitorConditionSourceAvailable MonitorConditionType = "SourceAvailable"
	// MonitorConditionSourceLabel indicates that the source label has been found.
	MonitorConditionSourceLabelFound MonitorConditionType = "SourceLabelFound"
	// MonitorConditionSourceLabelValid indicates that the source label is valid.
	MonitorConditionSourceLabelValid MonitorConditionType = "SourceLabelValid"
)

// Monitor CR spec field.
type MonitorSpec struct {
	// Service that generated the secret content originally (e.g., docker.io, quay.io)
	// +kubebuilder:validation:Required
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Service that generated the secret content",xDescriptors="urn:alm:descriptor:com.tectonic.ui:text"
	Service string `json:"service"`

	// +kubebuilder:validation:Required
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Secret Reference",xDescriptors={"urn:alm:descriptor:io.kubernetes:Secret"}
	SecretRef *SecretReference `json:"secretRef"`

	// AlertThresholds defines when to trigger different alert levels
	// +optional
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Alert Thresholds",xDescriptors="urn:alm:descriptor:com.tectonic.ui:advanced"
	AlertThresholds *AlertThresholds `json:"alertThresholds,omitempty"`
}

// Reference to a Secret to monitor.
// It should contain a label with the expiration timestamp in "YYYY-MM-DD" format, e.g.:
//
//	expiringsecret.stakater.com/validUntil: "2025-12-31"
type SecretReference struct {
	// Name is the name of the secret
	// +kubebuilder:validation:Required
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Name of the secret to monitor",xDescriptors="urn:alm:descriptor:io.kubernetes:Secret"
	Name string `json:"name"`

	// Namespace is the namespace of the secret
	// If empty, defaults to the same namespace as the Monitor
	// +optional
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Namespace of the secret to monitor",xDescriptors="urn:alm:descriptor:io.kubernetes:Namespace"
	Namespace string `json:"namespace,omitempty"`
}

// Define the thresholds for different alert levels
// +optional
type AlertThresholds struct {
	// InfoDays is the number of days before expiration to trigger info alerts
	// +kubebuilder:validation:Minimum=1
	// +optional
	// +default=30
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Info alert threshold (days before expiration)",xDescriptors="urn:alm:descriptor:com.tectonic.ui:number"
	InfoDays int32 `json:"infoDays,omitempty"`

	// WarningDays is the number of days before expiration to trigger warning alerts
	// +kubebuilder:validation:Minimum=1
	// +optional
	// +default=14
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Warning alert threshold (days before expiration)",xDescriptors="urn:alm:descriptor:com.tectonic.ui:number"
	WarningDays int32 `json:"warningDays,omitempty"`

	// CriticalDays is the number of days before expiration to trigger critical alerts
	// +kubebuilder:validation:Minimum=1
	// +optional
	// +default=7
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Critical alert threshold (days before expiration)",xDescriptors="urn:alm:descriptor:com.tectonic.ui:number"
	CriticalDays int32 `json:"criticalDays,omitempty"`
}

// Monitor CR status field.
type MonitorStatus struct {
	// ExpiresAt is the expiration timestamp of the monitored secret
	// +kubebuilder:validation:Optional
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Expiration timestamp",xDescriptors="urn:alm:descriptor:com.tectonic.ui:text"
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// SecondsRemaining is the number of seconds until expiration
	// +kubebuilder:validation:Optional
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Seconds until expiration",xDescriptors="urn:alm:descriptor:com.tectonic.ui:number"
	SecondsRemaining *int64 `json:"secondsRemaining,omitempty"`

	// LastChecked is the timestamp when the secret was last checked
	// +kubebuilder:validation:Optional
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Last check timestamp",xDescriptors="urn:alm:descriptor:com.tectonic.ui:text"
	LastChecked *metav1.Time `json:"lastChecked,omitempty"`

	// State represents the current state of the monitor
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=Valid;Info;Warning;Critical;Expired;Error
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Current state",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:select:Valid","urn:alm:descriptor:com.tectonic.ui:select:Info","urn:alm:descriptor:com.tectonic.ui:select:Warning","urn:alm:descriptor:com.tectonic.ui:select:Critical","urn:alm:descriptor:com.tectonic.ui:select:Expired","urn:alm:descriptor:com.tectonic.ui:select:Error"}
	State MonitorState `json:"state,omitempty"`

	// Message provides additional information about the current state
	// +kubebuilder:validation:Optional
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Status message",xDescriptors="urn:alm:descriptor:com.tectonic.ui:text"
	Message string `json:"message,omitempty"`

	// Conditions represent the latest available observations of the monitor's state
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// ObservedGeneration reflects the generation of the most recently observed monitor.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastSourceResourceVersion stores the last observed resourceVersion of the source Secret.
	// +optional
	LastSourceResourceVersion string `json:"lastSourceResourceVersion,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mon
// +kubebuilder:printcolumn:name="Service",type="string",JSONPath=".spec.service"
// +kubebuilder:printcolumn:name="Secret",type="string",JSONPath=".spec.secretRef.name"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Expires At",type="date",JSONPath=".status.expiresAt"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +operator-sdk:csv:customresourcedefinitions:displayName="Expiring Secrets Monitor"
// This annotation provides a hint for OLM which resources are managed by Monitor kind.
// It's not mandatory to list all resources.
// +operator-sdk:csv:customresourcedefinitions:resources={{Pod,v1,""},{Deployment,apps/v1,""},{ServiceAccount,v1,""},{Service,v1,""},{Secret,v1,""}}

// Monitor is the Schema for the monitors API
type Monitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MonitorSpec   `json:"spec,omitempty"`
	Status MonitorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MonitorList contains a list of Monitor
type MonitorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Monitor `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Monitor{}, &MonitorList{})
}

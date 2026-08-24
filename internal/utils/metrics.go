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

package utils

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
)

// Prometheus metrics
const (
	PrometheusNamespace = "expiringsecrets"
	PrometheusSubsystem = "monitor"

	ValidUntilMetricHelp = "Secret expiration timestamp"
	ValidUntilMetricName = "valid_until_timestamp_seconds"

	UntilExpiryMetricHelp = "Seconds until secret expires"
	UntilExpiryMetricName = "until_expiration_seconds"

	StateMetricHelp = "Current state of the Monitor, always 1 for the active state"
	StateMetricName = "state"

	LabelMonitorName      = "monitor_name"
	LabelMonitorNamespace = "monitor_namespace"
	LabelState            = "state"
	LabelSecretService    = "secret_service"
	LabelSecretName       = "secret_name"
	LabelSecretNamespace  = "secret_namespace"
)

var (
	// valueLabels identify a Monitor and describe the Secret it watches.
	// state is deliberately absent: it changes over a Monitor's lifetime,
	// and a changing label value orphans the series recorded under the
	// previous value.
	valueLabels = []string{
		LabelMonitorName,
		LabelMonitorNamespace,
		LabelSecretService,
		LabelSecretName,
		LabelSecretNamespace,
	}

	// stateLabels carry the same identity plus the state itself.
	stateLabels = append(append([]string{}, valueLabels...), LabelState)

	SecretValidUntilTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusSubsystem,
			Name:      ValidUntilMetricName,
			Help:      ValidUntilMetricHelp,
		},
		valueLabels,
	)

	SecretSecondsUntilExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusSubsystem,
			Name:      UntilExpiryMetricName,
			Help:      UntilExpiryMetricHelp,
		},
		valueLabels,
	)

	MonitorStateGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusSubsystem,
			Name:      StateMetricName,
			Help:      StateMetricHelp,
		},
		stateLabels,
	)
)

func init() {
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(
		SecretValidUntilTimestamp,
		SecretSecondsUntilExpiry,
		MonitorStateGauge,
	)
}

type Metric struct {
	monitor *expiringsecretv1alpha1.Monitor
	logger  logr.Logger
}

func NewMetric(monitor *expiringsecretv1alpha1.Monitor) *Metric {
	return &Metric{
		monitor: monitor,
		logger:  logr.Discard(),
	}
}

func (m *Metric) WithLogger(logger logr.Logger) *Metric {
	m.logger = logger
	return m
}

// Labels returns the label set shared by the two value gauges. It carries no
// state label; see StateLabels.
func (m *Metric) Labels() prometheus.Labels {
	if m == nil || m.monitor == nil {
		return prometheus.Labels{}
	}

	secretName := ""
	secretNamespace := ""
	if m.monitor.Spec.SecretRef != nil {
		secretName = m.monitor.Spec.SecretRef.Name
		secretNamespace = m.monitor.Spec.SecretRef.Namespace
	}
	// An empty secretRef namespace means the Monitor's own namespace, which
	// is the same defaulting the reconciler applies when resolving it.
	if secretNamespace == "" {
		secretNamespace = m.monitor.Namespace
	}

	return prometheus.Labels{
		LabelMonitorName:      m.monitor.Name,
		LabelMonitorNamespace: m.monitor.Namespace,
		LabelSecretName:       secretName,
		LabelSecretNamespace:  secretNamespace,
		LabelSecretService:    m.monitor.Spec.Service,
	}
}

// StateLabels returns the label set for the state gauge.
func (m *Metric) StateLabels() prometheus.Labels {
	labels := m.Labels()
	if m == nil || m.monitor == nil {
		return labels
	}
	labels[LabelState] = string(m.monitor.Status.State)
	return labels
}

// identityLabels scope a deletion to one Monitor, whatever its descriptive
// labels currently say. Deleting by full label match is what allows orphans:
// once a value has changed, the exact-match delete looks for the wrong
// series and silently misses.
func (m *Metric) identityLabels() prometheus.Labels {
	if m == nil || m.monitor == nil {
		return prometheus.Labels{}
	}
	return prometheus.Labels{
		LabelMonitorName:      m.monitor.Name,
		LabelMonitorNamespace: m.monitor.Namespace,
	}
}

func (m *Metric) LabelValues() string {
	metricLabels := m.Labels()
	labelsString := make([]string, 0, len(metricLabels))
	for k, v := range metricLabels {
		labelsString = append(labelsString, fmt.Sprintf(`%s="%s"`, k, v))
	}
	slices.Sort(labelsString)
	return strings.Join(labelsString, ",")
}

// reset drops every series belonging to this Monitor and reports how many
// were removed.
func (m *Metric) reset() int {
	identity := m.identityLabels()
	if len(identity) == 0 {
		return 0
	}
	deleted := SecretValidUntilTimestamp.DeletePartialMatch(identity)
	deleted += SecretSecondsUntilExpiry.DeletePartialMatch(identity)
	deleted += MonitorStateGauge.DeletePartialMatch(identity)
	return deleted
}

func (m *Metric) Update() error {
	if m == nil || m.monitor == nil {
		return fmt.Errorf("monitor is nil")
	}
	if m.monitor.Status.ExpiresAt == nil {
		return fmt.Errorf("status field ExpiresAt is nil")
	}
	if m.monitor.Status.SecondsRemaining == nil {
		return fmt.Errorf("status field SecondsRemaining is nil")
	}
	if m.monitor.Status.State == "" {
		return fmt.Errorf("status field State is empty")
	}

	// Clear first, so a changed state, service or secretRef cannot leave a
	// stale series behind at its last written value.
	m.reset()

	labels := m.Labels()

	validUntilGauge, err := SecretValidUntilTimestamp.GetMetricWith(labels)
	if err != nil {
		return err
	}
	validUntilGauge.Set(float64(m.monitor.Status.ExpiresAt.Unix()))

	secondsUntilGauge, err := SecretSecondsUntilExpiry.GetMetricWith(labels)
	if err != nil {
		return err
	}
	secondsUntilGauge.Set(float64(*m.monitor.Status.SecondsRemaining))

	stateGauge, err := MonitorStateGauge.GetMetricWith(m.StateLabels())
	if err != nil {
		return err
	}
	stateGauge.Set(1)

	return nil
}

// SetError drops the value gauges, whose expiry is genuinely unknown while
// the Monitor is failing, and publishes the state series so that the failure
// itself stays alertable. Deleting everything would make the most
// alert-worthy condition the one that goes silent.
func (m *Metric) SetError() error {
	if m == nil || m.monitor == nil {
		return fmt.Errorf("monitor is nil")
	}

	m.reset()

	labels := m.StateLabels()
	if labels[LabelState] == "" {
		labels[LabelState] = string(expiringsecretv1alpha1.MonitorStateError)
	}

	stateGauge, err := MonitorStateGauge.GetMetricWith(labels)
	if err != nil {
		return err
	}
	stateGauge.Set(1)

	m.logger.Info("Published error state metric", "labels", labels)
	return nil
}

func (m *Metric) Cleanup() {
	if m == nil || m.monitor == nil {
		return
	}
	deleted := m.reset()
	m.logger.Info("Deleted metrics for Monitor",
		"seriesDeleted", deleted, "labels", m.identityLabels())
}

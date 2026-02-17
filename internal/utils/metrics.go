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

	LabelMonitorName      = "monitor_name"
	LabelMonitorNamespace = "monitor_namespace"
	LabelState            = "state"
	LabelSecretService    = "secret_service"
	LabelSecretName       = "secret_name"
	LabelSecretNamespace  = "secret_namespace"
)

var (
	labels = []string{
		LabelMonitorName,
		LabelMonitorNamespace,
		LabelState,
		LabelSecretService,
		LabelSecretName,
		LabelSecretNamespace,
	}

	SecretValidUntilTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusSubsystem,
			Name:      ValidUntilMetricName,
			Help:      ValidUntilMetricHelp,
		},
		labels,
	)

	SecretSecondsUntilExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: PrometheusSubsystem,
			Name:      UntilExpiryMetricName,
			Help:      UntilExpiryMetricHelp,
		},
		labels,
	)
)

func init() {
	// Register custom metrics with the global prometheus registry
	metrics.Registry.MustRegister(SecretValidUntilTimestamp, SecretSecondsUntilExpiry)
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

func (m *Metric) Labels() prometheus.Labels {
	if m == nil || m.monitor == nil {
		return prometheus.Labels{}
	}

	// Determine the actual secret namespace (defaulting logic)
	secretNamespace := m.monitor.Spec.SecretRef.Namespace
	if secretNamespace == "" {
		secretNamespace = m.monitor.Namespace
	}

	metricLabels := prometheus.Labels{
		LabelMonitorName:      m.monitor.Name,
		LabelMonitorNamespace: m.monitor.Namespace,
		LabelState:            "",
		LabelSecretService:    "",
		LabelSecretName:       "",
		LabelSecretNamespace:  "",
	}

	if m.monitor.Spec.SecretRef.Name != "" {
		metricLabels[LabelSecretName] = m.monitor.Spec.SecretRef.Name
	}
	if secretNamespace != "" {
		metricLabels[LabelSecretNamespace] = secretNamespace
	}
	if m.monitor.Spec.Service != "" {
		metricLabels[LabelSecretService] = m.monitor.Spec.Service
	}
	if m.monitor.Status.State != "" {
		metricLabels[LabelState] = string(m.monitor.Status.State)
	}

	return metricLabels
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

func (m *Metric) Update() error {
	if m == nil || m.monitor == nil {
		return fmt.Errorf("monitor is nil")
	}

	metricLabels := m.Labels()

	// Guard against nil status fields
	if m.monitor.Status.ExpiresAt == nil {
		return fmt.Errorf("status field ExpiresAt is nil")
	}
	if m.monitor.Status.SecondsRemaining == nil {
		return fmt.Errorf("status field SecondsRemaining is nil")
	}

	validUntilGauge, err := SecretValidUntilTimestamp.GetMetricWith(metricLabels)
	if err != nil {
		return err
	}
	validUntilGauge.Set(float64(m.monitor.Status.ExpiresAt.Unix()))

	secondsUntilGauge, err := SecretSecondsUntilExpiry.GetMetricWith(metricLabels)
	if err != nil {
		return err
	}
	secondsUntilGauge.Set(float64(*m.monitor.Status.SecondsRemaining))
	return nil
}

func (m *Metric) Cleanup() {
	if m == nil || m.monitor == nil {
		return
	}

	metricLabels := m.Labels()

	successSecretValidUntilTimestamp := SecretValidUntilTimestamp.Delete(metricLabels)
	if successSecretValidUntilTimestamp {
		m.logger.Info("Deleted metrics for Monitor, ValidUntilTimestamp", "labels", metricLabels)
	} else {
		noSecretValidUntilTimestamp := SecretValidUntilTimestamp.DeletePartialMatch(metricLabels)
		m.logger.Info("(Partial Match) Deleted metrics for Monitor, ValidUntilTimestamp", "noOfMetricsDeleted", noSecretValidUntilTimestamp, "labels", metricLabels)
	}

	successSecretSecondsUntilExpiry := SecretSecondsUntilExpiry.Delete(metricLabels)
	if successSecretSecondsUntilExpiry {
		m.logger.Info("Deleted metrics for Monitor, SecondsUntilExpiry", "labels", metricLabels)
	} else {
		noSecretSecondsUntilExpiry := SecretSecondsUntilExpiry.DeletePartialMatch(metricLabels)
		m.logger.Info("(Partial Match) Deleted metrics for Monitor, SecondsUntilExpiry", "noOfMetricsDeleted", noSecretSecondsUntilExpiry, "labels", metricLabels)
	}
}

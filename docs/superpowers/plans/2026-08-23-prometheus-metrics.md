# Prometheus Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Prometheus successfully scrape, store, and alert on the operator's secret-expiry metrics, in both Kind and OpenShift user-workload monitoring.

**Architecture:** The metric contract splits into two identity-labelled value gauges plus a separate state info-gauge, with every write performing an identity-scoped `DeletePartialMatch` so no label change can orphan a series. Prometheus authenticates using a shipped `metrics-reader` ServiceAccount token referenced from the ServiceMonitor via `authorization`, which works under both Kind and UWM. Alert rules become state-driven so the CRD's per-Monitor thresholds actually govern alerting.

**Tech Stack:** Go, controller-runtime, prometheus/client_golang, Ginkgo/Gomega, envtest, kustomize, Prometheus Operator v0.72.0, promtool, Kind.

**Spec:** `docs/superpowers/specs/2026-08-23-prometheus-metrics-design.md`

## Global Constraints

- Metric namespace/subsystem is `expiringsecrets` / `monitor`. Full names:
  `expiringsecrets_monitor_valid_until_timestamp_seconds`,
  `expiringsecrets_monitor_until_expiration_seconds`,
  `expiringsecrets_monitor_state`. The old rules used the singular
  `expiringsecret_` prefix and matched nothing; never reintroduce it.
- Identity labels: `monitor_name`, `monitor_namespace`. Descriptive labels:
  `secret_name`, `secret_namespace`, `secret_service`. The `state` label
  appears on `expiringsecrets_monitor_state` only.
- The state gauge only ever holds the value `1`, and only for the Monitor's
  current state. Do not emit `0` series for inactive states.
- `bearerTokenFile` is forbidden in the ServiceMonitor. OpenShift UWM sets
  `arbitraryFSAccessThroughSMs: deny`, which rejects it. Use
  `authorization.credentials` with a Secret reference.
- Licence header: every new `.go` file starts with the Apache 2.0 header
  copied verbatim from `internal/utils/metrics.go`. The pre-commit hook
  checks this.
- Coverage thresholds live in `.github/.testcoverage-local.yml`: 70% per
  file, 80% per package. Verify with `make check-coverage`.
- The pre-commit hook currently fails on 6 pre-existing `goconst` findings
  in `internal/controller/monitor_controller_test.go`. Task 0 clears them so
  every later task can commit normally.

---

### Task 0: Unblock commits by clearing pre-existing lint debt

The pre-commit hook runs `golangci-lint`, which fails on 6 `goconst`
findings in existing test code. Until this is fixed no task in this plan can
commit without `--no-verify`. This task touches only test constants and
changes no behaviour.

**Files:**
- Modify: `internal/controller/monitor_controller_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: test-file constants `MonitorNamespace`, `Service`,
  `TokenKey`, `MonitorKind`, `TargetSecretName` (exact names below), reused
  by later tasks' test code.

- [ ] **Step 1: See the current failures**

Run: `make lint`

Expected: 6 `goconst` issues. If instead you see
`cannot execute binary file: Exec format error`, the cached
`bin/golangci-lint` is built for the wrong architecture. `bin/*` is
gitignored, so remove it and let the target refetch:

```bash
rm -f bin/golangci-lint && make lint
```

- [ ] **Step 2: Add the missing constants**

`MonitorNamespace` and `Service` already exist in the file — find them and
reuse those exact names rather than declaring duplicates. Add the three that
do not exist yet, next to the existing constant block:

```go
const (
	TokenKey         = "token"
	MonitorKind      = "Monitor"
	TargetSecretName = "target-secret"
)
```

- [ ] **Step 3: Replace the repeated literals**

Replace every occurrence flagged by the linter:

- `"default"` (17 occurrences) → `MonitorNamespace`
- `"docker.io"` (6 occurrences) → `Service`
- `"token"` (5 occurrences) → `TokenKey`
- `"Monitor"` (6 occurrences) → `MonitorKind`
- `"target-secret"` (4 occurrences) → `TargetSecretName`

Only replace string literals. Do not touch struct field names or comments
that happen to contain the same word.

- [ ] **Step 4: Verify lint is clean and tests still pass**

Run: `make lint && make test`

Expected: lint reports no issues; all tests pass. Behaviour is unchanged, so
any test failure means a literal was replaced in the wrong place.

- [ ] **Step 5: Commit**

```bash
git add internal/controller/monitor_controller_test.go
git commit -m "test: extract repeated literals to constants for goconst"
```

---

### Task 1: Reshape the metric contract

Removes `state` from the value gauges, adds the state info-gauge, and makes
every write identity-scoped so label churn cannot orphan series.

**Files:**
- Modify: `internal/utils/metrics.go`
- Test: `internal/utils/metrics_test.go`

**Interfaces:**
- Consumes: `testutils.GenerateFullMonitor(ns, secretRef types.NamespacedName, service string, thresholds *v1alpha1.AlertThresholds) *v1alpha1.Monitor`.
- Produces:
  - `SecretValidUntilTimestamp`, `SecretSecondsUntilExpiry` — `*prometheus.GaugeVec`, labelled with identity + descriptive labels only.
  - `MonitorStateGauge` — `*prometheus.GaugeVec`, labelled with identity + descriptive + `state`.
  - `(*Metric) Labels() prometheus.Labels` — value-gauge labels, **no** `state` key.
  - `(*Metric) StateLabels() prometheus.Labels` — value labels plus `state`.
  - `(*Metric) Update() error`
  - `(*Metric) SetError() error`
  - `(*Metric) Cleanup()`
  - `(*Metric) WithLogger(logr.Logger) *Metric`

- [ ] **Step 1: Write the failing tests**

Replace the whole body of `internal/utils/metrics_test.go` below the import
block. Keep the existing licence header. The import block becomes:

```go
import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	testutils "github.com/stakater/expiring-secret-operator/test/utils"
)
```

The specs:

```go
// fixedExpiry keeps CollectAndCompare deterministic: a wall-clock value
// would change between runs.
const fixedExpiryUnix = int64(1800000000)

func monitorWithStatus(
	name, namespace, secretName, secretNamespace, service string,
	state expiringsecretv1alpha1.MonitorState,
) *expiringsecretv1alpha1.Monitor {
	monitor := testutils.GenerateFullMonitor(
		types.NamespacedName{Name: name, Namespace: namespace},
		types.NamespacedName{Name: secretName, Namespace: secretNamespace},
		service,
		nil,
	)
	expiresAt := metav1.NewTime(time.Unix(fixedExpiryUnix, 0))
	secondsRemaining := int64(3600)
	monitor.Status.ExpiresAt = &expiresAt
	monitor.Status.SecondsRemaining = &secondsRemaining
	monitor.Status.State = state
	return monitor
}

var _ = Describe("Metric", func() {
	// The gauge vectors are package-level globals shared by every spec, so
	// reset them to keep series counts meaningful.
	BeforeEach(func() {
		SecretValidUntilTimestamp.Reset()
		SecretSecondsUntilExpiry.Reset()
		MonitorStateGauge.Reset()
	})

	Context("label sets", func() {
		It("omits state from the value gauge labels", func() {
			monitor := monitorWithStatus("m", "ns", "s", "", "docker.io",
				expiringsecretv1alpha1.MonitorStateWarning)
			labels := NewMetric(monitor).Labels()

			Expect(labels).NotTo(HaveKey(LabelState))
			Expect(labels[LabelMonitorName]).To(Equal("m"))
			Expect(labels[LabelMonitorNamespace]).To(Equal("ns"))
			Expect(labels[LabelSecretName]).To(Equal("s"))
			// An empty secretRef namespace defaults to the Monitor's own.
			Expect(labels[LabelSecretNamespace]).To(Equal("ns"))
			Expect(labels[LabelSecretService]).To(Equal("docker.io"))
		})

		It("includes state in the state gauge labels", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateInfo)
			labels := NewMetric(monitor).StateLabels()

			Expect(labels[LabelState]).To(Equal("Info"))
			Expect(labels[LabelMonitorName]).To(Equal("m"))
		})

		It("builds deterministic label values without state", func() {
			monitor := monitorWithStatus(
				"label-values-monitor", "label-values-namespace",
				"label-values-secret", "label-values-secret-namespace",
				"quay.io", expiringsecretv1alpha1.MonitorStateInfo)

			expected := `monitor_name="label-values-monitor",` +
				`monitor_namespace="label-values-namespace",` +
				`secret_name="label-values-secret",` +
				`secret_namespace="label-values-secret-namespace",` +
				`secret_service="quay.io"`
			Expect(NewMetric(monitor).LabelValues()).To(Equal(expected))
		})

		It("tolerates a nil monitor and a nil secretRef", func() {
			Expect(NewMetric(nil).Labels()).To(BeEmpty())

			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			monitor.Spec.SecretRef = nil
			labels := NewMetric(monitor).Labels()
			Expect(labels[LabelSecretName]).To(BeEmpty())
			Expect(labels[LabelSecretNamespace]).To(Equal("ns"))
		})
	})

	Context("updates", func() {
		It("rejects incomplete status", func() {
			Expect(NewMetric(nil).Update()).NotTo(Succeed())

			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			monitor.Status.ExpiresAt = nil
			Expect(NewMetric(monitor).Update()).NotTo(Succeed())

			monitor = monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			monitor.Status.SecondsRemaining = nil
			Expect(NewMetric(monitor).Update()).NotTo(Succeed())

			monitor = monitorWithStatus("m", "ns", "s", "ns", "quay.io", "")
			Expect(NewMetric(monitor).Update()).NotTo(Succeed())
		})

		It("publishes all three series", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
			Expect(testutil.CollectAndCount(SecretSecondsUntilExpiry)).To(Equal(1))
			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(1))
		})
	})

	Context("series lifecycle", func() {
		It("leaves exactly one state series across a transition", func() {
			// Regression test: state used to be a label on the value gauges,
			// so each transition minted a new series and abandoned the old.
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			monitor.Status.State = expiringsecretv1alpha1.MonitorStateCritical
			Expect(NewMetric(monitor).Update()).To(Succeed())

			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(1))
			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
			Expect(testutil.CollectAndCount(SecretSecondsUntilExpiry)).To(Equal(1))

			Expect(testutil.ToFloat64(
				MonitorStateGauge.With(NewMetric(monitor).StateLabels()),
			)).To(Equal(1.0))
		})

		It("leaves no orphan when the secretRef is retargeted", func() {
			monitor := monitorWithStatus("m", "ns", "old-secret", "ns",
				"quay.io", expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			monitor.Spec.SecretRef.Name = "new-secret"
			Expect(NewMetric(monitor).Update()).To(Succeed())

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(1))
		})

		It("leaves no orphan when the service changes", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			monitor.Spec.Service = "ghcr.io"
			Expect(NewMetric(monitor).Update()).To(Succeed())

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
		})

		It("does not disturb another Monitor's series", func() {
			first := monitorWithStatus("first", "ns", "s1", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			second := monitorWithStatus("second", "ns", "s2", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(first).Update()).To(Succeed())
			Expect(NewMetric(second).Update()).To(Succeed())

			NewMetric(first).Cleanup()

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(1))
			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(1))
		})

		It("removes every series on cleanup", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			NewMetric(monitor).Cleanup()

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(0))
			Expect(testutil.CollectAndCount(SecretSecondsUntilExpiry)).To(Equal(0))
			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(0))
		})
	})

	Context("error state", func() {
		It("drops the value gauges but keeps the failure alertable", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io",
				expiringsecretv1alpha1.MonitorStateValid)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			monitor.Status.State = expiringsecretv1alpha1.MonitorStateError
			Expect(NewMetric(monitor).SetError()).To(Succeed())

			Expect(testutil.CollectAndCount(SecretValidUntilTimestamp)).To(Equal(0))
			Expect(testutil.CollectAndCount(SecretSecondsUntilExpiry)).To(Equal(0))
			Expect(testutil.CollectAndCount(MonitorStateGauge)).To(Equal(1))

			labels := NewMetric(monitor).StateLabels()
			Expect(labels[LabelState]).To(Equal("Error"))
			Expect(testutil.ToFloat64(MonitorStateGauge.With(labels))).To(Equal(1.0))
		})

		It("defaults to the Error state when status carries none", func() {
			monitor := monitorWithStatus("m", "ns", "s", "ns", "quay.io", "")
			Expect(NewMetric(monitor).SetError()).To(Succeed())

			labels := NewMetric(monitor).Labels()
			labels[LabelState] = string(expiringsecretv1alpha1.MonitorStateError)
			Expect(testutil.ToFloat64(MonitorStateGauge.With(labels))).To(Equal(1.0))
		})

		It("rejects a nil monitor", func() {
			Expect(NewMetric(nil).SetError()).NotTo(Succeed())
		})
	})

	Context("exposed contract", func() {
		It("exposes the documented names, labels and values", func() {
			monitor := monitorWithStatus(
				"contract-monitor", "contract-ns",
				"contract-secret", "contract-ns",
				"quay.io", expiringsecretv1alpha1.MonitorStateWarning)
			Expect(NewMetric(monitor).Update()).To(Succeed())

			expected := `
# HELP expiringsecrets_monitor_state Current state of the Monitor, always 1 for the active state
# TYPE expiringsecrets_monitor_state gauge
expiringsecrets_monitor_state{monitor_name="contract-monitor",monitor_namespace="contract-ns",secret_name="contract-secret",secret_namespace="contract-ns",secret_service="quay.io",state="Warning"} 1
`
			Expect(testutil.CollectAndCompare(MonitorStateGauge,
				strings.NewReader(expected))).To(Succeed())

			expected = `
# HELP expiringsecrets_monitor_until_expiration_seconds Seconds until secret expires
# TYPE expiringsecrets_monitor_until_expiration_seconds gauge
expiringsecrets_monitor_until_expiration_seconds{monitor_name="contract-monitor",monitor_namespace="contract-ns",secret_name="contract-secret",secret_namespace="contract-ns",secret_service="quay.io"} 3600
`
			Expect(testutil.CollectAndCompare(SecretSecondsUntilExpiry,
				strings.NewReader(expected))).To(Succeed())

			expected = `
# HELP expiringsecrets_monitor_valid_until_timestamp_seconds Secret expiration timestamp
# TYPE expiringsecrets_monitor_valid_until_timestamp_seconds gauge
expiringsecrets_monitor_valid_until_timestamp_seconds{monitor_name="contract-monitor",monitor_namespace="contract-ns",secret_name="contract-secret",secret_namespace="contract-ns",secret_service="quay.io"} 1.8e+09
`
			Expect(testutil.CollectAndCompare(SecretValidUntilTimestamp,
				strings.NewReader(expected))).To(Succeed())
		})
	})
})
```

Add `"strings"` to the import block for `strings.NewReader`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/utils/... -run TestTheUtils`

Expected: compile failure — `MonitorStateGauge`, `StateLabels`, and
`SetError` are undefined.

- [ ] **Step 3: Rewrite `internal/utils/metrics.go`**

Keep the licence header. Replace everything from the `const` block onward:

```go
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/utils/... -run TestTheUtils -v`

Expected: PASS. If `CollectAndCompare` fails, read the diff carefully — the
exposition format orders labels alphabetically and renders `1800000000` as
`1.8e+09`.

- [ ] **Step 5: Confirm the controller still builds**

Run: `go build ./...`

Expected: success. `monitor_controller.go` still calls `Update()` and
`Cleanup()`, both of which kept their signatures. `SetError` is wired up in
Task 2.

- [ ] **Step 6: Commit**

```bash
git add internal/utils/metrics.go internal/utils/metrics_test.go
git commit -m "feat: split state into its own gauge and scope metric writes by identity"
```

---

### Task 2: Keep failing Monitors alertable

Switches the reconciler's error path from deleting all metrics to publishing
`state="Error"`, and adds envtest coverage for the full series lifecycle.

**Files:**
- Modify: `internal/controller/monitor_controller.go` (the `handleError` function)
- Test: `internal/controller/monitor_controller_test.go`

**Interfaces:**
- Consumes: `utils.NewMetric(...).WithLogger(...).SetError() error`, `utils.MonitorStateGauge`, `utils.LabelState` from Task 1.
- Produces: no new exported symbols.

- [ ] **Step 1: Write the failing tests**

Append this `Context` inside the existing `Describe("Monitor Controller", ...)`
block in `internal/controller/monitor_controller_test.go`. It uses the
file's existing `newReconciler()` helper, the envtest `k8sClient`, and the
constants from Task 0.

```go
	Context("Prometheus metrics", func() {
		BeforeEach(func() {
			utils.SecretValidUntilTimestamp.Reset()
			utils.SecretSecondsUntilExpiry.Reset()
			utils.MonitorStateGauge.Reset()
		})

		It("publishes all three series for a healthy Monitor", func() {
			ctx := context.Background()
			secret := testutils.GenerateValidDaysSecret(
				types.NamespacedName{Name: "metrics-secret", Namespace: MonitorNamespace},
				60,
			)
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			monitor := testutils.GenerateMonitorService(
				types.NamespacedName{Name: "metrics-monitor", Namespace: MonitorNamespace},
				types.NamespacedName{Name: "metrics-secret", Namespace: MonitorNamespace},
				Service,
			)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			reconciler := newReconciler()
			name := types.NamespacedName{Name: "metrics-monitor", Namespace: MonitorNamespace}
			// First pass adds the finalizer and defaults; the second
			// populates status, which is what the metrics are built from.
			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())

			Expect(testutil.CollectAndCount(utils.SecretValidUntilTimestamp)).To(Equal(1))
			Expect(testutil.CollectAndCount(utils.SecretSecondsUntilExpiry)).To(Equal(1))
			Expect(testutil.CollectAndCount(utils.MonitorStateGauge)).To(Equal(1))

			By("removing every series once the Monitor is deleted")
			Expect(k8sClient.Delete(ctx, monitor)).To(Succeed())
			_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())

			Expect(testutil.CollectAndCount(utils.SecretValidUntilTimestamp)).To(Equal(0))
			Expect(testutil.CollectAndCount(utils.SecretSecondsUntilExpiry)).To(Equal(0))
			Expect(testutil.CollectAndCount(utils.MonitorStateGauge)).To(Equal(0))

			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
		})

		It("keeps a broken Monitor alertable via the state series", func() {
			ctx := context.Background()
			// No Secret is created, so the source lookup fails.
			monitor := testutils.GenerateMonitorService(
				types.NamespacedName{Name: "error-metrics-monitor", Namespace: MonitorNamespace},
				types.NamespacedName{Name: "absent-secret", Namespace: MonitorNamespace},
				Service,
			)
			Expect(k8sClient.Create(ctx, monitor)).To(Succeed())

			reconciler := newReconciler()
			name := types.NamespacedName{Name: "error-metrics-monitor", Namespace: MonitorNamespace}
			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())
			_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())

			By("dropping the value gauges, whose expiry is unknown")
			Expect(testutil.CollectAndCount(utils.SecretValidUntilTimestamp)).To(Equal(0))
			Expect(testutil.CollectAndCount(utils.SecretSecondsUntilExpiry)).To(Equal(0))

			By("publishing the Error state so an alert can fire")
			Expect(testutil.CollectAndCount(utils.MonitorStateGauge)).To(Equal(1))
			metric, err := utils.MonitorStateGauge.GetMetricWith(prometheus.Labels{
				utils.LabelMonitorName:      "error-metrics-monitor",
				utils.LabelMonitorNamespace: MonitorNamespace,
				utils.LabelSecretName:       "absent-secret",
				utils.LabelSecretNamespace:  MonitorNamespace,
				utils.LabelSecretService:    Service,
				utils.LabelState:            string(expiringsecretv1alpha1.MonitorStateError),
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(testutil.ToFloat64(metric)).To(Equal(1.0))

			Expect(k8sClient.Delete(ctx, monitor)).To(Succeed())
			_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())
		})
	})
```

Add `"github.com/prometheus/client_golang/prometheus"` to the import block —
the rest of the imports used here are already present.

- [ ] **Step 2: Run the tests to verify the error case fails**

Run: `make test`

Expected: the healthy-Monitor spec passes; the broken-Monitor spec FAILS,
reporting 0 state series, because `handleError` still calls `Cleanup()`.

- [ ] **Step 3: Switch the error path to SetError**

In `internal/controller/monitor_controller.go`, inside `handleError`,
replace:

```go
	// Clean up metrics when monitor enters error state
	utils.NewMetric(r.output).WithLogger(r.log).Cleanup()
```

with:

```go
	// Drop the value gauges, whose expiry is unknown, but keep publishing the
	// state so a failing Monitor stays alertable rather than going silent.
	if err := utils.NewMetric(r.output).WithLogger(r.log).SetError(); err != nil {
		r.log.Error(err, "Failed to publish error state metric", "monitor", r.output.Name)
	}
```

Leave `handleDeletion`'s `Cleanup()` call alone: a deleted Monitor should
disappear from Prometheus entirely.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `make test`

Expected: PASS.

- [ ] **Step 5: Check coverage**

Run: `make check-coverage`

Expected: no threshold violations for `internal/utils` or
`internal/controller`.

- [ ] **Step 6: Commit**

```bash
git add internal/controller/monitor_controller.go internal/controller/monitor_controller_test.go
git commit -m "feat: publish Error state metric instead of deleting metrics on failure"
```

---

### Task 3: Make the scrape authenticate

Ships the reader ServiceAccount and its token, authorizes it, and points the
ServiceMonitor at it. Removes the duplicate PodMonitor.

**Files:**
- Create: `config/rbac/metrics_reader_service_account.yaml`
- Create: `config/rbac/metrics_reader_token.yaml`
- Create: `config/rbac/metrics_reader_role_binding.yaml`
- Create: `config/default/prometheus_name_reference.yaml`
- Modify: `config/rbac/kustomization.yaml`
- Modify: `config/prometheus/servicemonitor.yaml`
- Modify: `config/prometheus/kustomization.yaml`
- Modify: `config/default/kustomization.yaml`
- Delete: `config/prometheus/podmonitor.yaml`

**Interfaces:**
- Consumes: the `metrics-reader` ClusterRole already in `config/rbac/metrics_reader_role.yaml`.
- Produces: a Secret named `metrics-reader-token` (rendered as `expiring-secret-operator-metrics-reader-token`) holding a `token` key, referenced by the ServiceMonitor. Task 5 and Task 6 rely on the ServiceMonitor being the only scrape config.

- [ ] **Step 1: Create the reader ServiceAccount**

`config/rbac/metrics_reader_service_account.yaml`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    app.kubernetes.io/name: expiring-secrets
    app.kubernetes.io/managed-by: kustomize
  name: metrics-reader
  namespace: system
```

- [ ] **Step 2: Create the token Secret**

Kubernetes 1.24 and later no longer auto-create token Secrets, so declare
one explicitly. `config/rbac/metrics_reader_token.yaml`:

```yaml
# A long-lived token for Prometheus to authenticate against /metrics.
# Its only grant is `get` on the non-resource URL /metrics, so the blast
# radius of a leak is read access to secret-expiry metrics.
apiVersion: v1
kind: Secret
metadata:
  labels:
    app.kubernetes.io/name: expiring-secrets
    app.kubernetes.io/managed-by: kustomize
  name: metrics-reader-token
  namespace: system
  annotations:
    # NOTE: this value must carry the namePrefix from
    # config/default/kustomization.yaml. kustomize rewrites resource names
    # but never the contents of an annotation, so this one string has to
    # track that prefix by hand.
    kubernetes.io/service-account.name: expiring-secret-operator-metrics-reader
type: kubernetes.io/service-account-token
```

- [ ] **Step 3: Authorize the reader**

`config/rbac/metrics_reader_role_binding.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    app.kubernetes.io/name: expiring-secrets
    app.kubernetes.io/managed-by: kustomize
  name: metrics-reader-rolebinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: metrics-reader
subjects:
- kind: ServiceAccount
  name: metrics-reader
  namespace: system
```

kustomize rewrites `roleRef.name` and the ServiceAccount subject
automatically — both are built-in name references, unlike the annotation in
Step 2.

- [ ] **Step 4: Register the new RBAC resources**

In `config/rbac/kustomization.yaml`, add to the `resources` list directly
below the existing `- metrics_reader_role.yaml` line:

```yaml
- metrics_reader_service_account.yaml
- metrics_reader_token.yaml
- metrics_reader_role_binding.yaml
```

- [ ] **Step 5: Teach kustomize about the ServiceMonitor's Secret reference**

`authorization.credentials.name` is not a field kustomize knows about, so
without this the ServiceMonitor would keep referencing the unprefixed name
while the Secret gets prefixed. Create
`config/default/prometheus_name_reference.yaml`:

```yaml
# Teaches kustomize to rewrite the Secret name inside the ServiceMonitor's
# authorization block when namePrefix is applied. Declared here, in the
# kustomization that applies namePrefix, because that is where the
# transformer runs.
nameReference:
- kind: Secret
  version: v1
  fieldSpecs:
  - kind: ServiceMonitor
    group: monitoring.coreos.com
    version: v1
    path: spec/endpoints/authorization/credentials/name
```

Then in `config/default/kustomization.yaml`, add at the end of the file:

```yaml
configurations:
- prometheus_name_reference.yaml
```

- [ ] **Step 6: Rewrite the ServiceMonitor**

Replace the whole of `config/prometheus/servicemonitor.yaml`:

```yaml
# Prometheus Monitor Service (Metrics)
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    control-plane: controller-manager
    app.kubernetes.io/name: expiring-secrets
    app.kubernetes.io/managed-by: kustomize
  name: controller-manager-metrics-monitor
  namespace: system
spec:
  endpoints:
    - path: /metrics
      # Named port from config/default/metrics_service.yaml, so this cannot
      # drift from the Service definition.
      port: https
      scheme: https
      # The metrics endpoint is protected by the manager's authn/authz filter
      # (see cmd/main.go), so the scrape must present a bearer token.
      #
      # Do NOT switch this to bearerTokenFile. OpenShift user-workload
      # monitoring sets arbitraryFSAccessThroughSMs to deny, which rejects
      # any ServiceMonitor reading a path from the Prometheus container's
      # filesystem. Prometheus Operator also deprecates that field.
      authorization:
        type: Bearer
        credentials:
          name: metrics-reader-token
          key: token
      tlsConfig:
        # TODO(user): the manager serves a self-signed certificate, so there
        # is no CA to verify against yet. Replacing this means issuing
        # serving certs with cert-manager and referencing the CA here as
        # tlsConfig.ca.secret — note that caFile is unavailable for the same
        # arbitraryFSAccessThroughSMs reason described above.
        insecureSkipVerify: true
  selector:
    matchLabels:
      control-plane: controller-manager
```

- [ ] **Step 7: Drop the PodMonitor and enable the rules**

```bash
git rm config/prometheus/podmonitor.yaml
```

A single-replica Deployment already behind a Service gains nothing from
pod-level scraping, and shipping both duplicates every series.

Replace `config/prometheus/kustomization.yaml` entirely:

```yaml
resources:
- servicemonitor.yaml
- rule.yaml
```

`rule.yaml` was commented out, which is why no alert rules shipped at all.

- [ ] **Step 8: Verify the rendered output**

Run:

```bash
make kustomize
./bin/kustomize build config/default | grep -A 8 'authorization:'
```

Expected: the credentials name renders **prefixed**:

```yaml
      authorization:
        type: Bearer
        credentials:
          key: token
          name: expiring-secret-operator-metrics-reader-token
```

If it renders unprefixed as `metrics-reader-token`, the `configurations`
entry from Step 5 is not being picked up — check it is in
`config/default/kustomization.yaml` and not in the prometheus base.

Then confirm the Secret, ServiceAccount and binding all render, that no
PodMonitor remains, and that the rules are included:

```bash
./bin/kustomize build config/default | grep -E '^kind:|^  name:' | grep -B 1 -E 'metrics-reader|expired-secret-rules'
./bin/kustomize build config/default | grep -c 'kind: PodMonitor'
```

Expected: the ServiceAccount, Secret and ClusterRoleBinding are present, the
PrometheusRule is present, and the PodMonitor count is `0`.

- [ ] **Step 9: Commit**

```bash
git add config/rbac config/prometheus config/default
git commit -m "feat: authenticate Prometheus scrapes with a metrics-reader token"
```

---

### Task 4: Make alerting respect per-Monitor thresholds

Rewrites the rules against the state metric, and adds promtool checks so a
rule that matches nothing cannot pass CI again.

**Files:**
- Modify: `config/prometheus/rule.yaml`
- Create: `test/rules/rule_test.yaml`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `expiringsecrets_monitor_state` from Task 1; the rule file being part of the kustomization from Task 3.
- Produces: `make test-rules` target; `PROMTOOL` variable.

- [ ] **Step 1: Rewrite the rules**

The old rules hardcoded 30/14/7 in PromQL while `spec.alertThresholds` is
per-Monitor, so a Monitor with `criticalDays: 2` reported `Valid` in status
while Prometheus fired critical at 7 days. Alerting on the state the
operator computed is what makes those CRD fields mean anything.

Replace `config/prometheus/rule.yaml` entirely. Note there is no `namespace`
field: the kustomize `namespace:` directive places this in the operator's own
namespace, which is where OpenShift UWM looks for rules.

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: expired-secret-rules
  labels:
    prometheus: k8s
    role: alert-rules
    app.kubernetes.io/name: expiring-secrets
    app.kubernetes.io/managed-by: kustomize
spec:
  groups:
    - name: expired-secret.rules
      rules:
        # These alert on the state the operator computed, not on a duration
        # threshold repeated in PromQL. Thresholds are per-Monitor
        # (spec.alertThresholds), so only the operator knows which one
        # applies; hardcoding them here silently ignored the CRD.
        - alert: SecretExpirationDateIsApproaching
          expr: expiringsecrets_monitor_state{state="Info"} == 1
          for: 10m
          labels:
            severity: info
          annotations:
            summary: "Secret expiration date is approaching"
            description: "The secret '{{ $labels.secret_name }}' in namespace '{{ $labels.secret_namespace }}' has passed its info threshold."
        - alert: SecretExpirationDateIsApproachingRapidly
          expr: expiringsecrets_monitor_state{state="Warning"} == 1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Secret expiration date is approaching rapidly"
            description: "The secret '{{ $labels.secret_name }}' in namespace '{{ $labels.secret_namespace }}' has passed its warning threshold."
        - alert: SecretExpirationDateIsCritical
          expr: expiringsecrets_monitor_state{state="Critical"} == 1
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "Secret expiration date is critical"
            description: "The secret '{{ $labels.secret_name }}' in namespace '{{ $labels.secret_namespace }}' has passed its critical threshold."
        - alert: SecretHasExpired
          expr: expiringsecrets_monitor_state{state="Expired"} == 1
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "Secret has expired"
            description: "The secret '{{ $labels.secret_name }}' in namespace '{{ $labels.secret_namespace }}' has expired."
        - alert: SecretMonitorError
          expr: expiringsecrets_monitor_state{state="Error"} == 1
          for: 15m
          labels:
            severity: warning
          annotations:
            summary: "Secret monitor cannot evaluate expiry"
            description: "The Monitor '{{ $labels.monitor_name }}' in namespace '{{ $labels.monitor_namespace }}' cannot evaluate secret '{{ $labels.secret_name }}'. Expiry is unknown."
```

- [ ] **Step 2: Write the failing rule test**

`promtool` cannot read a `PrometheusRule` custom resource — it expects a
plain Prometheus rules file — so the make target in Step 3 extracts `.spec`
first. Write the test against that extracted shape.

`test/rules/rule_test.yaml`:

```yaml
# Run via `make test-rules`, which extracts .spec from the PrometheusRule
# into rules.generated.yaml alongside this file.
rule_files:
  - rules.generated.yaml

evaluation_interval: 1m

tests:
  - interval: 1m
    input_series:
      - series: 'expiringsecrets_monitor_state{monitor_name="m1",monitor_namespace="ns1",secret_name="s1",secret_namespace="ns1",secret_service="quay.io",state="Critical"}'
        values: '1+0x20'
    alert_rule_test:
      - eval_time: 10m
        alertname: SecretExpirationDateIsCritical
        exp_alerts:
          - exp_labels:
              severity: critical
              monitor_name: m1
              monitor_namespace: ns1
              secret_name: s1
              secret_namespace: ns1
              secret_service: quay.io
              state: Critical
            exp_annotations:
              summary: "Secret expiration date is critical"
              description: "The secret 's1' in namespace 'ns1' has passed its critical threshold."
      # A Critical Monitor must not also fire the warning-level alert.
      - eval_time: 10m
        alertname: SecretExpirationDateIsApproachingRapidly
        exp_alerts: []

  - interval: 1m
    input_series:
      - series: 'expiringsecrets_monitor_state{monitor_name="m2",monitor_namespace="ns2",secret_name="s2",secret_namespace="ns2",secret_service="ghcr.io",state="Error"}'
        values: '1+0x30'
    alert_rule_test:
      # Below the 15m `for`, nothing fires yet.
      - eval_time: 10m
        alertname: SecretMonitorError
        exp_alerts: []
      - eval_time: 20m
        alertname: SecretMonitorError
        exp_alerts:
          - exp_labels:
              severity: warning
              monitor_name: m2
              monitor_namespace: ns2
              secret_name: s2
              secret_namespace: ns2
              secret_service: ghcr.io
              state: Error
            exp_annotations:
              summary: "Secret monitor cannot evaluate expiry"
              description: "The Monitor 'm2' in namespace 'ns2' cannot evaluate secret 's2'. Expiry is unknown."
```

- [ ] **Step 3: Add the make target**

Add to the root `Makefile`, above the `include` line. Project-specific
targets belong here rather than in `makefiles/common.mk`, which is shared
across repositories.

```make
PROMTOOL ?= $(LOCALBIN)/promtool
# The prometheus Go module numbers releases v0.x while the binaries are
# tagged 2.x/3.x: v0.55.1 here is Prometheus 2.55.1.
PROMTOOL_VERSION ?= v0.55.1

.PHONY: promtool
promtool: ## Download promtool locally if necessary.
	$(call go-install-tool,$(PROMTOOL),github.com/prometheus/prometheus/cmd/promtool,$(PROMTOOL_VERSION))

.PHONY: test-rules
test-rules: promtool ## Validate and unit-test the PrometheusRule alert rules.
	@command -v yq >/dev/null 2>&1 || { echo "yq is required by test-rules"; exit 1; }
	@echo ">> extracting rules from the PrometheusRule resource"
	yq '.spec' config/prometheus/rule.yaml > test/rules/rules.generated.yaml
	@echo ">> checking rule syntax"
	$(PROMTOOL) check rules test/rules/rules.generated.yaml
	@echo ">> running rule unit tests"
	$(PROMTOOL) test rules test/rules/rule_test.yaml
```

Add the generated file to `.gitignore`:

```
test/rules/rules.generated.yaml
```

- [ ] **Step 4: Run the rule tests**

Run: `make test-rules`

Expected: `SUCCESS` from both `check rules` and `test rules`.

Two failure modes to expect. If `go install` of promtool fails, check the
version mapping noted in the Makefile comment and pick a `v0.x` tag that
exists. If `test rules` reports an annotation mismatch, the expected text in
`rule_test.yaml` must match the rendered template exactly, character for
character — copy the actual rendered string from the failure output.

- [ ] **Step 5: Prove the guard works**

This is the check that the rules match real series. Temporarily reintroduce
the original bug by editing one `expr` in `config/prometheus/rule.yaml` to
the old singular prefix `expiringsecret_monitor_state`, then:

Run: `make test-rules`

Expected: FAIL — the alert does not fire because nothing matches. Revert the
edit and confirm `make test-rules` passes again. Without this step there is
no evidence the test would have caught the original defect.

- [ ] **Step 6: Commit**

```bash
git add config/prometheus/rule.yaml test/rules/rule_test.yaml Makefile .gitignore
git commit -m "feat: alert on computed state so per-Monitor thresholds apply"
```

---

### Task 5: Deploy a Prometheus that actually scrapes

`make install-dependencies` installs the Prometheus Operator, so the CRDs
exist but no `Prometheus` instance ever runs. Without one, "Prometheus can
scrape us" stays unverifiable — which is how both the 401 and the metric
prefix typo survived.

**Files:**
- Create: `test/monitoring/kustomization.yaml`
- Create: `test/monitoring/namespace.yaml`
- Create: `test/monitoring/rbac.yaml`
- Create: `test/monitoring/prometheus.yaml`
- Modify: `Makefile`

**Interfaces:**
- Consumes: the ServiceMonitor and PrometheusRule from Tasks 3 and 4.
- Produces: `make deploy-monitoring` / `make undeploy-monitoring`; a Prometheus reachable at `svc/prometheus-operated:9090` in the `monitoring` namespace, used by Task 6.

These files live under `test/` rather than `config/` on purpose: anything
under `config/` can be pulled into the OLM bundle via `config/manifests`,
and a dev-only `Prometheus` CR must never ship to users.

- [ ] **Step 1: Create the namespace**

`test/monitoring/namespace.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
```

- [ ] **Step 2: Create Prometheus's own RBAC**

This is what Prometheus needs to discover targets. It is separate from the
`metrics-reader` binding in Task 3, which is what authorizes reading our
`/metrics`. `test/monitoring/rbac.yaml`:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: prometheus
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dev-prometheus
rules:
- apiGroups: [""]
  resources:
  - nodes
  - nodes/metrics
  - services
  - endpoints
  - pods
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources:
  - configmaps
  # Reading the token Secret that the ServiceMonitor's authorization block
  # references.
  - secrets
  verbs: ["get"]
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dev-prometheus
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: dev-prometheus
subjects:
- kind: ServiceAccount
  name: prometheus
  namespace: monitoring
```

- [ ] **Step 3: Create the Prometheus instance**

`test/monitoring/prometheus.yaml`:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata:
  name: dev
  namespace: monitoring
spec:
  serviceAccountName: prometheus
  # Empty selectors mean "everything", across every namespace: this is a
  # throwaway dev instance, not a tuned production one.
  serviceMonitorNamespaceSelector: {}
  serviceMonitorSelector: {}
  ruleNamespaceSelector: {}
  ruleSelector:
    matchLabels:
      role: alert-rules
  scrapeInterval: 30s
  resources:
    requests:
      memory: 400Mi
  enableAdminAPI: false
```

- [ ] **Step 4: Create the kustomization**

`test/monitoring/kustomization.yaml`:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- namespace.yaml
- rbac.yaml
- prometheus.yaml
```

- [ ] **Step 5: Add the make targets**

Add to the root `Makefile`, above the `include` line:

```make
.PHONY: deploy-monitoring
deploy-monitoring: kustomize ## Deploy a dev Prometheus into Kind to verify scraping.
	$(KUSTOMIZE) build test/monitoring | $(KUBECTL) apply -f -
	$(KUBECTL) -n monitoring rollout status statefulset/prometheus-dev --timeout=180s

.PHONY: undeploy-monitoring
undeploy-monitoring: kustomize ## Remove the dev Prometheus from Kind.
	-$(KUSTOMIZE) build test/monitoring | $(KUBECTL) delete --ignore-not-found=true -f -
```

Note: `make deploy-core`, which `CLAUDE.md` documents, does not exist in
this repository. Do not wire these into it. Run `make deploy` followed by
`make deploy-monitoring`.

- [ ] **Step 6: Verify the scrape end to end**

This is the acceptance test for the whole plan.

```bash
make docker-build deploy
make deploy-monitoring
kubectl -n monitoring port-forward svc/prometheus-operated 9090:9090 &
sleep 5
curl -s 'http://localhost:9090/api/v1/query?query=up{job="expiring-secret-operator-controller-manager-metrics-service"}' | jq '.data.result[0].value[1]'
```

Expected: `"1"`. A `"0"` or an empty result means the scrape is failing —
open `http://localhost:9090/targets` and read the error. `401` means the
token or the `metrics-reader` binding from Task 3 is wrong; `connection
refused` means the port name or the metrics bind address is wrong.

Then confirm a real series has landed. Apply a sample Monitor first:

```bash
kubectl apply -f config/samples/expiring-secrets_v1alpha1_monitor.yaml
sleep 60
curl -s 'http://localhost:9090/api/v1/query?query=expiringsecrets_monitor_state' | jq '.data.result'
```

Expected: at least one series, with a `state` label. Kill the port-forward
when done.

- [ ] **Step 7: Commit**

```bash
git add test/monitoring Makefile
git commit -m "test: add dev Prometheus stack to verify scraping in Kind"
```

---

### Task 6: Assert the scrape in e2e

**Files:**
- Modify: `test/e2e/e2e_test.go`

**Interfaces:**
- Consumes: the Prometheus from Task 5, the state metric from Task 1.
- Produces: no new exported symbols.

- [ ] **Step 1: Extend the existing metrics assertions**

`e2e_test.go` already has a `should expose metrics endpoint` spec that curls
`/metrics` with a token and checks for `validUntilMetricName` and
`untilExpiryMetricName`. Those are not plain string constants — they are
local variables inside the `Context("Prometheus Metrics", ...)` block
(around line 371), assembled from the exported constants. Add a third one
immediately after them, following the same pattern:

```go
		stateMetricName := fmt.Sprintf(
			"%s_%s_%s",
			internalutils.PrometheusNamespace,
			internalutils.PrometheusSubsystem,
			internalutils.StateMetricName)
```

Copy the format string from the two existing declarations rather than
assuming it — read lines 371-380 first.

Then, in that same spec, after the existing two `ContainSubstring`
assertions, add:

```go
			By("verifying that metrics output contains expected metric " + stateMetricName)
			Expect(outputStr).To(
				ContainSubstring(stateMetricName))

			By("verifying the state label is absent from the value gauges")
			// state moved to its own metric; if it reappears here the
			// stale-series bug is back.
			for _, line := range strings.Split(outputStr, "\n") {
				if strings.HasPrefix(line, validUntilMetricName+"{") ||
					strings.HasPrefix(line, untilExpiryMetricName+"{") {
					Expect(line).NotTo(ContainSubstring("state="))
				}
			}
```

`strings` is **not** currently imported by this file — add it to the import
block. The existing imports are `fmt`, `os`, `os/exec`, `path/filepath` and
`time`, so `strings` slots into that first group.

- [ ] **Step 2: Add a Prometheus scrape spec**

Add this as a new `It` inside the same `Context` as the metrics spec:

```go
		It("should be scraped successfully by Prometheus", func() {
			By("checking whether a dev Prometheus is deployed")
			cmd := exec.Command("kubectl", "get", "prometheus", "dev",
				"-n", "monitoring", "--ignore-not-found=true", "-o", "name")
			out, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			if len(strings.TrimSpace(string(out))) == 0 {
				Skip("no dev Prometheus deployed; run `make deploy-monitoring` first")
			}

			By("querying the scrape target's up metric")
			// svcName is already declared in this Context and is exactly the
			// job label Prometheus Operator assigns to a ServiceMonitor target.
			query := fmt.Sprintf(`up{job="%s"}`, svcName)
			Eventually(func() string {
				cmd := exec.Command("kubectl", "exec", "-n", "monitoring",
					"prometheus-dev-0", "-c", "prometheus", "--",
					"wget", "-qO-",
					"http://localhost:9090/api/v1/query?query="+query,
				)
				out, err := utils.Run(cmd)
				if err != nil {
					return ""
				}
				return string(out)
			}, 3*time.Minute, 10*time.Second).Should(ContainSubstring(`"value":`))
		})
```

The spec skips rather than fails when no Prometheus is present, so
`make test-e2e` keeps working without the monitoring stack, as the spec
requires.

- [ ] **Step 2b: Run the e2e suite without the monitoring stack**

Run: `make test-e2e`

Expected: the metrics specs pass and the new Prometheus spec reports
`Skip`ped.

- [ ] **Step 3: Run the e2e suite with the monitoring stack**

```bash
make deploy-monitoring
make test-e2e
```

Expected: the Prometheus spec passes rather than skipping.

- [ ] **Step 4: Commit**

```bash
git add test/e2e/e2e_test.go
git commit -m "test: assert Prometheus scrapes the operator in e2e"
```

---

### Task 7: Document the OpenShift path

**Files:**
- Modify: `DEPLOY.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything above.
- Produces: no code.

- [ ] **Step 1: Add the monitoring section to DEPLOY.md**

Insert a new `## Monitoring` section after the existing
`## Manual Deployment` section:

```markdown
## Monitoring

The operator serves metrics on `:8443` over HTTPS, protected by the
manager's authn/authz filter. A `ServiceMonitor` and a `PrometheusRule` ship
with the default kustomization, along with a `metrics-reader` ServiceAccount
whose token the ServiceMonitor presents when scraping.

### OpenShift

Metrics are collected by user-workload monitoring, which auto-discovers
`ServiceMonitor` and `PrometheusRule` resources in user namespaces. No
namespace label is needed. In particular, do **not** add
`openshift.io/cluster-monitoring: "true"` — that selects platform
monitoring, which is reserved for platform operators in `openshift-*`
namespaces.

User-workload monitoring must be enabled once, by a cluster administrator.
This is deliberately not shipped as a manifest: `cluster-monitoring-config`
is a cluster singleton, and applying it from our kustomization would clobber
unrelated cluster configuration.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    enableUserWorkload: true
```

Verify the operator is being scraped:

```sh
oc -n openshift-user-workload-monitoring get pods
oc get servicemonitor -n expiring-secret-operator-system
```

The ServiceMonitor authenticates with `authorization.credentials`, not
`bearerTokenFile`. User-workload monitoring sets
`arbitraryFSAccessThroughSMs: deny`, which rejects any ServiceMonitor that
reads a path from the Prometheus container's filesystem, so
`bearerTokenFile` fails there even though it works elsewhere. The same
constraint applies to TLS: a CA must be supplied as `tlsConfig.ca.secret`
rather than `caFile`.

### Local Kind cluster

The Prometheus Operator is installed by `make install-dependencies`, but it
only provides CRDs. To run an actual Prometheus and confirm scraping works:

```sh
make deploy
make deploy-monitoring
kubectl -n monitoring port-forward svc/prometheus-operated 9090:9090
```

Then open <http://localhost:9090/targets> and check that the
`controller-manager-metrics-service` target is `UP`.
```

- [ ] **Step 2: Correct the metrics section in README.md**

The `## Prometheus Metrics` section (around line 68) is entirely fictional.
It documents `secretmonitor_valid_until_timestamp`,
`secretmonitor_seconds_until_expiry` and a `secretmonitor_reconcile_total`
counter, with labels `registry` / `name` / `namespace`. None of those metric
names, and none of those label names, have ever existed in the code. Replace
the whole fenced block with the real contract:

```prometheus
# Absolute expiration timestamp (Unix time)
expiringsecrets_monitor_valid_until_timestamp_seconds{monitor_name="docker-registry-monitor",monitor_namespace="default",secret_name="docker-registry-token",secret_namespace="default",secret_service="docker.io"} 1760486400

# Seconds until expiry, negative once expired
expiringsecrets_monitor_until_expiration_seconds{monitor_name="docker-registry-monitor",monitor_namespace="default",secret_name="docker-registry-token",secret_namespace="default",secret_service="docker.io"} 1209600

# Current state, always 1, emitted only for the state the Monitor is in
expiringsecrets_monitor_state{monitor_name="docker-registry-monitor",monitor_namespace="default",secret_name="docker-registry-token",secret_namespace="default",secret_service="docker.io",state="Info"} 1
```

Directly beneath that block, add:

```markdown
The `state` label appears on `expiringsecrets_monitor_state` only, never on
the two value gauges. Keeping it off them is deliberate: a label whose value
changes over the object's lifetime orphans the series recorded under the
previous value.

Alerts fire from `expiringsecrets_monitor_state` rather than by comparing
`expiringsecrets_monitor_until_expiration_seconds` against a duration in
PromQL. Thresholds are per-Monitor (`spec.alertThresholds`), so only the
operator knows which one applies to a given Monitor; a threshold written
into a PromQL expression would silently ignore the CRD.
```

- [ ] **Step 3: Correct the PrometheusRule example in README.md**

The `## PrometheusRule Example` section (around line 95) alerts on
`secretmonitor_seconds_until_expiry` with hardcoded 14-day and 7-day
thresholds — the exact pattern this work removes. Replace the two rules in
that example with state-driven equivalents, matching what now ships in
`config/prometheus/rule.yaml`:

```yaml
    - alert: SecretExpiringSoon
      expr: expiringsecrets_monitor_state{state="Warning"} == 1
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Secret {{ $labels.secret_name }} has passed its warning threshold"

    - alert: SecretExpiredCritical
      expr: expiringsecrets_monitor_state{state="Critical"} == 1
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "Secret {{ $labels.secret_name }} has passed its critical threshold"
```

Note that the operator already ships these rules, so the README example
should say it is illustrative of writing your own.

- [ ] **Step 4: Verify the licence check still passes**

Run: `make check_license`

Expected: no findings. There is no markdownlint or vale make target in this
repository despite `.markdownlint.yaml` and `.vale.ini` being present, so
there is nothing further to run for docs.

- [ ] **Step 5: Commit**

```bash
git add DEPLOY.md README.md
git commit -m "docs: document Prometheus scraping for OpenShift and Kind"
```

---

## Final verification

Run the full suite before declaring the work done:

```bash
make lint
make test
make check-coverage
make test-rules
make docker-build deploy deploy-monitoring
make test-e2e
```

Every one must pass. `make test-e2e` in particular must show the Prometheus
scrape spec passing rather than skipping — that is the only step that proves
the original defect is actually fixed.

# Prometheus Metrics: Design

**Date:** 2026-08-23
**Status:** Approved, pending implementation plan

## Problem

The operator already produces Prometheus metrics, but Prometheus cannot
usefully consume them. Five defects stand between the two:

1. **Scrapes are unauthenticated.** `cmd/main.go` enables
   `filters.WithAuthenticationAndAuthorization` on the metrics server, but
   neither `config/prometheus/servicemonitor.yaml` nor `podmonitor.yaml`
   presents a credential. Every scrape returns `401`.
2. **No reader is authorized.** `config/rbac/metrics_reader_role.yaml`
   defines a `metrics-reader` ClusterRole with no binding, so no
   ServiceAccount is permitted to read `/metrics`.
3. **Stale series accumulate.** `state` is a label on both value gauges.
   `Update()` resolves series via `GetMetricWith()` including that label, so
   each threshold crossing mints a new series and abandons the previous one
   at its last written value, permanently.
4. **Alert rules match nothing.** `rule.yaml` queries
   `expiringsecret_monitor_*`; the code registers `expiringsecrets_monitor_*`
   (plural). The rules are valid YAML over a metric name that does not exist.
   Separately, `rule.yaml` is commented out of
   `config/prometheus/kustomization.yaml`, so no rules ship at all.
5. **Per-Monitor thresholds are ignored by alerting.**
   `spec.alertThresholds` is per-Monitor and honoured by
   `calculateState()`, but `rule.yaml` hardcodes 30/14/7 in PromQL. A Monitor
   with `criticalDays: 2` reports `Valid` in its status while Prometheus
   fires `SecretExpirationDateIsCritical` at 7 days. The CRD field only
   matters for alerting, and alerting is exactly where it has no effect.

Defect 5 is the one that determines the metric contract. Because the
operator alone knows each Monitor's thresholds, the computed `state` is the
only correct carrier of that decision into Prometheus. It must therefore be
queryable, which rules out simply deleting the label.

## Scope

In scope: the metric contract, the scrape path, a Kind stack that makes the
scrape verifiable, OpenShift user-workload monitoring wiring, and tests for
all of it.

Out of scope, deliberately:

- **Label-driven Secret discovery.** Metrics stay driven by opt-in `Monitor`
  CRs, as implemented. Reconciling any labelled Secret cluster-wide would
  collapse the series key to the Secret's identity, move thresholds out of
  the CR, and reshape the API. If wanted, it is its own spec.
- **Real TLS verification.** `insecureSkipVerify: true` remains, with its
  TODO narrowed to name cert-manager as the follow-up. Issuing serving certs
  and distributing the CA to Prometheus is orthogonal to authentication.

## Constraints

- Single instance: `config/manager/manager.yaml` sets `replicas: 1` with
  `--leader-elect`. All series live in one process, so no cross-replica
  deduplication or empty-follower problem needs designing around, and no
  pod or instance label is required.
- `Monitor` is `scope: Namespaced`, so `monitor_namespace` is meaningful.
- Coverage thresholds in `.github/.testcoverage-local.yml`: 70% per file,
  80% per package. `internal/utils` and `internal/controller` are both
  in scope for coverage; `cmd/main.go` and `api/v1alpha1` are excluded.

## 1. Metric contract

Three metrics under `expiringsecrets_monitor_`:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `..._valid_until_timestamp_seconds` | gauge | identity + descriptive | Unix expiry timestamp |
| `..._until_expiration_seconds` | gauge | identity + descriptive | Seconds remaining, negative once expired |
| `..._state` | gauge, always `1` | identity + descriptive + `state` | Current state, info-metric style |

- **identity**: `monitor_name`, `monitor_namespace`. The owning Monitor CR,
  unique cluster-wide.
- **descriptive**: `secret_name`, `secret_namespace`, `secret_service`.
  Present on all three metrics so alert annotations can reference them.

`state` is removed from the two value gauges, resolving defect 3.

Only the current state is emitted, at value `1`. No zero-filled series for
the other six states: one state series per Monitor instead of seven, and
`expiringsecrets_monitor_state{state="Critical"} == 1` reads directly.
Absence of a state series means "not in that state"; the value gauges and
normal staleness handling cover "Monitor no longer exists".

Steady-state cardinality is 3 series per Monitor.

### Series lifecycle

Deleting by exact label match is what permits stale series in the first
place: when a label value changes, the delete searches for the old series
using the new labels and misses. Instead, every write performs
`DeletePartialMatch({monitor_name, monitor_namespace})` across all three
vecs, then sets fresh values.

One mechanism then covers every kind of label churn: state transitions, a
retargeted `spec.secretRef`, an edited `spec.service`. `Cleanup()` reduces
to the same call, replacing the current delete-then-fall-back-to-partial-match
duplication in `internal/utils/metrics.go`.

Cost is one delete plus three sets per Monitor per reconcile (once a minute),
which is immaterial at any plausible Monitor count.

### Error handling (behaviour change)

Today `handleError()` calls `Cleanup()`, so a Monitor whose Secret is missing
or whose label is malformed disappears from Prometheus entirely. The
failure most deserving of an alert is the one that goes silent.

New behaviour: the error path runs the same identity-scoped reset as any
other write, then writes only the state series with `state="Error"` = 1. The
two value gauges are therefore absent, because the expiry is genuinely
unknown, while the condition itself stays alertable.

This is an intentional behaviour change, accepted as part of this work.

## 2. Scrape path

- `servicemonitor.yaml`: authenticate via `authorization` referencing a
  ServiceAccount token Secret (detailed below), resolving defect 1. Change
  `targetPort: 8443` to `port: https`, referencing the Service's named port
  instead of a number that must be kept in sync with
  `config/default/metrics_service.yaml`.
- Delete `podmonitor.yaml`. A single replica behind an existing Service
  gains nothing from pod-level scraping, and shipping both duplicates every
  series.
- Uncomment `rule.yaml` in `config/prometheus/kustomization.yaml`.
- Remove `namespace: openshift-monitoring` from `rule.yaml`; the kustomize
  `namespace:` directive places it in the operator's namespace, where UWM
  reads it. Retain its `prometheus: k8s` / `role: alert-rules` labels — the
  Kind Prometheus `ruleSelector` matches on them.
- Rewrite the rules against the corrected metric names, state-driven so
  per-Monitor thresholds are respected (defects 4 and 5):

  | Alert | Expression | For | Severity |
  |---|---|---|---|
  | `SecretExpirationDateIsApproaching` | `..._state{state="Info"} == 1` | 10m | info |
  | `SecretExpirationDateIsApproachingRapidly` | `..._state{state="Warning"} == 1` | 5m | warning |
  | `SecretExpirationDateIsCritical` | `..._state{state="Critical"} == 1` | 5m | critical |
  | `SecretHasExpired` | `..._state{state="Expired"} == 1` | 5m | critical |
  | `SecretMonitorError` | `..._state{state="Error"} == 1` | 15m | warning |

  `SecretHasExpired` and `SecretMonitorError` are new; expiry and monitor
  failure are currently unalertable.

### Authentication method

The obvious choice, and the one this design initially took, is
`bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token` — the
traditional kubebuilder scaffolding. It is rejected because it does not work
in the environment §4 targets:

- OpenShift user-workload monitoring sets `arbitraryFSAccessThroughSMs` to
  `deny`, which rejects any user-namespace ServiceMonitor specifying
  `bearerTokenFile`, precisely because it reads an arbitrary path from the
  Prometheus container's filesystem.
- Prometheus Operator additionally deprecates `Endpoint.BearerTokenFile` in
  favour of `authorization`. It still functions in the pinned v0.72.0, but it
  is on the way out.

Instead: ship a dedicated `metrics-reader` ServiceAccount alongside a
`kubernetes.io/service-account-token` Secret annotated with
`kubernetes.io/service-account.name`, letting the token controller populate
it (Kubernetes 1.24+ no longer auto-creates these). The ServiceMonitor then
carries:

```yaml
authorization:
  type: Bearer
  credentials:
    name: <token-secret>
    key: token
```

Prometheus Operator resolves that SecretKeySelector in the ServiceMonitor's
own namespace, so this works identically under Kind and under UWM.

This also simplifies defect 2. Because the authorized subject is now a
ServiceAccount we ship rather than whichever ServiceAccount the local
Prometheus happens to run as, the `metrics-reader` ClusterRoleBinding
becomes environment-independent and lives in `config/rbac` in the base.
No per-environment binding is needed.

The trade-off is a long-lived bearer token at rest in a Secret, readable by
anything with secret-read in the operator namespace. Its only grant is `get`
on the non-resource URL `/metrics`, so the blast radius is read access to
expiry metrics.

## 3. Kind verification stack

New directory `test/monitoring/`, deliberately outside `config/` so that a
`Prometheus` CR can never reach the OLM bundle through `config/manifests`:

- A `Prometheus` CR and its ServiceAccount, with a ClusterRole for
  service/endpoint/pod discovery. No `metrics-reader` binding is needed
  here; §2 ships it in the base.
- `serviceMonitorSelector` and `ruleSelector` matching the labels the
  existing manifests already carry.
- A `deploy-monitoring` make target, wired into `deploy-core`.

The prerequisite already exists: `DEPENDENCIES` in `makefiles/common.mk`
installs the Prometheus Operator, so the CRDs are present but no
`Prometheus` instance is ever created.

This is what makes the design falsifiable. The assertion is
`up{service="expiring-secret-operator-controller-manager-metrics-service"} == 1`.
Absent it, "Prometheus can scrape us" is an untested claim — which is how
both the 401 and the metric-name typo survived this long.

## 4. OpenShift user-workload monitoring

Because §2's authentication is portable, no OpenShift-specific overlay is
required. The base manifests apply unchanged. What remains is documentation
in `DEPLOY.md`:

- The one prerequisite that must not ship as a manifest:
  `enableUserWorkload: true` in the `cluster-monitoring-config` ConfigMap.
  That ConfigMap is a cluster singleton owned by the cluster administrator;
  applying it from our kustomization would clobber unrelated cluster
  configuration.
- A note that `arbitraryFSAccessThroughSMs: deny` under UWM is why the
  ServiceMonitor uses `authorization` rather than `bearerTokenFile`, so the
  constraint is not accidentally reverted later.

UWM auto-discovers ServiceMonitors and PrometheusRules in user namespaces,
so **no namespace label is required**. The
`openshift.io/cluster-monitoring: "true"` label is the platform-monitoring
path, reserved for platform operators in `openshift-*` namespaces; applying
it here would be incorrect.

## 5. Test plan

Test-driven per `CLAUDE.md`: the contract change lands as failing tests
first. `internal/utils/metrics_test.go:60` currently asserts `state="Info"`
within `LabelValues()`, so existing tests must change. That is the contract
change surfacing, not incidental churn.

**Unit** (`internal/utils/metrics_test.go`, extending the existing
Ginkgo + `testutil` style):

- Value gauges carry no `state` label.
- A `Valid → Critical` transition leaves exactly one state series. This is
  the regression test for defect 3.
- The error path clears both value gauges while leaving `state="Error"` = 1.
- A retargeted `spec.secretRef` leaves no orphaned series.
- `CollectAndCompare` against expected exposition text, pinning metric
  names and label sets exactly. This is what would have caught defect 4.

**envtest** (`internal/controller/monitor_controller_test.go`): a reconcile
produces all three series; deleting the Monitor removes all three.

**Rule tests**: `promtool check rules` plus `promtool test rules` against a
fixture. This guards the defect-4 class directly — today the rules are
syntactically valid, match zero series, and nothing in CI notices. Requires
adding `promtool` to the tool downloads in `makefiles/common.mk`; accepted
as part of this work.

**e2e**: assert the Prometheus target is up and a series is queryable, gated
on the Kind monitoring stack being present.

Coverage remains governed by `make check-coverage` against
`.github/.testcoverage-local.yml`.

## Accepted trade-offs

- The error-state behaviour change (§1) alters observable behaviour rather
  than only fixing a defect.
- `promtool` (§5) adds a tool download to the build.
- `insecureSkipVerify: true` persists until a follow-up introduces
  cert-manager-issued serving certificates. Note that the same
  `arbitraryFSAccessThroughSMs: deny` constraint will apply to that work:
  under UWM the CA must arrive via `tlsConfig.ca.secret`, not `caFile`.
- A long-lived ServiceAccount token is stored in a Secret (§2), rather than
  using a projected, auto-rotating token. Prometheus Operator's
  `authorization.credentials` requires a Secret reference.

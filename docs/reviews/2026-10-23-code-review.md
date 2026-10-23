# Code Review: Expiring Secrets Operator

| | |
| --- | --- |
| Date | 2026-10-23 |
| Commit | `b67f235` on `master` (clean tree) |
| Scope | Whole repository: Go, CRD, manifests, packaging, build, CI |
| Companion | [Security review](2026-10-23-security-review.md) |

## Summary

The operator is well structured for its size. It uses `controller-runtime`
correctly for the basics (manager, cached client, status subresource,
predicates), the metrics design is sound, and the test pyramid is
unusually complete for a small project: an `envtest` controller suite, a
metrics contract suite, `promtool` unit tests for the alert rules, and two
Kind-based end-to-end suites (Kustomize and Helm).

Two defects deserve attention before the next release:

- **C-01** The reconciler keeps per-request state in struct fields and the
  Secret-to-Monitor mapping function writes to the same fields from the
  informer `goroutine`. The race detector confirms a data race.
- **C-02** A Monitor that enters the `Error` state is never re-evaluated on
  its own. Fixing the `validUntil` label on the Secret does not trigger a
  reconcile either, so a user who corrects a typo sees no change until the
  operator restarts.

The remaining findings are design improvements (CRD defaulting and
validation, the finalizer, condition bookkeeping), scalability, and
hygiene. None block a release on their own.

| ID | Severity | Finding |
| --- | --- | --- |
| C-01 | High | Reconciler shares request state across `goroutines` |
| C-02 | High | `Error` state is sticky; label-only Secret edits are ignored |
| C-03 | Medium | Finalizer only protects in-memory metrics, blocks deletion |
| C-04 | Medium | Controller writes defaults into `spec` |
| C-05 | Medium | CRD lacks ordering and string validation |
| C-06 | Medium | Status conditions go stale |
| C-07 | Medium | Every Secret event in the cluster lists every Monitor |
| C-08 | Low | Expiry date is interpreted as start of day |
| C-09 | Low | Dead code and scaffolding left in the API package |
| C-10 | Low | Info-level log noise on every reconcile |
| C-11 | Low | Test suite gaps and weak specs |
| C-12 | Low | Documentation drifted from the code |
| C-13 | Low | OLM catalog path is stale and self-inconsistent |
| C-14 | Low | Helm post-processing warns instead of failing |
| C-15 | Low | Local tooling is tied to one OS and architecture |
| C-16 | Low | `go.mod` is not tidy |
| C-17 | Low | Build flags and `get-pod-logs` target |
| C-18 | Info | No alert covers the operator itself being down |

## Findings

### C-01 Reconciler shares request state across `goroutines` (High)

> Fixed in PR #49.

**Where:** `internal/controller/monitor_controller.go` lines 46-56
(struct), 83-95 (`Reconcile`), 408-410 (`mapSecretToMonitor`).

**What:** `MonitorReconciler` stores `ctx`, `log`, `output` and `original`
as fields and every method reads them. `Reconcile` assigns them at the top
of each call. `mapSecretToMonitor`, which `controller-runtime` invokes from
the Secret informer's event-handler `goroutine`, also assigns `r.ctx` and
`r.log`. Nothing synchronises the two.

**Why it matters:** A Secret event arriving while a reconcile is in flight
swaps the context and logger of that reconcile underneath it. Today the visible
effect is mostly lost log context, but any future move to
`MaxConcurrentReconciles > 1` would make two reconciles overwrite each
other's `output` object and patch the wrong Monitor's status.

**Evidence:** A throwaway test that calls `Reconcile` and
`mapSecretToMonitor` concurrently on one reconciler, run with
`go test -race`, reports:

```text
WARNING: DATA RACE
Write at ... by goroutine 59:
  monitor_controller.go:83   (r.ctx = ctx in Reconcile)
Previous write at ... by goroutine 55:
  monitor_controller.go:409  (r.ctx = ctx in mapSecretToMonitor)
```

Similar reports appear for lines 84 (`r.log`) and 88 (`r.output`).

**Recommendation:** Make the reconciler stateless. Pass `ctx`, the logger
and the Monitor through parameters (or a small per-request struct created
inside `Reconcile`), and have `mapSecretToMonitor` use only its own `ctx`
argument. This also removes the need for the `original` field: use
`client.MergeFrom(monitor.DeepCopy())` at the patch site. Add `-race` to
the unit-test invocation in `common.mk` so a regression is caught.

### C-02 `Error` state is sticky; label-only Secret edits are ignored (High)

> Fixed in PR #51.

**Where:** `monitor_controller.go` line 216 (`handleError` returns an empty
`Result`), lines 479-500 (`secretUpdatePredicate`).

**What:** Two independent choices combine badly:

1. `handleSuccess` sets `RequeueAfter` to one minute, but `handleError`
   returns `ctrl.Result{}`, so nothing schedules another pass. A Monitor
   in `Error` is only revisited when some other event arrives.
1. The Secret update predicate compares only `.data`. The operator reads
   the `expiring-secrets.stakater.com/validUntil` **label**, which lives in
   metadata, so an edit that only changes the label is filtered out.

**Why it matters:** The most common recovery actions never take effect:

- Secret exists but lacks the label. User adds the label. Nothing happens.
- Label has a typo (`2026-13-01`). User fixes it. Nothing happens.
- A transient API error while fetching the Secret puts the Monitor in
  `Error`. It stays there indefinitely.

The Monitor recovers only when the Secret's data changes, the Monitor spec
changes, or the operator restarts. The existing predicate test
(`monitor_controller_test.go` around line 1345) locks in the data-only
comparison, so the gap is covered by a test that asserts the wrong thing.

**Recommendation:**

- In `handleError`, return the same `RequeueAfter: time.Minute` as the
  success path (or return the error for exponential back-off when the cause
  is an API error rather than user input).
- Change `secretUpdatePredicate` to fire when the `validUntil` label value
  changes. Comparing `ResourceVersion` is simpler and also correct once the
  watch is metadata-only (see S-01 in the security review).
- Add a controller test: Secret without label, Monitor goes to `Error`,
  label added, Monitor becomes `Valid` without any other action.

### C-03 Finalizer only protects in-memory metrics, blocks deletion (Medium)

> Fixed in PR #52.

**Where:** `monitor_controller.go` lines 107-111, 228-244;
`config/rbac/role.yaml` (`monitors/finalizers`).

**What:** The only work done in `handleDeletion` is deleting Prometheus
series from the process-local registry. Those series are keyed by Monitor
name and namespace, both of which are available from the reconcile request
even after the object is gone.

**Why it matters:** A finalizer makes every Monitor deletion depend on the
operator being up. If the operator is scaled down, crash-looping, or
uninstalled before its Monitors are removed, `kubectl delete` hangs, and a
namespace containing Monitors sticks in `Terminating`. This is a common
operational complaint with operators and here it buys nothing. It also
forces a spec `Update` on first reconcile (C-04) and the extra RBAC verb.
The reconciliation diagram in the README already describes the intended
behaviour ("Not Found, clean up metrics") but the code does not do it.

**Recommendation:** Remove the finalizer. On `IsNotFound` in `Reconcile`,
call the existing `DeletePartialMatch` cleanup with the request's name and
namespace. Keep one Monitor in the e2e suite that is deleted while the
operator is scaled to zero, then confirm it disappears without help.

### C-04 Controller writes defaults into `spec` (Medium)

> Fixed in PR #52.

**Where:** `monitor_controller.go` lines 113-128, 312-336;
`api/v1alpha1/monitor_types.go` lines 100-123.

**What:** When `spec.alertThresholds` is absent, the controller fills in
30/14/7 and issues an `Update` on the object. The individual fields already
carry `+default` markers, so the API server fills them in whenever the
`alertThresholds` object is present. Only the fully absent case reaches
the controller.

**Why it matters:**

- GitOps tools (Argo CD, Flux) see a permanent diff between the committed
  Monitor and the live one.
- The first reconcile of every Monitor performs a write it does not need,
  and triggers a second reconcile through the spec-changed predicate.
- Any failure of that `Update` is logged as `Conflict updating Monitor
  spec, requeueing` and retried every second (lines 120-121), whatever
  the real cause. An RBAC denial or a validation error produces a tight
  loop with a misleading log line.

**Recommendation:** Add an object-level default so the API server owns it:

```go
// +kubebuilder:default={infoDays:30,warningDays:14,criticalDays:7}
AlertThresholds *AlertThresholds `json:"alertThresholds,omitempty"`
```

Then delete `applyDefaultAlertThresholds`, the `needsUpdate` block, and the
re-fetch. With C-03 done as well, `Reconcile` no longer writes to the main
resource at all.

### C-05 CRD lacks ordering and string validation (Medium)

> Fixed in PR #52.

**Where:** `monitor_types.go` lines 67-123;
`config/crd/bases/expiring-secrets.stakater.com_monitors.yaml`.

**What:**

- Nothing requires `criticalDays < warningDays < infoDays`. With inverted
  values (for example info 7, warning 14, critical 30) the state machine
  in `calculateState` tests `critical` first, so `Info` and `Warning` can
  never occur and the alerts tied to them never fire.
- `spec.service` and `spec.secretRef.name` are required but accept the
  empty string and have no length limit or pattern. An empty name produces
  an `Error` state from the API client instead of a rejection at admission,
  and both values become Prometheus label values without bounds.

**Recommendation:**

```go
// +kubebuilder:validation:XValidation:rule="self.criticalDays < self.warningDays && self.warningDays < self.infoDays"
type AlertThresholds struct { ... }

// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// plus a DNS-1123 subdomain Pattern
Name string `json:"name"`
```

Give `service` a `MinLength=1` and a sensible `MaxLength`. Add a test in
the `api/v1alpha1` suite that creates an inverted-threshold Monitor against
`envtest` and expects rejection.

### C-06 Status conditions go stale (Medium)

> Fixed in PR #52.

**Where:** `monitor_controller.go` lines 155-179, 181-216.

**What:**

- `handleSuccess` sets `SourceAvailable`, `SourceLabelFound` and `Ready` to
  `True`, but never resets `SourceLabelValid`. After a Secret had an
  invalid date and was fixed, `SourceLabelValid=False` remains forever.
- `handleError` with reason `SourceNotAvailable` leaves the two label
  conditions untouched, so they describe a Secret that no longer exists.
- `metav1.Condition.ObservedGeneration` is never set, and
  `status.observedGeneration` is set only on the success path.
- The constant `MonitorStateUnknown` is not in the CRD `enum` (line 144), so
  any future code path that uses it would be rejected by the API server.

**Recommendation:** Decide the full condition set on every reconcile and
write all of them, in both success and error paths. Set
`ObservedGeneration` on each condition and on status in every path. Either
add `Unknown` to the `enum` or delete the constant.

### C-07 Every Secret event in the cluster lists every Monitor (Medium)

> Fixed in PR #51.

**Where:** `monitor_controller.go` lines 408-441, 510-518.

**What:** The operator watches all Secrets cluster-wide. For each create,
update (with changed data) or delete of any Secret, `mapSecretToMonitor`
lists all Monitors from the cache and scans them for a matching reference.

**Why it matters:** Secret churn in a real cluster is high (service account
tokens, cert-manager renewals, Helm release records, CI jobs). The cost is
`O(secrets × monitors)` per unit of time. The list is served from the
cache so it is not an API-server problem, but it is CPU and allocation on
the operator for work that is almost always irrelevant.

**Recommendation:** Register a field index on Monitors keyed by
`<secretNamespace>/<secretName>` (resolving the empty-namespace default at
index time) and query it with `client.MatchingFields`. Combine with the
metadata-only Secret watch described in S-01 of the security review, which
also removes the full-object comparison in the predicate.

### C-08 Expiry date is interpreted as start of day (Low)

**Where:** `monitor_controller.go` line 297, 339-355.

**What:** `time.Parse("2006-01-02", ...)` yields midnight UTC. A token
labelled `validUntil: 2026-03-15` is therefore reported `Expired` from
00:00 UTC on 15 March, while most issuers keep it valid until the end of
that day. The behaviour is conservative, which is the right direction for
an expiry monitor, but it is undocumented and the status message says
"expired on 2026-03-15" for the whole of that day.

**Recommendation:** Document the semantics in the README and the CRD field
description, or parse as end of day (`23:59:59Z`). Either way, add a test
that pins the chosen behaviour.

### C-09 Dead code and scaffolding left in the API package (Low)

> Fixed in PR #52.

**Where:** `monitor_types.go`.

- Lines 23-24: "EDIT THIS FILE! THIS IS SCAFFOLDING" comment.
- Lines 28-50: `+operator-sdk:csv:customresourcedefinitions:type=spec`
  markers on string constants. They have no effect there.
- Line 182: the CSV `resources=` marker claims Monitor owns Pods,
  Deployments, ServiceAccounts and Services. The operator creates none of
  these, so the OLM UI will show misleading "owned resources".
- Lines 163-165: `status.lastSourceResourceVersion` is written and never
  read. Once the API leaves alpha this field is hard to remove.
- `cmd/main.go` lines 95-97: a webhook server is configured although the
  operator registers no webhooks.

**Recommendation:** Remove all of the above. Keep the API surface to what
the controller actually uses.

### C-10 Info-level log noise on every reconcile (Low)

**Where:** `monitor_controller.go` lines 86, 98, 415, 424-426;
`cmd/main.go` lines 72-74.

**What:** Each reconcile logs "Reconciling Monitor", "Is deleted?" and, for
every Secret event, "Mapping Secret to Monitors" with an empty list object,
all at Info level. With the one-minute `RequeueAfter` this is at least
three lines per Monitor per minute, plus one per Secret event in the cluster.
Development-mode logging (`Development: true`) also defaults to debug
level and console encoding in production.

**Recommendation:** Move per-reconcile lines to `V(1)` and per-event
mapping lines to `V(2)`. Set `Development: false` and rely on
`--zap-devel` locally. The security review (S-06) covers the `DPanic`
implication of development mode.

### C-11 Test suite gaps and weak specs (Low)

**Where:** `internal/controller/monitor_controller_test.go`,
`test/utils/utils.go`.

**What:**

- "should handle invalid state" (lines 502-513) and "should handle monitor
  deletion and cleanup metrics" (350-362) assert nothing about the
  behaviour their names describe.
- Line 182 says "15 days should be in Info state" on a 243-day secret that
  expects `Valid`; line 179 says "shows error" while expecting success.
- `h.NsName(...)` is called on a nil `*TestHelper` (lines 135-136, 419).
  It works only because the method ignores its receiver.
- `GenerateMonitor` picks a random service name, so failures are not
  reproducible.
- `utils.Run` calls `os.Chdir`, changing the working directory of the
  whole test process.
- No test covers: label-only Secret update (C-02), inverted thresholds
  (C-05), condition reset (C-06), deletion with the operator down (C-03),
  or concurrent reconcile safety (C-01).
- The unit suite is not run with `-race`.

**Recommendation:** Fix the misleading names, delete or complete the empty
specs, and add the missing scenarios as table-driven `DescribeTable`
entries where they share a shape. Add `-race` to `common-test`.

### C-12 Documentation drifted from the code (Low)

**Where:** `README.md`, `DEPLOY.md`, `config/manifests/patches`.

- README "Check Status" shows a `REGISTRY` column; the CRD prints
  `SERVICE`.
- README says the operator "reconciles PrometheusRule and ServiceMonitor
  resources". It ships them; it does not reconcile them.
- README flowchart shows "Not Found, clean up metrics" and "Error,
  `Requeue`". Neither is implemented (C-02, C-03).
- README requires Kubernetes 1.25+; the CSV sets `minKubeVersion: 1.31.0`
  and `envtest` runs 1.31.0.
- README install examples reference `v0.0.2` (Kustomize) and `0.0.3`
  (Helm) while `VERSION` is 0.0.4.
- `DEPLOY.md` describes `catalog/channels.yaml` entries that do not match
  the file (C-13).

**Recommendation:** Update the README after C-02 and C-03 land so the
diagram matches, and have `make set-version` rewrite the README version
references as well.

### C-13 OLM catalog path is stale and self-inconsistent (Low)

**Where:** `catalog/package.yaml`, `catalog/channels.yaml`,
`generate-catalog-index.sh`, `bundle/metadata/annotations.yaml`.

**What:** The bundle declares package `expiring-secret-operator`;
`package.yaml` declares `expiring-secrets`; `channels.yaml` mixes
`expiring-secrets.v0.0.1` with `expiring-secret-operator.v0.0.2` and stops
at 0.0.2; the index script hard-codes `expiring-secrets.` and
`expiring-secrets-bundle:`. With `VERSION` at 0.0.4 the script's release
check can never match, so no catalog is ever produced. `catalog.Dockerfile`
also builds from `opm:latest`.

**Recommendation:** Either bring the catalog path back in line (one package
name everywhere, entries for every released version, pinned `opm` tag) or
remove it and state in `DEPLOY.md` that Helm and Kustomize are the
supported install paths. Half-maintained release tooling is worse than
none.

### C-14 Helm post-processing warns instead of failing (Low)

**Where:** `hack/helm-overrides/apply.sh` lines 87-93;
`hack/helm-overrides/templates.yaml`.

**What:** The chart is generated at release time by `helmify` and then
patched with string replacements. When a search pattern matches nothing,
the script prints a warning and continues. A renamed resource or a
`helmify` upgrade that changes its output would ship a chart with the
patch silently missing; `helm lint --strict` would still pass.

A second, verified edge case: the metrics-reader ServiceAccount is named
from the `serviceAccountName` helper, but the token Secret's
`kubernetes.io/service-account.name` annotation is rewritten from
`fullname`. They agree only while `serviceAccount.name` is unset.
Rendering with `--set serviceAccount.name=custom-sa` gives:

```text
SA     custom-sa-metrics-reader
TOKEN  myrel-expiring-secret-operator-metrics-reader   (annotation value)
```

The token is never populated and Prometheus scrapes fail with 401, with no
error anywhere in the operator.

**Recommendation:** Make a zero-match pattern a hard failure (exit 1) by
default, with an explicit `optional: true` key for the few patterns that
may legitimately not match. Rewrite the token annotation from the same
helper as the ServiceAccount. Extend `test/e2e_helm` with the metrics
scrape check that `test/e2e` already has.

### C-15 Local tooling is tied to one OS and architecture (Low)

**Where:** `makefiles/common.mk` (`LOCALBIN`, `go-install-tool`,
`GOTOOLCHAIN=go1.25.0`), `bin/`.

**What:** `bin/` on this machine contains Linux ARM64 binaries for
`controller-gen`, `kustomize` and `helmify` (left by a dev container) next
to macOS binaries. `make test` and `make helmify` therefore fail with
"Exec format error" on the host. The `go-install-tool` helper only checks
that a file exists, not that it runs. The Helm download target is also
hard-coded to `linux-amd64`.

**Recommendation:** Key `LOCALBIN` by `$(shell go env GOOS)_$(shell go env
GOARCH)` (the `envtest` layout already does this), or have the helper
verify the binary executes (`$(1) --help >/dev/null`) before trusting it.
Use `go env GOOS/GOARCH` in the Helm download URL.

### C-16 `go.mod` is not tidy (Low)

> Fixed in PR #51.

**Where:** `go.mod` line 100; `api/v1alpha1/crd_printcolumns_test.go`.

**What:** `sigs.k8s.io/yaml` is imported directly by the print-column test
but still listed as `// indirect`. `go mod tidy -diff` is non-empty.
Renovate runs `gomodTidy`, so the next dependency PR will carry an
unrelated `go.mod` hunk.

**Recommendation:** Run `go mod tidy` and commit. Consider adding
`go mod tidy -diff` to `make pre-commit`.

### C-17 Build flags and `get-pod-logs` target (Low)

**Where:** `Dockerfile` line 33; `makefiles/common.mk` lines 285-293.

- `go build -a` forces a full rebuild of the standard library and every
  dependency on each image build. It is a leftover from older scaffolds
  and only costs time. `-trimpath` and `-ldflags="-s -w"` are absent, so
  the binary carries build paths and symbols; no version is stamped in.
- `get-pod-logs` reads `$$ns`, which is never set in that recipe, so the
  pod loop runs against the current context namespace and finds nothing.
  The target is used on e2e failure, exactly when the logs matter.

**Recommendation:** Drop `-a`, add `-trimpath -ldflags="-s -w -X
main.version=$(VERSION)"`, and replace `$$ns` with `$(OPERATOR_NS)`.

### C-18 No alert covers the operator itself being down (Info)

**Where:** `config/prometheus/rule.yaml`.

**What:** All five alerts are driven by `expiringsecrets_monitor_state`.
When the operator is down, every series disappears and every alert
resolves. The failure mode that loses all coverage is the one that looks
healthiest.

**Recommendation:** Add a rule on the scrape target, for example:

```yaml
expr: absent(up{job="expiring-secret-operator-controller-manager-metrics-service"})
for: 10m
```

or `up{...} == 0`, with a `promtool` unit test alongside the existing ones
in `test/rules/rule_test.yaml`. The marker line above and the job name in
this snippet exceed 80 columns because neither can be wrapped.

## Positive observations

- Metrics design: state is its own gauge, value gauges carry stable labels
  only, and cleanup uses `DeletePartialMatch` by identity. The regression
  tests for orphaned series are exactly the right shape.
- Alert rules are unit-tested with `promtool`, including negative cases.
- Two end-to-end suites exercise the real install paths, and the Helm one
  deliberately runs on chart-affecting changes only.
- `make verify-version` and the Renovate exclusion for the operator's own
  image close a real release-integrity hole and are well commented.
- Comments throughout explain the *why* of non-obvious choices (printer
  column type, `bearerTokenFile` rejection, cache-only `opm`).
- `golangci-lint` reports zero issues and `go vet` is clean.

## Verification performed

| Check | Result |
| --- | --- |
| `go build ./...` | ok |
| `go vet ./...` | ok |
| `make lint` (golangci-lint v2.9.0, pinned toolchain) | 0 issues |
| `go mod tidy -diff` | one hunk (C-16) |
| Unit suites, native `envtest` 1.31.0 | 4 packages pass, 71.9% coverage |
| Throwaway `-race` test for C-01 | data race reported |
| Chart generation (`helmify` + overrides) | ok, strict lint passes |
| Chart render with custom `serviceAccount.name` | mismatch (C-14) |
| `govulncheck ./...` | 10 reachable findings (see security review) |

The `make test` target could not run on this host because `bin/` holds a
Linux `controller-gen` (C-15). The suites were run directly with native
`envtest` binaries instead (`api/v1alpha1`, `cmd`, `internal/controller`,
`internal/utils`), all green. Coverage is measured across `./...`.

## Suggested order of work

1. C-01 and C-02 together: they touch the same functions and share tests.
1. C-04 then C-03: remove the spec write, then remove the finalizer.
1. C-05 and C-06: validation and conditions, both small and self-contained.
1. C-14: make the chart generation fail loudly before the next release.
1. Everything else as hygiene pull requests.

## Glossary

- **OLM**: Operator Lifecycle Manager, the OpenShift component that
  installs operators from catalogs.
- **CSV**: ClusterServiceVersion, the OLM manifest that describes one
  version of an operator (not comma-separated values).

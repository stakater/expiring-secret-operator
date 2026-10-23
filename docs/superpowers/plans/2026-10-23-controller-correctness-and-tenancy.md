# Controller Correctness and Tenancy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Monitor controller stateless, metadata-only, same-namespace, self-healing and finalizer-free, with defaults and validation owned by the CRD, delivered as a stack of six pull requests.

**Architecture:** The reconciler keeps only its client and scheme; each `Reconcile` builds a `reconcileState` value and passes it to helpers. Pure functions (state calculation, status message, conditions) move to `monitor_status.go`; Secret lookup, parsing, mapping and predicates move to `secret_source.go`. The Secret watch becomes metadata-only with a field index on `spec.secretRef.name`, scoped to the Monitor's namespace. Error outcomes re-check every minute or return the error under a one-minute-capped back-off. The finalizer goes; metric cleanup happens on not-found.

**Tech Stack:** Go (per `go.mod`), controller-runtime v0.23, Kubernetes 0.35 APIs, Ginkgo v2 / Gomega, `envtest` 1.31.0, controller-gen, Operator SDK bundle tooling, Kind for e2e.

**Spec:** `docs/superpowers/specs/2026-10-23-controller-correctness-and-tenancy-design.md`

## Global Constraints

- Branch and commit rules from the global `CLAUDE.md`: never commit to `master`; one branch per PR; Conventional Commit messages; no Jira ID (none exists).
- Stack: each branch is created from the previous branch; each PR is opened with `--base <previous branch>`; after a lower PR merges, retarget the next with `gh pr edit --base master`.
- Before every push: `make lint`, `make test`, and for PRs 2 to 4 also `make test-e2e-dev` on the local Kind cluster. Never target any cluster other than Kind.
- On this Mac `bin/` holds Linux binaries for `controller-gen`, `kustomize` and `helmify`; `make test`, `make manifests` and `make bundle` fail with "Exec format error". Delete `bin/controller-gen*`, `bin/kustomize*` and `bin/helmify*` first so the make targets reinstall native ones, or run `GOTOOLCHAIN=go1.25.0 make lint` and `KUBEBUILDER_ASSETS=$(pwd)/bin/k8s/1.31.0-darwin-arm64 go test -race ./...` directly.
- Functions under 20 lines. Table-driven (`DescribeTable`) where entries share a shape.
- New Go files start with the header in `hack/boilerplate.go.txt`.
- Never read or log Secret `.data`. RBAC may only shrink. Metric names, labels and values are unchanged.
- Coverage gate (`.github/.testcoverage.yml`): 70 % per file, 80 % per package, so every new file needs tests.
- Each PR that closes a finding adds, right under that finding's heading in `docs/reviews/*.md`, the line `> Fixed in PR #n.` in a follow-up commit once the PR number is known.
- Markdown: 80 columns, `markdownlint -c .markdownlint.yaml`, Vale (see the local-tooling note in `docs/reviews/2026-10-23-code-review.md`, C-15, for the Vale setup).
- Exact strings that must stay as they are (e2e asserts them): status messages `Secret is valid until %s`, `Secret expires in less than %d days`, `Secret expired on %s`, `Failed to get source Secret: referenced secret not found`, `Source object does not have any labels, expected %s label`.

## Review Focus

- A Monitor that was `Valid` whose Secret is then deleted: next reconcile must report `Error` / `SourceNotAvailable`, drop both value gauges and keep one `state="Error"` series. Test added to Task 10.
- A Monitor created before its Secret exists: when the Secret appears, the create event must bring the Monitor to `Valid` with no other action. Test added to Task 12 (e2e).
- Two Monitors in different namespaces referencing Secrets with the same name: a Secret event must enqueue only the Monitor in its own namespace. Test added to Task 8.
- An existing Monitor carrying the legacy finalizer and a deletion timestamp: the reconciler must strip the finalizer, let the object go, and return without trying to patch status. Test added to Task 14.
- A status patch that fails with an API error: `Reconcile` must return the error (so it is retried), not swallow it. Test added to Task 10.

---

## Part 0: `docs/operator-review` (PR 0)

### Task 0: Commit the reviews, the design and this plan

**Files:**

- Modify: `docs/superpowers/specs/2026-10-23-controller-correctness-and-tenancy-design.md` (status line)
- Add: `docs/reviews/2026-10-23-code-review.md`, `docs/reviews/2026-10-23-security-review.md`, `docs/superpowers/plans/2026-10-23-controller-correctness-and-tenancy.md`

- [ ] **Step 1: Branch**

```bash
git switch master && git pull --ff-only && git switch -c docs/operator-review
```

- [ ] **Step 2: Set the design status to `Approved 2026-10-23`** in the header table of the design document.

- [ ] **Step 3: Lint the three reviewable documents**

Run: `markdownlint -c .markdownlint.yaml docs/reviews/*.md docs/superpowers/specs/2026-10-23-controller-correctness-and-tenancy-design.md`
Expected: no output. Vale on the same files: `0 errors`.

- [ ] **Step 4: Commit and open the PR**

```bash
git add docs/reviews docs/superpowers
git commit -m "docs: add code and security review and the controller design"
git push -u origin docs/operator-review
gh pr create --base master --title "Add operator review and controller design" \
  --body "Full code and security review of the operator as of b67f235, plus the approved design and plan for the controller correctness and tenancy work. The five PRs that follow stack on this one and cite its findings."
```

---

## Part 1: `refactor/stateless-reconciler` (PR 1, spec D2)

Branch from `docs/operator-review`. No behaviour change.

### Task 1: Prove the data race with a test

**Files:**

- Modify: `makefiles/common.mk:249-253` (`common-test`)
- Test: `internal/controller/monitor_controller_test.go`

- [ ] **Step 1: Add `-race` to the unit-test target** so `go test` in `common-test` reads `go test $(GOOPTS) -race $(PKGS) -coverprofile cover.out -covermode=atomic ...`.

- [ ] **Step 2: Write the failing test** in a new `Context("When reconciling concurrently")`:

```go
It("reconciles and maps Secrets concurrently without a data race", func() {
    // fake client with one labelled Secret and one Monitor referencing it,
    // WithStatusSubresource(&expiringsecretv1alpha1.Monitor{})
    r := &MonitorReconciler{Client: c, Scheme: scheme}
    var wg sync.WaitGroup
    for i := 0; i < 20; i++ {
        wg.Add(2)
        go func() { defer wg.Done(); _, _ = r.Reconcile(ctx, req) }()
        go func() { defer wg.Done(); _ = r.mapSecretToMonitor(ctx, secret) }()
    }
    wg.Wait()
})
```

- [ ] **Step 3: Run it under the race detector and confirm it fails**

Run: `go test -race -count=1 ./internal/controller/ -ginkgo.focus "concurrently"`
Expected: `WARNING: DATA RACE` naming `monitor_controller.go` lines 83, 84, 88 and 409, exit status 1.

### Task 2: Split pure status logic into `monitor_status.go`

**Files:**

- Create: `internal/controller/monitor_status.go`
- Create: `internal/controller/monitor_status_test.go`
- Modify: `internal/controller/monitor_controller.go` (remove the moved methods)

**Interfaces:**

- Produces:
    - `func calculateState(m *expiringsecretv1alpha1.Monitor, validUntil, now time.Time)`
    - `func setStatusMessage(m *expiringsecretv1alpha1.Monitor)`
    - `func setCondition(m *expiringsecretv1alpha1.Monitor, t expiringsecretv1alpha1.MonitorConditionType, status metav1.ConditionStatus, reason, message string)`
    - `func applyDefaultAlertThresholds(m *expiringsecretv1alpha1.Monitor) bool`
    - Constants `secretIsValid`, `secretExpiresIn`, `secretExpiredOn` move here unchanged.

- [ ] **Step 1: Write the failing tests.** Move the existing `DescribeTable("When testing state calculation logic", ...)` and the three `generateStatusMessage` specs under "When testing helper functions" into `monitor_status_test.go`, rewritten to call the free functions. The table entry becomes:

```go
func(daysRemaining int, expected expiringsecretv1alpha1.MonitorState) {
    now := time.Now()
    calculateState(monitor, now.Add(time.Duration(daysRemaining)*24*time.Hour), now)
    Expect(monitor.Status.State).To(Equal(expected))
    setStatusMessage(monitor)
    Expect(monitor.Status.Message).NotTo(BeEmpty())
}
```

Add one entry: `Entry("treats exactly zero seconds remaining as Expired", 0, MonitorStateExpired)`.

- [ ] **Step 2: Run to verify they fail to compile** (`undefined: calculateState`).

- [ ] **Step 3: Implement the four functions** by moving the bodies of `calculateState`, `generateStatusMessage`, `updateCondition` and `applyDefaultAlertThresholds` off the receiver; `calculateState` uses the `now` argument instead of `time.Now()`.

- [ ] **Step 4: Run the package tests and lint**

Run: `go test -race ./internal/controller/ && make lint`
Expected: PASS (the race spec from Task 1 still fails; that is Task 3).

- [ ] **Step 5: Commit** `refactor(controller): move pure status logic to monitor_status.go`

### Task 3: Make the reconciler stateless

**Files:**

- Modify: `internal/controller/monitor_controller.go`
- Create: `internal/controller/secret_source.go` (lookup, parse, mapping, predicates)
- Create: `internal/controller/secret_source_test.go`
- Modify: `internal/controller/monitor_controller_test.go`

**Interfaces:**

- Produces:
    - `type MonitorReconciler struct { client.Client; Scheme *runtime.Scheme }` (no other fields)
    - `type reconcileState struct { ctx context.Context; log logr.Logger; monitor, original *expiringsecretv1alpha1.Monitor }`
    - `func newReconcileState(ctx context.Context, m *expiringsecretv1alpha1.Monitor) *reconcileState` (logger from `log.FromContext(ctx)`, `original = m.DeepCopy()`)
    - `func (r *MonitorReconciler) handleSuccess(s *reconcileState) (ctrl.Result, error)`
    - `func (r *MonitorReconciler) handleError(s *reconcileState, cause error, reason, message string) (ctrl.Result, error)`
    - `func (r *MonitorReconciler) handleDeletion(s *reconcileState) (ctrl.Result, error)`
    - `func (r *MonitorReconciler) getSourceObject(s *reconcileState) (client.Object, error)`
    - `func parseValidUntil(log logr.Logger, obj client.Object) (time.Time, *MonitorErrorReasonMessage)`
    - `func (r *MonitorReconciler) mapSecretToMonitor(ctx context.Context, obj client.Object) []ctrl.Request` (reads nothing from `r` except `r.Client`)

- [ ] **Step 1: Rewrite the specs that reach into the struct.** In `monitor_controller_test.go`: "should skip deletion when finalizer is missing" calls `reconciler.handleDeletion(newReconcileState(ctx, monitor))`; "should return error on source lookup failure" calls `reconciler.getSourceObject(newReconcileState(ctx, monitor))`; "should tolerate metrics update error in handleSuccess" calls `reconciler.handleSuccess(newReconcileState(ctx, monitor))`; "should use unknown message for unknown state" and the three specs under "Can handle invalid values" call `setStatusMessage(monitor)`. Move the two `parseSourceObject` specs to `secret_source_test.go` as `parseValidUntil(logr.Discard(), secret)`.

- [ ] **Step 2: Run to verify compile failure** (`undefined: newReconcileState`).

- [ ] **Step 3: Implement.** Delete the `ctx`, `log`, `output`, `original` fields. `Reconcile` fetches the Monitor, builds the state, and passes it down. Move `getSourceObject`, `parseValidUntil`, `mapSecretToMonitor`, the four predicates and `LabelKey` into `secret_source.go`. `SetupWithManager` stays in `monitor_controller.go`.

- [ ] **Step 4: Run the whole package under `-race`**

Run: `go test -race -count=1 ./internal/controller/`
Expected: PASS, including the concurrency spec from Task 1.

- [ ] **Step 5: Verify, commit, open the PR**

Run: `make lint && make test`
Expected: both pass.

```bash
git add -A internal/controller makefiles/common.mk
git commit -m "refactor(controller): make the reconciler stateless"
git push -u origin refactor/stateless-reconciler
gh pr create --base docs/operator-review --title "Make the reconciler stateless" \
  --body "The reconciler kept per-request state in struct fields and the Secret mapper wrote to them from another goroutine; the race detector confirmed a data race (review C-01). Each reconcile now carries its own state and the unit tests run under -race so it cannot come back. No behaviour change."
```

Then add `> Fixed in PR #n.` under C-01 in the code review, commit `docs: note C-01 fixed`, push.

---

## Part 2: `feat/same-namespace-monitors` (PR 2, spec D1)

Branch from `refactor/stateless-reconciler`.

### Task 4: Remove `secretRef.namespace` from the API

**Files:**

- Modify: `api/v1alpha1/monitor_types.go:83-98`
- Regenerate: `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/`, `config/rbac/role.yaml`, `bundle/`, `config/manifests/bases/`
- Modify: `README.md` (delete the `namespace: default` line in the Monitor example only)
- Test: `api/v1alpha1/crd_printcolumns_test.go` (unchanged, must still pass)

- [ ] **Step 1: Delete the `Namespace` field and its comment from `SecretReference`.** Update the type comment on `SecretReference` to say the Secret is resolved in the Monitor's namespace.

- [ ] **Step 2: Regenerate**

Run: `make manifests generate bundle`
Expected: the CRD no longer lists `secretRef.namespace`; the CSV in `config/manifests/bases` drops its `secretRef.namespace` descriptor; `operator-sdk bundle validate` passes. Commit everything that changed under `api/`, `config/`, `bundle/`.

- [ ] **Step 3: Build and vet**

Run: `go build ./... ; go vet ./...`
Expected: compile errors only in `internal/`, `test/` (fixed by Tasks 5 and 6).

- [ ] **Step 4: Commit** `feat(api)!: drop secretRef.namespace, Secrets are same-namespace only`

### Task 5: Resolve, map and label by the Monitor's namespace

**Files:**

- Modify: `internal/controller/secret_source.go` (`getSourceObject`, `mapSecretToMonitor`)
- Modify: `internal/utils/metrics.go:133-151` (`Labels`)
- Modify: `test/utils/utils.go` (generator signatures)
- Test: `internal/controller/secret_source_test.go`, `internal/controller/monitor_controller_test.go`, `internal/utils/metrics_test.go`

**Interfaces:**

- Produces (test helpers, all callers updated):
    - `func GenerateFullMonitor(ns types.NamespacedName, secretName string, service string, thresholds *expiringsecretv1alpha1.AlertThresholds) *expiringsecretv1alpha1.Monitor`
    - `func GenerateMonitorService(ns types.NamespacedName, secretName string, service string) *expiringsecretv1alpha1.Monitor`
    - `func GenerateMonitor(ns types.NamespacedName, secretName string) *expiringsecretv1alpha1.Monitor`
    - `metrics_test.go` helper `monitorWithStatus(name, namespace, secretName, service string, state MonitorState)`

- [ ] **Step 1: Write the failing tests.**
    - In `secret_source_test.go`, replace the envtest spec "should handle cross-namespace references" and the fake-client spec "should default secret namespace when secretRef namespace is empty" with one fake-client spec: Monitor `m` in namespace `a` referencing `s`; Secret `s` in namespace `b`; `mapSecretToMonitor(ctx, secretInB)` returns an empty slice; `mapSecretToMonitor(ctx, secretInA)` returns exactly `a/m`.
    - In `monitor_controller_test.go`, add an envtest spec "reports SourceNotAvailable for a Secret that only exists in another namespace": namespace `other` with a labelled Secret `shared`; Monitor in `default` referencing `shared`; after one reconcile `Status.State == MonitorStateError`, `Status.ExpiresAt == nil`, condition `SourceAvailable` is `False` with reason `SourceNotAvailable`.
    - In `metrics_test.go`, drop the `secretNamespace` parameter from `monitorWithStatus`; the label-set spec asserts `labels[LabelSecretNamespace] == "ns"` for a Monitor in `ns`.

- [ ] **Step 2: Run to verify failure** (compile errors from the signature changes, then the two behaviour specs fail).

- [ ] **Step 3: Implement.** `getSourceObject` uses `s.monitor.Namespace` only. `mapSecretToMonitor` matches `monitor.Namespace == obj.GetNamespace() && monitor.Spec.SecretRef.Name == obj.GetName()`. `Labels()` sets `LabelSecretNamespace: m.monitor.Namespace`. Update `test/utils/utils.go` generators and every caller (`internal/controller`, `internal/utils`, `test/e2e`, `test/e2e_helm`) to pass `nsSecret.Name`.

- [ ] **Step 4: Run tests and lint**

Run: `make lint && make test`
Expected: PASS.

- [ ] **Step 5: Commit** `feat(controller): resolve the Secret in the Monitor's namespace only`

### Task 6: Replace the cross-namespace e2e spec

**Files:**

- Modify: `test/e2e/e2e_test.go` (context "Monitor Resource Functionality Cross-Namespace")

- [ ] **Step 1: Rewrite the context** as "Monitor cannot see Secrets in other namespaces" with one spec: labelled Secret `cross-ns-secret` in `secret-ns`; Monitor `test-monitor-cross-ns` in `e2e-test` referencing `cross-ns-secret`; `Eventually` `Status.State == MonitorStateError`; then `Expect(monitor.Status.ExpiresAt).To(BeNil())` and the `SourceAvailable` condition is `False` with reason `SourceNotAvailable`. Keep the existing namespace setup and cleanup.

- [ ] **Step 2: Run the e2e suite on Kind**

Run: `make test-e2e-dev`
Expected: all specs pass.

- [ ] **Step 3: Commit, verify, open the PR**

```bash
git commit -am "test(e2e): prove a Monitor cannot see another namespace's Secret"
git push -u origin feat/same-namespace-monitors
gh pr create --base refactor/stateless-reconciler --title "Monitors watch Secrets in their own namespace only" \
  --body "A Monitor could point at a Secret in any namespace, which let any tenant use the operator's cluster-wide read permission to learn whether a Secret exists elsewhere and when it expires (review S-02). Tenants never needed this. The secretRef.namespace field is removed; the Secret is always resolved in the Monitor's namespace. Breaking API change, to be released as 0.1.0."
```

Then `> Fixed in PR #n.` under S-02 in the security review, commit, push.

---

## Part 3: `feat/metadata-only-secret-watch` (PR 3, spec D3 and D4)

Branch from `feat/same-namespace-monitors`.

### Task 7: Metadata-only lookup and label predicate

**Files:**

- Modify: `internal/controller/secret_source.go`
- Test: `internal/controller/secret_source_test.go`

**Interfaces:**

- Produces:
    - `func (r *MonitorReconciler) getSourceObject(s *reconcileState) (*metav1.PartialObjectMetadata, error)`; returns the sentinel `errSecretNotFound = errors.New("referenced secret not found")` on not-found, the raw error otherwise.
    - `func secretUpdatePredicate(e event.UpdateEvent) bool`: true when `e.ObjectOld.GetLabels()[LabelKey] != e.ObjectNew.GetLabels()[LabelKey]`.

- [ ] **Step 1: Write the failing predicate table** replacing "should evaluate secret update predicate":

```go
DescribeTable("secretUpdatePredicate", func(oldLabels, newLabels map[string]string, want bool) {
    old := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Labels: oldLabels}}
    cur := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Labels: newLabels}}
    Expect(secretUpdatePredicate(event.UpdateEvent{ObjectOld: old, ObjectNew: cur})).To(Equal(want))
},
    Entry("label added", nil, map[string]string{LabelKey: "2030-01-01"}, true),
    Entry("label changed", map[string]string{LabelKey: "2030-01-01"}, map[string]string{LabelKey: "2031-01-01"}, true),
    Entry("label removed", map[string]string{LabelKey: "2030-01-01"}, nil, true),
    Entry("unrelated label changed", map[string]string{LabelKey: "2030-01-01", "x": "1"}, map[string]string{LabelKey: "2030-01-01", "x": "2"}, false),
    Entry("no labels either side", nil, nil, false),
)
```

Add a spec: `getSourceObject` against `k8sClient` for an existing Secret returns a `*metav1.PartialObjectMetadata` whose `GetLabels()` carries `LabelKey`; for a missing Secret the error satisfies `errors.Is(err, errSecretNotFound)`.

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement.** `getSourceObject` builds `&metav1.PartialObjectMetadata{}` with `SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))` before `r.Get`. The predicate compares the label values and never touches `.data`.

- [ ] **Step 4: Run tests** `go test -race ./internal/controller/` → PASS.

- [ ] **Step 5: Commit** `feat(controller): read Secret metadata only and watch the validUntil label`

### Task 8: Field index for the Secret-to-Monitor mapping

**Files:**

- Modify: `internal/controller/secret_source.go`, `internal/controller/monitor_controller.go` (`SetupWithManager`)
- Test: `internal/controller/secret_source_test.go`, `internal/controller/monitor_controller_test.go` ("Can be setup with Manager")

**Interfaces:**

- Produces:
    - `const secretRefNameIndex = "spec.secretRef.name"`
    - `func indexMonitorBySecretName(o client.Object) []string` (nil when `SecretRef` is nil)
    - `mapSecretToMonitor` lists with `client.InNamespace(obj.GetNamespace())` and `client.MatchingFields{secretRefNameIndex: obj.GetName()}`.

- [ ] **Step 1: Write the failing tests.** Move all mapping specs to a fake client built with `.WithIndex(&expiringsecretv1alpha1.Monitor{}, secretRefNameIndex, indexMonitorBySecretName)` and make them a table over (monitors, secret) → expected request keys, with entries: one match; no match on name; same name in another namespace (Review Focus 3); two Monitors on one Secret → two requests; list error (errorClient) → nil. Change "Can be setup with Manager" to build the manager with the suite's `cfg` and `ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0"}` so `IndexField` can resolve the REST mapping, and assert `SetupWithManager` succeeds.

- [ ] **Step 2: Run to verify failure** (`MatchingFields` against the un-indexed fake client errors; `secretRefNameIndex` undefined).

- [ ] **Step 3: Implement.** Register the index in `SetupWithManager` before `Complete`; change the `Watches` call to pass `builder.OnlyMetadata`.

- [ ] **Step 4: Run tests** → PASS.

- [ ] **Step 5: Commit** `feat(controller): index Monitors by secretRef.name and map by namespace`

### Task 9: Capped back-off

**Files:**

- Create: `internal/controller/rate_limiter.go`
- Test: `internal/controller/rate_limiter_test.go`
- Modify: `internal/controller/monitor_controller.go` (`SetupWithManager` adds `WithOptions(controller.Options{RateLimiter: newRateLimiter()})`)
- Modify: `go.mod` (`golang.org/x/time` becomes direct; run `go mod tidy`)

**Interfaces:**

- Produces: `func newRateLimiter() workqueue.TypedRateLimiter[reconcile.Request]` = `workqueue.NewTypedMaxOfRateLimiter(` per-item exponential `5*time.Millisecond` to `time.Minute`, bucket `rate.NewLimiter(rate.Limit(10), 100)` `)`.

- [ ] **Step 1: Write the failing test**

```go
It("caps the per-item back-off at one minute", func() {
    l := newRateLimiter()
    req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "m", Namespace: "ns"}}
    var d time.Duration
    for i := 0; i < 40; i++ { d = l.When(req) }
    Expect(d).To(Equal(time.Minute))
})
```

- [ ] **Step 2: Run to verify failure.** **Step 3: Implement.** **Step 4: Run** → PASS.

- [ ] **Step 5: Commit** `feat(controller): cap reconcile back-off at one minute`

### Task 10: Error outcomes and recovery

**Files:**

- Modify: `internal/controller/monitor_controller.go` (`Reconcile`, `handleError`)
- Modify: `internal/controller/monitor_status.go` (reason constants)
- Test: `internal/controller/monitor_controller_test.go`

**Interfaces:**

- Produces:
    - Reason constants in `monitor_status.go`: `ReasonReady = "Ready"`, `ReasonSourceNotAvailable = "SourceNotAvailable"`, `ReasonSourceLabelNotFound = "SourceLabelNotFound"`, `ReasonSourceLabelInvalid = "SourceLabelInvalid"`, `ReasonAPIError = "APIError"`. `parseValidUntil` returns these reasons (the lower-case `sourceLabelNotAvailable` constant goes).
    - `handleError` returns `ctrl.Result{RequeueAfter: time.Minute}, patchErr` for every reason except `ReasonAPIError`, where it returns `ctrl.Result{}, errors.Join(cause, patchErr)`.
    - `func (r *MonitorReconciler) handleSourceError(s *reconcileState, err error) (ctrl.Result, error)`: `errors.Is(err, errSecretNotFound)` → `ReasonSourceNotAvailable`, else `ReasonAPIError`; message `Failed to get source Secret` in both cases.
    - Test double: `errorClient` gains `statusPatchErr error`; its `Status()` returns a `client.SubResourceWriter` whose `Patch` returns that error.

- [ ] **Step 1: Write the failing tests** (envtest unless stated):
    - Table "handleError result by reason": for each of `ReasonSourceNotAvailable`, `ReasonSourceLabelNotFound`, `ReasonSourceLabelInvalid` the result is `RequeueAfter == time.Minute` and `err == nil`; for `ReasonAPIError` with cause `errors.New("boom")` the result is zero and `errors.Is(err, cause)`.
    - "recovers once the missing label is added": Secret without label, Monitor; reconcile → `Error`, message contains `Source object does not have any labels`; `Update` the Secret adding `LabelKey: <future date>` only; reconcile → `Valid`.
    - "drops the value gauges when the Secret disappears" (Review Focus 1): reconcile to `Valid`; delete the Secret; reconcile → `Error`, `testutil.CollectAndCount(utils.SecretValidUntilTimestamp) == 0`, `MonitorStateGauge` has one series with `state="Error"`.
    - "returns the error when the status patch fails" (Review Focus 5): fake client wrapped in `errorClient{statusPatchErr: errors.New("patch failed")}`; `Reconcile` returns an error wrapping it.
    - Update "should return error on source lookup failure" to call `Reconcile` with `errorClient{getErr: ...}` and assert the error is returned and the fetched Monitor's `Status.State == MonitorStateError` (use a second, plain client to read it back).
    - Keep "should requeue when updating spec fails" unchanged (removed in Task 14).

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement** per the Interfaces block. `Reconcile` calls `handleSourceError` on lookup failure and `handleError(s, parseErr, parseErr.Reason, parseErr.Message)` on parse failure.

- [ ] **Step 4: Run** `go test -race ./internal/controller/` → PASS; `make lint` → 0 issues.

- [ ] **Step 5: Commit** `feat(controller): re-check failing Monitors every minute`

### Task 11: Delete the full-object Secret watch leftovers

**Files:**

- Modify: `internal/controller/secret_source.go`, `internal/controller/monitor_controller_test.go`

- [ ] **Step 1: Grep** `grep -rn "corev1.Secret{}" internal/controller/*.go` — the only remaining production use must be the `Watches(&corev1.Secret{}, ..., builder.OnlyMetadata, ...)` registration. Replace any other with `PartialObjectMetadata`. Delete the spec "should return nil when context is cancelled" (it asserted nothing meaningful).

- [ ] **Step 2: Run** `make lint && make test` → PASS. **Step 3: Commit** `refactor(controller): remove full-object Secret reads`

### Task 12: e2e for recovery through the real watch

**Files:**

- Modify: `test/e2e/e2e_test.go` ("Monitor Resource Functionality" context)

- [ ] **Step 1: Add two specs.**
    - "recovers when the validUntil label is added later": create a Secret with payload and no label, then the Monitor; `Eventually` `Error`; `Get` the Secret, set `Labels[utils.ValidUntilLabel]` to a date 365 days out, `Update`; `Eventually` `Valid` within the suite `timeout`.
    - Extend "should handle missing secrets gracefully" (Review Focus 2): after asserting `Error`, create the labelled Secret; `Eventually` `Valid`.

- [ ] **Step 2: Run** `make test-e2e-dev` → PASS.

- [ ] **Step 3: Commit, verify, open the PR**

```bash
git commit -am "test(e2e): Monitors recover when the Secret or its label appears"
git push -u origin feat/metadata-only-secret-watch
gh pr create --base feat/same-namespace-monitors --title "Metadata-only Secret watch and self-healing error states" \
  --body "The operator cached every Secret in the cluster, payload included, in a pod with a 128 MiB limit (review S-01), and a Monitor in Error stayed there until something unrelated happened because the watch ignored label-only edits and the error path never re-queued (review C-02). The watch now stores Secret metadata only, fires on changes to the validUntil label, maps through a namespace-scoped index (C-07), and every error re-checks within a minute. Trade-off: API-server errors use the controller's back-off, capped at one minute instead of the default 1000 s."
```

Then `> Fixed in PR #n.` under S-01, C-02 and C-07; commit; push.

---

## Part 4: `refactor/crd-owned-defaults` (PR 4, spec D5, D6, D7, D9)

Branch from `feat/metadata-only-secret-watch`.

### Task 13: CRD defaults, validation and API tidy-up

**Files:**

- Modify: `api/v1alpha1/monitor_types.go`
- Regenerate: `api/v1alpha1/zz_generated.deepcopy.go`, `config/crd/bases/`, `bundle/`, `config/manifests/bases/`
- Modify: `internal/utils/metrics.go` (no change needed unless it references removed fields)
- Create: `internal/controller/crd_validation_test.go` (envtest, reuses the suite's `k8sClient`; layout is the builder's choice per the spec, this file keeps one `envtest` bootstrap)

**Interfaces:**

- Produces, in `monitor_types.go`:
    - On `MonitorSpec.AlertThresholds`: `// +kubebuilder:default={infoDays:30,warningDays:14,criticalDays:7}`
    - On `type AlertThresholds`: `// +kubebuilder:validation:XValidation:rule="self.criticalDays < self.warningDays && self.warningDays < self.infoDays",message="alertThresholds must satisfy criticalDays < warningDays < infoDays"`
    - On `MonitorSpec.Service`: `MinLength=1`, `MaxLength=253`
    - On `SecretReference.Name`: `MinLength=1`, `MaxLength=253`, `Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$``
    - Removed: `MonitorStatus.LastSourceResourceVersion`, `MonitorStateUnknown`, the two scaffold comment lines, every `+operator-sdk:csv:customresourcedefinitions:type=spec` marker on the `MonitorState` constants; the `resources=` marker becomes `{{Secret,v1,""}}`.

- [ ] **Step 1: Write the failing admission table** in `crd_validation_test.go` (`specWith`, `specWithService`, `specWithSecretName` and `uniqueName` are small test-local helpers the builder writes):

```go
DescribeTable("Monitor admission", func(spec expiringsecretv1alpha1.MonitorSpec, wantErr bool, want *expiringsecretv1alpha1.AlertThresholds) {
    m := &expiringsecretv1alpha1.Monitor{ObjectMeta: metav1.ObjectMeta{Name: uniqueName(), Namespace: "default"}, Spec: spec}
    err := k8sClient.Create(ctx, m)
    if wantErr { Expect(err).To(HaveOccurred()); return }
    Expect(err).NotTo(HaveOccurred())
    DeferCleanup(func() { _ = k8sClient.Delete(ctx, m) })
    Expect(m.Spec.AlertThresholds).To(Equal(want))
},
    Entry("no thresholds are defaulted to 30/14/7", specWith(nil), false, &AlertThresholds{30, 14, 7}),
    Entry("empty thresholds object is defaulted", specWith(&AlertThresholds{}), false, &AlertThresholds{30, 14, 7}),
    Entry("partial thresholds keep the given value", specWith(&AlertThresholds{CriticalDays: 3}), false, &AlertThresholds{30, 14, 3}),
    Entry("inverted thresholds are rejected", specWith(&AlertThresholds{InfoDays: 7, WarningDays: 14, CriticalDays: 30}), true, nil),
    Entry("critical above the default warning is rejected", specWith(&AlertThresholds{CriticalDays: 20}), true, nil),
    Entry("empty service is rejected", specWithService(""), true, nil),
    Entry("empty secret name is rejected", specWithSecretName(""), true, nil),
    Entry("upper-case secret name is rejected", specWithSecretName("Bad-Name"), true, nil),
)
```

- [ ] **Step 2: Run to verify failure** (defaults absent, invalid specs accepted).

- [ ] **Step 3: Apply the markers and removals; regenerate**

Run: `make manifests generate bundle`
Expected: CRD gains the object default, the `x-kubernetes-validations` rule and the string limits; `bundle validate` passes.

- [ ] **Step 4: Run** `make test` → PASS (the controller still compiles; `LastSourceResourceVersion` assignment in `Reconcile` is removed).

- [ ] **Step 5: Commit** `feat(api)!: CRD-owned defaults and validation; drop unused fields`

### Task 14: Remove the finalizer and the spec write

**Files:**

- Modify: `internal/controller/monitor_controller.go`, `internal/controller/monitor_status.go` (delete `applyDefaultAlertThresholds`)
- Modify: `internal/utils/metrics.go`
- Test: `internal/utils/metrics_test.go`, `internal/controller/monitor_controller_test.go`

**Interfaces:**

- Produces:
    - `func CleanupMonitor(key types.NamespacedName) int` in `internal/utils/metrics.go`: `DeletePartialMatch` on all three vectors with `{monitor_name: key.Name, monitor_namespace: key.Namespace}`, returns the number of series removed. `(*Metric).Cleanup()` delegates to it.
    - `const legacyFinalizer = "expiring-secrets.stakater.com/monitor-finalizer"` (the `monitorFinalizer` constant is renamed; nothing adds it).
    - `func (r *MonitorReconciler) stripLegacyFinalizer(s *reconcileState) (bool, error)`: when `controllerutil.RemoveFinalizer` reports a change, `Update` and return `true`.
    - `Reconcile` order: fetch → not found: `utils.CleanupMonitor(req.NamespacedName)`, return → `stripLegacyFinalizer` → if `DeletionTimestamp != nil` return `ctrl.Result{}` → `s.monitor.Status.ObservedGeneration = s.monitor.Generation` → source lookup and the rest. `handleDeletion` is deleted.

- [ ] **Step 1: Write the failing tests.**
    - `metrics_test.go`: "CleanupMonitor removes every series for the key and returns their count" (publish a Monitor's three series, `CleanupMonitor` returns 3, counts are 0; another Monitor's series untouched).
    - `monitor_controller_test.go` (fake client unless stated):
        - "cleans up metrics when the Monitor is gone": publish series for `ns/m`; `Reconcile` for a non-existent `ns/m` → no error, counts 0.
        - "strips the legacy finalizer": Monitor with `legacyFinalizer`; after `Reconcile`, `Get` shows no finalizers and `Status.State` populated.
        - "lets a deleting Monitor with the legacy finalizer go" (Review Focus 4): Monitor with `legacyFinalizer` and `DeletionTimestamp` set; `Reconcile` returns `(ctrl.Result{}, nil)`; `Get` returns not-found.
        - envtest "never writes the spec": create a Monitor with no thresholds; immediately after `Create` `Spec.AlertThresholds` equals 30/14/7 and `Generation == 1`; after one reconcile `Generation` is still 1 and `ResourceVersion` differs only because of status (compare `Spec` deep-equal to the pre-reconcile spec).
        - envtest "deletes without the operator": create and reconcile a Monitor; `Delete` it; `Eventually` not-found with no further reconcile.
    - Delete the specs "should requeue when updating spec fails", "should skip deletion when finalizer is missing", "should return error when finalizer removal update fails", "should remove finalizer on deletion" and "should handle failing to add finalizer"; delete the `F:` reconcile hook in `CleanupResources` calls that only existed to strip the finalizer.

- [ ] **Step 2: Run to verify failure.** **Step 3: Implement** per Interfaces. **Step 4: Run** `make test` → PASS.

- [ ] **Step 5: Commit** `feat(controller)!: drop the finalizer; clean up metrics on not-found`

### Task 15: Conditions table

**Files:**

- Modify: `internal/controller/monitor_status.go`, `internal/controller/monitor_controller.go` (`handleSuccess`, `handleError` call `applyConditions`)
- Test: `internal/controller/monitor_status_test.go`

**Interfaces:**

- Produces:
    - `type conditionSet struct { Ready, SourceAvailable, SourceLabelFound, SourceLabelValid metav1.ConditionStatus }`
    - `func conditionsFor(reason string) conditionSet` implementing the spec D7 table (`ReasonReady` → all True; `ReasonSourceNotAvailable` → False, False, Unknown, Unknown; `ReasonSourceLabelNotFound` → False, True, False, Unknown; `ReasonSourceLabelInvalid` → False, True, True, False; `ReasonAPIError` → False, Unknown, Unknown, Unknown).
    - `func applyConditions(m *expiringsecretv1alpha1.Monitor, reason, message string)`: writes all four with `ObservedGeneration: m.Generation`; a `True` condition carries its own type name as reason and a fixed message; any other status carries `reason` and `message`.

- [ ] **Step 1: Write the failing table** over the five reasons asserting the four statuses, and one spec asserting `ObservedGeneration` equals `m.Generation` on every condition and that a second `applyConditions` with a different reason leaves exactly four conditions.

- [ ] **Step 2: Run to verify failure.** **Step 3: Implement**; `setCondition` from Task 2 gains the `ObservedGeneration` field. **Step 4: Run** → PASS.

- [ ] **Step 5: Commit** `fix(controller): write every condition on every reconcile`

### Task 16: e2e deletion without the operator

**Files:**

- Modify: `test/e2e/e2e_test.go`

- [ ] **Step 1: Hoist the metrics fetch helper.** The `curl` closure inside the "Prometheus Metrics" context becomes a package-level `fetchMetrics() string` that creates the cluster role binding and token, runs the curl pod and returns the body, so more than one context can use it.

- [ ] **Step 2: Add the spec** "can be deleted while the operator is down" in a new `Ordered` context:
        - create a labelled Secret and a Monitor; `Eventually` `Valid`;
        - `kubectl -n expiring-secret-operator-system scale deploy/expiring-secret-operator-controller-manager --replicas=0` then `kubectl wait --for=delete pod -l control-plane=controller-manager -n expiring-secret-operator-system --timeout=90s`;
        - `k8sClient.Delete` the Monitor; `Eventually` `apierrors.IsNotFound` on `Get` within 30 s;
        - scale back to 1 and `kubectl rollout status` it;
        - assert the body of `fetchMetrics()` does not contain the label pair `monitor_name="NAME"` for the deleted Monitor.

- [ ] **Step 3: Run** `make test-e2e-dev` → PASS.

- [ ] **Step 4: Commit** `test(e2e): Monitors delete cleanly while the operator is down`

### Task 17: RBAC trim

**Files:**

- Modify: `internal/controller/monitor_controller.go:74-77` (markers)
- Modify: `config/rbac/leader_election_role.yaml`
- Regenerate: `config/rbac/role.yaml`, `bundle/`

- [ ] **Step 1: Set the markers** to `monitors: get;list;watch;update;patch`, `monitors/status: get;update;patch`, `secrets: get;list;watch`; delete the `monitors/finalizers` marker. Reduce the leader-election Role to the `coordination.k8s.io/leases` rule only.

- [ ] **Step 2: Regenerate and diff**

Run: `make manifests bundle && git diff --stat config bundle`
Expected: `role.yaml` loses `create`, `delete` and the finalizers rule; the bundle CSV's `clusterPermissions` and `permissions` match.

- [ ] **Step 3: Run e2e** `make test-e2e-dev` → PASS (proves the trimmed role is enough, including leader election).

- [ ] **Step 4: Commit, verify, open the PR**

```bash
git commit -am "chore(rbac): grant only what the controller uses"
git push -u origin refactor/crd-owned-defaults
gh pr create --base feat/metadata-only-secret-watch --title "CRD-owned defaults, no finalizer, complete conditions" \
  --body "The controller wrote defaults into spec (GitOps drift, review C-04), carried a finalizer whose only job was in-memory metric cleanup and which blocked deletion whenever the operator was down (C-03), and left stale conditions behind (C-06). Defaults and validation now live in the CRD, including an ordering rule for the thresholds (C-05); the finalizer is gone and metrics are cleaned on not-found; all four conditions are written every time. RBAC shrinks to what is used (S-09). Breaking: status.lastSourceResourceVersion and the finalizer are removed."
```

Then `> Fixed in PR #n.` under C-03, C-04, C-05, C-06, C-09, S-09; commit; push.

---

## Part 5: `chore/logging-and-docs` (PR 5, spec D8)

Branch from `refactor/crd-owned-defaults`.

### Task 18: Production logging defaults

**Files:**

- Modify: `cmd/main.go:72-74`
- Modify: `internal/controller/monitor_controller.go`, `internal/controller/secret_source.go`
- Test: `internal/controller/secret_source_test.go`

- [ ] **Step 1: Write the failing test** using `github.com/go-logr/logr/funcr`:

```go
It("never logs the Secret's label map", func() {
    var lines []string
    log := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{Verbosity: 2})
    secret := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "s", Labels: map[string]string{"team": "x"}}}
    _, _ = parseValidUntil(log, secret)
    Expect(strings.Join(lines, "\n")).NotTo(ContainSubstring("team"))
    Expect(strings.Join(lines, "\n")).To(ContainSubstring("labelPresent"))
})
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement.** `zap.Options{}` in `main.go` (development off; `--zap-devel` still works). "Reconciling Monitor" and friends go to `log.V(1)`, the mapping line to `log.V(2)`; the "Is deleted?" line is deleted; `parseValidUntil` logs `"labelPresent", exists` and never the map.

- [ ] **Step 4: Run** `make lint && make test` → PASS. **Step 5: Commit** `fix(logging): production defaults and no label dumps`

### Task 19: README changes tied to behaviour

**Files:**

- Modify: `README.md`

- [ ] **Step 1: Edit.** In "Create a Monitor Resource" add one sentence: the Secret must be in the same namespace as the Monitor. In "Check Status" change the `REGISTRY` column to `SERVICE`. In the reconciliation flowchart: the not-found branch reads "Clean up metrics" (now true), every error branch ends in "Status: Error, re-check in 1 minute", and the "Apply default alert thresholds" node is removed.

- [ ] **Step 2: Lint** `markdownlint -c .markdownlint.yaml README.md` and Vale → clean.

- [ ] **Step 3: Commit, verify, open the PR**

```bash
git commit -am "docs: describe same-namespace rule and the new error handling"
git push -u origin chore/logging-and-docs
gh pr create --base refactor/crd-owned-defaults --title "Production logging defaults and README updates" \
  --body "Development-mode logging was the compiled-in default, which turns DPanic into a crash and dumps every label of a referenced Secret into the logs (review S-06, C-10). Logging now defaults to production settings and records only whether the expected label was present. The README reflects the same-namespace rule and the error handling introduced in the PRs below this one."
```

Then `> Fixed in PR #n.` under S-06 and C-10, and a note under C-12 listing what this PR fixed; commit; push.

---

## After the stack

- Merge bottom-up. After each merge, `gh pr edit <next> --base master` and rebase the remaining branches.
- Release 0.1.0 with `RELEASING.md`, listing as breaking: `secretRef.namespace` removed, `status.lastSourceResourceVersion` removed, finalizer removed, thresholds now validated for ordering.

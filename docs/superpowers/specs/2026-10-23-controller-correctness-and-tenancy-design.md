# Controller Correctness and Tenancy: Design

| | |
| --- | --- |
| Date | 2026-10-23 |
| Status | Approved 2026-10-23 |
| Source | Review findings C-01..C-07, C-09, C-10, S-01, S-02, S-06, S-09 |
| Follow-ups | Supply chain and CI; metrics transport; packaging and docs |

## Intent

The operator is installed once, cluster-wide, by a cluster administrator.
Tenants then create a `Monitor` in their own namespace and get expiry
status and metrics without installing anything. That model is sound. The
review found that the controller implementing it has a data race, cannot
recover from the most common user mistakes, holds every Secret in the
cluster in memory, and lets a tenant read Secret metadata in namespaces
they do not own.

This design fixes the controller so that it is safe to run on a shared
cluster and boring to operate: stateless reconciles, a watch that sees
only metadata, a strict same-namespace rule, self-healing error states,
no finalizer, and an API whose defaults and validation live in the CRD.

## Goals

- A tenant's Monitor can only ever observe a Secret in the tenant's own
  namespace.
- The operator process never holds Secret payloads.
- Every error state recovers on its own once the cause is fixed, within
  one minute, with no operator restart.
- Deleting a Monitor or its namespace never depends on the operator being
  up.
- The reconciler is safe under `go test -race` and under
  `MaxConcurrentReconciles > 1`.
- Defaults and validation are enforced by the API server, so GitOps tools
  see no drift and bad input is rejected at admission.
- The metrics contract (names, labels, values) is unchanged.

## Non-goals

- Serving certificates for the metrics endpoint, the NetworkPolicy, and
  the long-lived scrape token (metrics transport design).
- Dependency bumps, vulnerability scanning, pinning of release tooling,
  workflow permissions (supply chain and CI design).
- Helm post-processing strictness, the OLM catalog, README cleanups not
  tied to changed behaviour, build flags (packaging and docs design).
- A new API version. Changes land in `v1alpha1` in place.
- Any support for cross-namespace references, opt-in or otherwise.

## Anti-goals

These would make the work a failure even if every test passed:

- Reading or logging Secret `.data` anywhere, including in tests.
- Widening RBAC. The ClusterRole may only shrink.
- Changing a metric name, label set, or value semantics. The shipped
  `PrometheusRule` and any tenant dashboards depend on them.
- Leaving any Monitor impossible to delete, including ones created by
  the current release.
- Touching any cluster other than the local Kind cluster.

## Constraints

- Development approach from `CLAUDE.md`: design first, tests before
  code, Ginkgo/Gomega with `envtest`, small increments.
- Code style from the global `CLAUDE.md`: functions under 20 lines,
  table-driven tests where entries share a shape.
- Delivery as a stack of pull requests, each green on its own, each
  targeting the one below it.
- The reviews must stay accurate: when a PR closes a finding, it says so
  in the description, and the review document gets a one-line "fixed in
  PR #n" note in the same PR.
- No live installations exist, so no upgrade path is required beyond the
  finalizer safety net below.

## Decisions

### D1. Same-namespace only

`spec.secretRef.namespace` is removed from the API. The Secret is always
resolved in the Monitor's namespace. The CRD, the generated deep-copy,
the sample, the CSV descriptors, the README example and the end-to-end
suite all drop the field.

The `secret_namespace` metric label stays and always equals
`monitor_namespace`. Removing it would change the contract for no gain.

A new end-to-end spec creates a labelled Secret in namespace A and a
Monitor named after it in namespace B, and asserts the Monitor reports
`Error` with reason `SourceNotAvailable` and never populates
`status.expiresAt`.

### D2. Stateless reconciler

`MonitorReconciler` keeps only `client.Client` and `Scheme`. `Reconcile`
builds a per-request value holding the context, the logger, the fetched
Monitor and a deep copy taken before any mutation, and passes it to the
helpers. The Secret mapping function uses only its arguments. Nothing on
the reconciler is written after construction.

A unit test calls `Reconcile` and the mapping function concurrently on
one reconciler and must pass under `-race`. The `common-test` target
gains `-race` permanently.

### D3. Metadata-only Secret watch

The Secret watch is registered with `builder.OnlyMetadata`, and the
lookup reads a `metav1.PartialObjectMetadata` with the Secret GVK set.
The informer cache then stores `ObjectMeta` only. No label selector is
applied to the cache (my call), so a Secret without the label still
produces the specific "label missing" error rather than "not found".
The cached Secret metadata is stored without annotations and managed
fields, so a `last-applied-configuration` annotation cannot carry the
payload into memory.

The mapping function queries a field index instead of listing every
Monitor. The index key is `spec.secretRef.name`, and the query is scoped
with `client.InNamespace(secret.Namespace)`. This relies on D1 having
landed first, which is why D1 precedes D3 in the delivery order (my
call); the index is then born namespace-scoped and never needs a
`<namespace>/<name>` key. Tests using the fake client register the same
index.

### D4. Error recovery

The Secret update predicate fires when the value of the
`expiring-secrets.stakater.com/validUntil` label differs between old and
new objects. It no longer reads `.data`. Create and delete events still
always fire.

Reconcile outcomes and what they return (my call on the cadence):

| Outcome | Result |
| --- | --- |
| Success | `RequeueAfter: 1m` |
| Secret not found, label missing, label malformed | `RequeueAfter: 1m` |
| Any other API error (Get, List, Patch) | return the error |

Returning the error lets `controller-runtime` apply its rate-limited
back-off. So that the "within one minute" goal also holds once an API
problem clears, `SetupWithManager` sets `controller.Options.RateLimiter`
to a per-item exponential limiter capped at one minute (my call); the
default cap of 1000 seconds would otherwise leave a Monitor waiting up to
a quarter of an hour after a short outage, long enough to trip the
`SecretMonitorError` alert. User-input errors poll at the success cadence
because the label watch will usually get there first and the poll is the
safety net.

A controller test covers each row: in particular, a Secret without the
label, then the label added with no other change, must move the Monitor
from `Error` to `Valid`. A unit test asserts the rate limiter's cap.

### D5. No finalizer

The finalizer is removed. When `Reconcile` gets `NotFound` for a Monitor,
it deletes that Monitor's metric series using the request's name and
namespace; the metrics package gains an entry point that needs only
those two values.

Safety net (my call, since no installation is known): if a fetched
Monitor still carries `expiring-secrets.stakater.com/monitor-finalizer`,
the reconciler removes it with an `Update` and continues. This is a few
lines and may be deleted at any later release.

An end-to-end spec scales the controller Deployment to zero, deletes a
Monitor, asserts it is gone, then scales back up and asserts its series
are absent from `/metrics`.

### D6. API defaults and validation

- `alertThresholds` gets an object-level default of 30/14/7. The
  per-field defaults stay so a partially specified object is completed.
  `applyDefaultAlertThresholds`, the spec `Update`, and the re-fetch are
  deleted. The controller never writes to the main resource except for
  the D5 safety net.
- `AlertThresholds` gets a validation rule requiring
  `criticalDays < warningDays < infoDays`, with a message that says so.
- `spec.service`: `MinLength=1`, `MaxLength=253`.
- `spec.secretRef.name`: `MinLength=1`, `MaxLength=253`, DNS-1123
  subdomain pattern.
- `status.lastSourceResourceVersion` is removed.
- `MonitorStateUnknown` is removed; the `enum` stays as is.
- Scaffold comments and the misplaced CSV markers on constants are
  removed. The CSV `resources=` marker lists only `Secret`.

An `api/v1alpha1` suite against `envtest` asserts: inverted thresholds
are rejected, empty `service` and empty `secretRef.name` are rejected, a
Monitor with no `alertThresholds` comes back with 30/14/7 filled in.

### D7. Conditions

All four conditions are written on every reconcile, with
`ObservedGeneration` set on each and `status.observedGeneration` set in
every path. Reasons are stable identifiers.

| Outcome | Ready | SourceAvailable | SourceLabelFound | SourceLabelValid |
| --- | --- | --- | --- | --- |
| Valid, Info, Warning, Critical, Expired | True | True | True | True |
| Secret not found | False | False | Unknown | Unknown |
| Label missing | False | True | False | Unknown |
| Label malformed | False | True | True | False |
| Other API error | False | Unknown | Unknown | Unknown |

`status.state` and `status.message` keep their current meaning.

### D8. Logging

`zap.Options{Development: false}` becomes the compiled-in default;
`--zap-devel` enables development mode locally. Per-reconcile lines move
to `V(1)`, per-Secret-event mapping lines to `V(2)`. The reconciler logs
whether the expected label key was present, never the label map.

### D9. RBAC

The RBAC markers and `config/rbac/leader_election_role.yaml` shrink to:

- `monitors`: `get, list, watch, update, patch` (`update` and `patch`
  remain only for the D5 safety net; drop them when it goes).
- `monitors/status`: `get, update, patch`.
- `monitors/finalizers`: removed.
- `secrets`: `get, list, watch` (unchanged; required for the watch).
- leader election: `leases` only; `configmaps` and `events` removed.

`make manifests` regenerates the ClusterRole and the bundle copies.

### D10. Delivery

One stack of pull requests, in this order. Each leaves `make test` (with
`-race`), `make lint` and `make test-e2e` green. There is no Jira work
item for this work, so the branch names below are final.

1. `docs/operator-review`: the two review documents and this design,
   with its status set to approved. Nothing else, so the stack above it
   can cite the findings and leave "fixed in PR #n" notes (my call). Both
   reviews already pass the repository's `markdownlint` and Vale
   configuration.
1. `refactor/stateless-reconciler`: D2. No behaviour change.
1. `feat/same-namespace-monitors`: D1. Second, so that the index in D3 is
   namespace-scoped from the start.
1. `feat/metadata-only-secret-watch`: D3 and D4. First behaviour change
   visible to tenants: error recovery.
1. `refactor/crd-owned-defaults`: D5, D6, D7, D9.
1. `chore/logging-and-docs`: D8, plus the README changes that describe
   changed behaviour (reconciliation diagram, same-namespace rule,
   printer columns).

The next release after the stack merges is 0.1.0, cut with the existing
`RELEASING.md` procedure, with the removed fields and the finalizer
change listed as breaking.

## Left to the builder

- The shape and name of the per-request value in D2, and how helpers
  receive it.
- Whether `MonitorErrorReasonMessage` survives or becomes plain error
  values with a reason.
- Exact test file layout and which specs become `DescribeTable` entries.
- How the end-to-end suite scales the Deployment and waits (D5).
- Wording of condition messages and the validation-rule message.

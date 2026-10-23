# Security Review: Expiring Secrets Operator

| | |
| --- | --- |
| Date | 2026-10-23 |
| Commit | `b67f235` on `master` (clean tree) |
| Scope | Controller, RBAC, manifests, image build, release tooling, CI |
| Companion | [Code review](2026-10-23-code-review.md) |

## Summary

The operator's own attack surface is small: no webhooks, no inbound API
other than an authenticated metrics endpoint, a `distroless` non-root image
and a hardened pod spec. The things that matter most are consequences of
its job. To read one label on a referenced Secret it is granted read
access to every Secret in the cluster, and it keeps all of them in memory.
Because a Monitor may point at a Secret in any namespace, that privilege
is effectively delegated to anyone who can create a Monitor.

Two findings are rated High:

- **S-01** The controller caches the full content of every Secret in the
  cluster, in a process with a 128 MiB memory limit.
- **S-02** Cross-namespace references turn the operator into an oracle for
  Secret existence and expiry across tenants, and the operator logs the
  full label set of referenced Secrets.

Dependency hygiene (S-03) and release-tooling supply chain (S-04) are the
next priorities. Several lower items are documented trade-offs from the
metrics design spec and are listed here for completeness with the cheapest
known mitigation.

| ID | Severity | Finding |
| --- | --- | --- |
| S-01 | High | Every Secret in the cluster is cached in memory |
| S-02 | High | Cross-namespace references expose Secret metadata |
| S-03 | Medium | Ten known vulnerabilities reachable; no scan in CI |
| S-04 | Medium | Release tooling runs unpinned remote code |
| S-05 | Medium | Scrape token sent over unverified TLS |
| S-06 | Medium | Development-mode logging in production |
| S-07 | Low | Long-lived scrape token has no rotation procedure |
| S-08 | Low | Build secrets handled through `ARG` and `ENV` |
| S-09 | Low | RBAC wider than the code uses |
| S-10 | Low | Pod and network hardening gaps |
| S-11 | Low | CI token permissions and dependency auto-merge |
| S-12 | Info | Controls that are in place |

## Findings

### S-01 Every Secret in the cluster is cached in memory (High)

> Fixed in PR #51.

**Where:** `internal/controller/monitor_controller.go` lines 259
(`r.Get` of the Secret) and 510-518 (`Watches(&corev1.Secret{}, ...)`);
`config/rbac/role.yaml` (`secrets: get, list, watch` cluster-wide);
`config/manager/manager.yaml` (`memory: 128Mi` limit).

**What:** `controller-runtime` serves both the watch and the `Get` from a
shared informer. Registering a watch on `corev1.Secret` with no
restriction starts an informer that lists and stores every Secret in the
cluster, data included. The operator only ever reads one label; the only
code that touches `.data` is the update predicate, which compares old and
new payloads to decide whether to reconcile.

**Why it matters:**

- *Exposure.* The operator process becomes a copy of every credential in
  the cluster. A heap or core dump, a future debug endpoint (`pprof` is one
  manager option away), or any memory-disclosure bug in a dependency
  exposes all of it, far beyond what the operator needs.
- *Availability.* Helm stores release manifests in Secrets, often hundreds
  of kilobytes each, and busy clusters hold thousands of Secrets. The cache
  can easily exceed the 128 MiB limit, after which the pod is OOM-killed in
  a loop and all expiry monitoring stops. Because the alerts are driven by
  the operator's own series (see C-18 in the code review), that outage is
  silent.
- *Least privilege.* RBAC still has to allow `list` and `watch` on Secrets
  for a watch to work, but holding payloads is a choice, not a need.

**Recommendation:** Switch the Secret watch and lookup to metadata only.
`controller-runtime` supports this directly:

```go
Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(...),
    builder.OnlyMetadata, builder.WithPredicates(...))
```

and in the reconciler:

```go
secret := &metav1.PartialObjectMetadata{}
secret.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
err := r.Get(ctx, key, secret)
```

The cache then stores only `ObjectMeta` for Secrets. The update predicate
should compare the `validUntil` label (or `ResourceVersion`) instead of
`.data`, which also fixes C-02. Optionally restrict the cache further with
a label selector so that only Secrets carrying the `validUntil` label are
tracked at all; note that this changes the "label missing" error into
"secret not found". Add an end-to-end assertion that the manager's
memory use stays flat when many unrelated Secrets are created.

### S-02 Cross-namespace references expose Secret metadata (High)

> Fixed in PR #50.

**Where:** `monitor_controller.go` lines 246-268 (`getSourceObject`),
271-308 (`parseSourceObject`, `availableLabels` at 285-290);
`api/v1alpha1/monitor_types.go` lines 93-97 (`secretRef.namespace`);
`test/e2e/e2e_test.go` "Cross-Namespace" context.

**What:** A Monitor in namespace A may reference a Secret in namespace B.
The feature is intentional and tested. The operator reads B's Secret with
its own cluster-wide permission and writes what it learns into A's Monitor
status and into its logs. Nothing checks that the author of the Monitor is
allowed to see anything in B.

**Why it matters:** On a shared cluster (OpenShift with multiple tenants is
the stated target), any user with `create` on Monitors in their own
namespace can:

- Probe whether a Secret with a given name exists in any namespace. The
  status message distinguishes "referenced secret not found" from the
  label errors.
- Read the `validUntil` label value of any Secret through
  `status.expiresAt`.
- Make the operator log the complete label map of any Secret at Error
  level (`availableLabels`). Logs are usually shipped to a central store
  with broader readership than the source namespace.

Secret names and labels are metadata, not payloads, but names frequently
encode purpose (`prod-db-admin`, `github-deploy-key`) and RBAC normally
hides even their existence across namespaces. The operator's permission is
in effect delegated to every Monitor author.

**Recommendation:** Keep cross-namespace monitoring, but make the owner of
the Secret opt in, following the pattern used by cert-manager and External
Secrets. For example, honour an annotation on the target Secret:

```yaml
expiring-secrets.stakater.com/allowed-namespaces: "team-a,team-b"  # or "*"
```

When the Monitor's namespace is not listed, treat the Secret as not found
and say so in the status (`SourceNotAllowed`). Stop logging
`availableLabels`; log only whether the expected key was present. Document
the tenancy model in the README. A simpler alternative is an operator flag
that disables cross-namespace references entirely for clusters that do not
need them.

### S-03 Ten known vulnerabilities reachable; no scan in CI (Medium)

**Where:** `go.mod`; `makefiles/common.mk` line 637 (`govulncheck`
install target, never invoked); `.github/workflows/*`.

**What:** `govulncheck ./...` at this commit reports ten vulnerabilities
in code paths the operator reaches, all in indirect dependencies pinned by
the Kubernetes and `controller-runtime` versions in use:

Advisory IDs below are `GO-2026-<n>`.

| Module | Found | Fixed in | Advisories |
| --- | --- | --- | --- |
| `golang.org/x/net` | v0.57.0 | v0.60.0 | 6617, 6612, 6611, 6610, 6603 |
| `google.golang.org/grpc` | v1.72.2 | v1.83.1 | 6348, 6061 |
| `go.opentelemetry.io/otel` | v1.36.0 | v1.41.0 | 5506 |
| `go.opentelemetry.io/otel/sdk` | v1.36.0 | v1.45.0 | 6505, 4394 |
| `.../otlp/otlptrace` (+grpc) | v1.34.0 | v1.45.0 | 6505 |

The `x/net` items are `HTTP/2` server and transport issues. The metrics
server disables `HTTP/2` by default (`cmd/main.go` lines 86-93), which
removes the server-side exposure, but the same package serves the client
transport to the API server. The gRPC and OpenTelemetry items sit on
paths that are linked but not configured at runtime.

The repository defines a `govulncheck` make target and enables Renovate
vulnerability alerts, but nothing runs the scanner on pull requests, so
reachable findings surface only when Renovate opens a PR for them.

**Recommendation:** Bump the five modules with `go get` and `go mod tidy`
(they are not constrained by the Kubernetes modules). Add `govulncheck`
to the pull-request workflow and to `make pre-commit`. Add an image scan
(`trivy` or `grype`) to the release workflow so OS-level findings in the
builder are also covered. `govulncheck` should be built with the same Go
version as the project; see C-15 for the local toolchain mismatch.

### S-04 Release tooling runs unpinned remote code (Medium)

**Where:** `makefiles/common.mk` lines 349, 362-381
(`download-helm-mk`, `helm-release`); `Makefile` lines 48-63
(`promtool`); `common.mk` Helm and Prometheus Operator download targets;
`Dockerfile`, `local.Dockerfile`, `catalog.Dockerfile`;
`.github/workflows/*.yaml`.

**What:**

- `make helm-release` downloads `helm.mk` from the `main` branch of
  `stakater/.github` over plain `curl` and executes it with `make`, passing
  the GHCR token as `GIT_TOKEN`. Whatever is on `main` at release time
  runs with push access to the chart registry.
- The repository pins the reusable workflows to a commit SHA, which is
  good, but those workflows call composite actions at
  `stakater/.github/.github/actions/operator/*@main`. The pin therefore
  does not freeze the code that runs with `GHCR_TOKEN`.
- `promtool`, Helm, the Prometheus Operator bundle and cert-manager are
  fetched from GitHub releases without checksum verification.
- Container images are not pinned by digest: `golang:1.25`,
  `gcr.io/distroless/static:nonroot`,
  `quay.io/operator-framework/opm:latest` (a floating tag), and
  `curlimages/curl:7.87.0` in the e2e suite. `renovate.json` extends
  `config:best-practices`, which includes digest pinning for Docker images
  and GitHub Actions, yet nothing is pinned. Worth checking the dependency
  dashboard for why.

**Why it matters:** The release path is where the registry credential is
live. An unpinned `main` branch in another repository, or a swapped tarball
on a release page, becomes code execution with that credential.

**Recommendation:** Point `HELM_MK_URL` at a tag or commit and record its
expected SHA-256. Verify tarball checksums (`sha256sum -c`) against the
checksums file the upstream projects publish. Pin images by digest and let
Renovate bump them. Raise the `@main` action references with the owners of
`stakater/.github` since they affect every operator built there.

### S-05 Scrape token sent over unverified TLS (Medium)

**Where:** `config/prometheus/servicemonitor.yaml`
(`insecureSkipVerify: true`); `cmd/main.go` lines 103-113 (self-signed
serving certificate); `config/default/metrics_service.yaml` (selects pods
by `control-plane: controller-manager`).

**What:** The metrics endpoint presents a self-signed certificate that
Prometheus does not verify, and the scrape carries the long-lived
`metrics-reader` bearer token. The design spec records this as an accepted
interim trade-off.

**Why it matters:** Any party that can answer on the Service's address
receives the token. Inside a cluster that includes anyone able to create a
pod in the operator namespace with the label the Service selects, and any
position on the node or in the cluster network between the two pods. The
token only grants `get` on `/metrics`, but that endpoint lists the name,
namespace, service and expiry date of every monitored Secret in the
cluster, which is exactly the cross-tenant metadata S-02 is concerned
with.

**Recommendation:** On OpenShift the fix needs no extra component:
annotate the metrics Service with
`service.beta.openshift.io/serving-cert-secret-name`, mount the resulting
Secret into the manager and set `CertDir`, `CertName` and `KeyName` on
`metricsserver.Options`; in the ServiceMonitor set `tlsConfig.ca.configMap`
to a ConfigMap annotated `service.beta.openshift.io/inject-cabundle: "true"`
plus `serverName`. Both are allowed under user-workload monitoring because
they are references, not file paths. On vanilla Kubernetes use a
cert-manager `Certificate` with the same wiring. Add a NetworkPolicy
(S-10) as a second layer.

### S-06 Development-mode logging in production (Medium)

> Fixed in PR #53.

**Where:** `cmd/main.go` lines 72-74; `monitor_controller.go` lines
285-290.

**What:** `zap.Options{Development: true}` is the compiled-in default. In
development mode zap's `DPanic` level panics instead of logging, the
default level is debug, sampling is off, and stack traces are attached at
warning and above. The reconciler additionally logs the full label map of
a referenced Secret when the expected label is missing.

**Why it matters:** A `DPanic` anywhere in a dependency becomes a crash of
the operator in production. Debug-level output from `controller-runtime`
and client-go is verbose and includes request details. The label dump
combines with S-02 to leak metadata across tenants through the logging
pipeline.

**Recommendation:** Set `Development: false` and enable it locally with
`--zap-devel`. Log the presence or absence of the expected label key, not
the whole map. Lower per-reconcile lines to `V(1)` as described in C-10.

### S-07 Long-lived scrape token has no rotation procedure (Low)

**Where:** `config/rbac/metrics_reader_token.yaml`; `DEPLOY.md`
"Monitoring"; design spec "Accepted trade-offs".

**What:** A `kubernetes.io/service-account-token` Secret is shipped so
Prometheus Operator can reference it from `authorization.credentials`.
Projected, auto-rotating tokens cannot be used with that field, and the
spec explains why `bearerTokenFile` is unavailable under user-workload
monitoring. The trade-off is reasonable; what is missing is the operating
procedure around it.

**Recommendation:** Document rotation in `DEPLOY.md`: delete the token
Secret, the token controller recreates its content, Prometheus Operator
picks up the new value on its next reconcile. Note that the token must be
rotated if anyone with secret read in the operator namespace leaves the
team, and recommend a namespace-scoped RBAC review for that namespace.
Keep the `metrics-reader` ClusterRole exactly as narrow as it is.

### S-08 Build secrets handled through `ARG` and `ENV` (Low)

**Where:** `Dockerfile` lines 6-13; `local.Dockerfile` lines 6-18;
`makefiles/common.mk` lines 415-421.

**What:** The CI build passes a Git token as `--build-arg GIT_TOKEN`, the
Dockerfile copies it into `ENV TOKEN=...` and writes it into
`/root/.gitconfig` in the builder stage. Build arguments and `ENV` values
are recorded in the builder image's configuration and are visible with
`docker history`; any pushed cache layer carries them. The final
`distroless` stage copies only the binary, so the shipped image is clean.
In this repository the token is empty in practice because the
`STAKATER_AB_REPOS` secret is not passed to the reusable workflows, and the
module graph contains no private dependencies. `local.Dockerfile` runs
`ssh-keyscan` and then sets `StrictHostKeyChecking no`, which undoes the
key scan.

**Recommendation:** Remove the private-module machinery (`GOPRIVATE`,
`insteadOf`, `GIT_TOKEN`) from both Dockerfiles since nothing needs it.
Where a token is genuinely required, use a BuildKit secret mount
(`RUN --mount=type=secret,id=git_token ...`) so it never enters a layer.
Drop the `StrictHostKeyChecking no` line.

### S-09 RBAC wider than the code uses (Low)

> Fixed in PR #52.

**Where:** `config/rbac/role.yaml`, `config/rbac/leader_election_role.yaml`,
`internal/controller/monitor_controller.go` lines 74-77 (RBAC markers).

**What:**

- `manager-role` grants `create` and `delete` on Monitors. The controller
  never creates or deletes them.
- `monitors/finalizers: update` is only required when setting owner
  references with `blockOwnerDeletion` on clusters that enforce
  `OwnerReferencesPermissionEnforcement`. Adding a finalizer to the object
  itself is an ordinary update. It becomes unnecessary once C-03 removes
  the finalizer.
- The leader-election Role grants all verbs on `configmaps` and `create`
  and `patch` on `events`. `controller-runtime` elects on `leases` by
  default and the operator has no event recorder.

**Recommendation:** Trim the markers to `get;list;watch;update;patch` on
Monitors (drop `update;patch` as well once the finalizer and spec
defaulting are gone), remove the finalizer sub-resource rule, and reduce
the leader-election Role to `leases`. Regenerate with `make manifests`.

### S-10 Pod and network hardening gaps (Low)

**Where:** `config/manager/manager.yaml`;
`config/default/kustomization.yaml` lines 23-30;
`config/network-policy/allow-metrics-traffic.yaml`.

**What:**

- `readOnlyRootFilesystem` is not set. The image is `distroless` static and
  writes nothing, so it is free to add.
- A NetworkPolicy restricting the metrics port exists but is commented out
  of the default Kustomization, so the port is reachable from any pod.
  Authentication protects it today; the policy is defence in depth and
  limits S-05.
- The public Kustomize base adds `imagePullSecrets: saap-dockerconfigjson`
  to the Deployment. External users of `kubectl apply -k` get a warning on
  every pull for a Secret that does not exist, and the name leaks an
  internal environment.

**Recommendation:** Add `readOnlyRootFilesystem: true`. Enable the
NetworkPolicy overlay in `config/default` (OpenShift user-workload
monitoring pods can be selected by namespace label). Move the pull-secret
patch into a dev-only overlay used by `make deploy`.

### S-11 CI token permissions and dependency auto-merge (Low)

**Where:** `.github/workflows/e2e_helm.yaml`, `verify.yaml`,
`pull_request.yaml`, `push.yaml`, `release.yaml`; `renovate.json`.

**What:**

- The repo-local workflows declare no `permissions:` block, so the
  `GITHUB_TOKEN` gets the repository default, which may be read-write.
  Neither job needs more than `contents: read`.
- `actions/checkout@v4` and `actions/setup-go@v5` are pinned to mutable
  tags rather than commit hashes, unlike the reusable workflows.
- Renovate auto-merges patch updates as soon as CI passes, with no
  `minimumReleaseAge`. Minor updates wait 14 days; patches wait zero.
  Compromised patch releases are the typical supply-chain route and are
  usually yanked within days.

**Recommendation:** Add `permissions: { contents: read }` at the top of
each repo-local workflow. Pin actions by commit hash (the Renovate
best-practices preset should do this; see S-04). Give patch updates a
`minimumReleaseAge` of at least three days.

### S-12 Controls that are in place (Info)

Listed so the next reviewer does not re-derive them:

- Metrics endpoint requires a bearer token and checks it with
  `TokenReview` and `SubjectAccessReview`
  (`filters.WithAuthenticationAndAuthorization`); the reader role grants
  only `get` on `/metrics`.
- `HTTP/2` disabled on the metrics server unless `--enable-http2` is set.
- Image: `distroless` static, `USER 65532`, no shell. Pod:
  `runAsNonRoot`, `seccompProfile: RuntimeDefault`, all capabilities
  dropped, `allowPrivilegeEscalation: false`, CPU and memory limits set.
- No webhooks, so no inbound TLS endpoint beyond metrics.
- No credentials in the repository or its history. A scan of every commit
  for common token formats (GitHub, AWS, Slack, Docker, private keys)
  found nothing.
- Reusable workflows pinned by commit SHA; Renovate vulnerability alerts
  enabled with a `security` label.
- The dev Prometheus RBAC deliberately excludes `secrets` with a comment
  explaining why.
- The metrics design spec records its security trade-offs explicitly.

## Verification performed

| Check | Result |
| --- | --- |
| `govulncheck ./...` (Go 1.27.3 build) | 10 reachable, 8 not reachable |
| Git history scan for token patterns | nothing found |
| `make lint` | 0 issues |
| Unit suites, native `envtest` 1.31.0 | 4 packages pass |
| Chart render under three release configs | token mismatch with custom SA |
| RBAC rules compared with client calls in code | S-09 |
| Upstream `stakater/.github` workflows and actions | read via GitHub API |

## Suggested order of work

1. S-01: metadata-only Secret watch. Small change, removes the largest
   exposure and an availability risk, and simplifies C-02.
1. S-02: opt-in annotation for cross-namespace references, and stop
   logging label maps.
1. S-03: bump the five modules and add `govulncheck` to the PR workflow.
1. S-04: pin `helm.mk` and verify tool checksums before the next release.
1. S-06 and S-10: one-line changes to `main.go` and the manifests.
1. S-05: serving certificates, as the follow-up the design spec already
   plans.

## Glossary

- **GHCR**: GitHub Container Registry, where this project's images and
  Helm chart are published.

# Deployment

## Manual Deployment
For local development and testing, you can build and push the operator image directly to a Docker repository.

### Steps
1. Update `VERSION` and `DOCKER_REPO_BASE` variables in the `Makefile`.
2. Build the controller and bundle images:
   ```sh
   make manifests build docker-build docker-push
   make bundle bundle-build bundle-push
   ```
3. Add a version entry to `catalog/channels.yaml` following OLM upgrade specifications:
   ```yaml
   entries:
   - name: expiring-secret-operator.v0.0.1
   - name: expiring-secret-operator.v0.0.2 # This is the next version to be released
     skips:
      - expiring-secret-operator.v0.0.1
      ```
4. Render, build, and push the catalog index:
   ```sh
   make catalog-render catalog-build catalog-push
   ```

## Monitoring

The operator serves metrics on `:8443` over HTTPS, protected by the
manager's authn/authz filter. A `ServiceMonitor` and a `PrometheusRule` ship
with the default kustomization, along with a `metrics-reader` ServiceAccount
whose token the ServiceMonitor presents when scraping.

> **Warning:** `config/rbac/metrics_reader_token.yaml` hardcodes the
> `namePrefix` from `config/default/kustomization.yaml` in its
> `kubernetes.io/service-account.name` annotation, because kustomize
> rewrites resource *names* but never the contents of an annotation
> *value*. If you change `namePrefix`, this annotation is not updated to
> match, the token Secret is never populated for the renamed
> ServiceAccount, and scrapes will silently fail with 401 — the operator's
> own metrics endpoint looks fine, you just get no series in Prometheus.
> Also note the token is populated asynchronously by the built-in
> ServiceAccount token controller on first apply, so a brief window where
> Prometheus can't yet authenticate right after a fresh deploy is normal
> and not a sign of misconfiguration.

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

## CI/CD Deployment
For automated builds and releases via CI/CD pipelines, the version is bumped based on the latest release tag rather than the `Makefile` settings.

### Conditions for Catalog Release

A catalog release is triggered if:
- Changes are made to files in the `catalog` directory.
- A new version entry is specified in `catalog/channels.yaml,` indicating the upcoming release.
  ```yaml
  entries:
  - name: expiring-secret-operator.v0.0.1
  - name: expiring-secret-operator.v0.0.2 # This is the next version to be released
    skips:
    - expiring-secret-operator.v0.0.1
  ```

## Working with Entries in `catalog/channels.yaml`

The entries section in `catalog/channels.yaml` defines versioning information for OLM to manage upgrades. Properly structuring these entries is essential for ensuring smooth version handling and change application.

### Semantic Versioning

Strict adherence to semantic versioning is required. Proper versioning is critical for maintaining smooth upgrades and avoiding deployment issues with OLM.
- **Major version changes** indicate breaking changes (e.g., v1.0.0 → v2.0.0).
- **Minor version changes** introduce backward-compatible features (e.g., v0.1.0 → v0.2.0).
- **Patch version changes** fix bugs or make minor improvements (e.g., v0.0.1 → v0.0.2).

### Entry Structure

Each release of has an entry in the entries section of `catalog/channels.yaml`. The following structure is used in the repository for entries:

#### Non-breaking API Changes (Use skips)
For non-breaking API changes (such as bug fixes or new features), the skips field is used to specify previous versions that are skipped during upgrades.

Example:

```yaml
entries:
- name: expiring-secret-operator.v0.0.3
  skips:
   - expiring-secret-operator.v0.0.1
   - expiring-secret-operator.v0.0.2
```
#### Breaking API Changes (Use replaces)
For breaking API changes, the replaces field is used to specify which previous version is being replaced. This indicates to OLM that the older version should be upgraded to the new version.
Example:

```yaml
entries:
- name: expiring-secret-operator.v0.0.3
  replaces: expiring-secret-operator.v0.0.1
```

## Contributing
1. Add the next version entry in `catalog/channels.yaml`:
   ```yaml
   entries:
      - name: expiring-secret-operator.v{{CURRENT}}
      - name: expiring-secret-operator.v{{NEXT}}
        skips:
          - expiring-secret-operator.v0.0.1
   ```
2. Create a PR and run tests.
3. Merging the PR will trigger the build and push the releases.

## More Information
Refer to the OpenShift documentation for managing custom catalogs:
[OLM Managing Custom Catalogs](https://docs.redhat.com/en/documentation/openshift_container_platform/4.18/html/operators/administrator-tasks)


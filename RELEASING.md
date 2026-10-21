# Releasing

A release must be **self-contained**: the tagged commit carries the version it
releases, so `kubectl apply -k …?ref=<tag>` and `helm install … --version <x>`
both get that exact release — not an older or a dev build.

## Background: three pipelines

| Trigger | Workflow | Publishes |
| --- | --- | --- |
| Pull request | `operator_pull_request` | a test image `…:vX.Y.Z-SNAPSHOT-PR-<n>-<sha>` |
| Merge to `master` | `operator_push` | a rolling **next-version dev** image `…:vX.Y.Z` |
| Push a git tag `vX.Y.Z` | `operator_release` | the **release**: image + Helm chart + GitHub release, all as `X.Y.Z` |

Two consequences to keep in mind:

- The push pipeline publishes a clean-semver image for the *next* version on
  every merge. It is a dev build, not a release. (Reserving clean semver tags
  for real releases is tracked upstream in `stakater/.github`.)
- **Renovate does not manage the operator's own image** (`renovate.json`), so
  `config/manager/kustomization.yaml`'s tag is owned entirely by the step
  below. Nothing bumps it behind your back.

## Cutting a release

```bash
# 1. Set the version everywhere (Makefile VERSION + kustomize image tag).
make set-version VERSION=0.0.4

# 2. Regenerate manifests/bundle for the new version.
make manifests bundle

# 3. Commit on a branch and open a PR. CI's "Verify image tag matches VERSION"
#    job fails if the Makefile VERSION and the kustomize tag disagree.
git checkout -b release/v0.0.4
git commit -am "chore: release v0.0.4"

# 4. After the PR merges, tag the merge commit. The tag push triggers
#    operator_release, which publishes the image + chart as 0.0.4.
git checkout master && git pull
gh release create v0.0.4 --target master --generate-notes --title v0.0.4
```

The image tag pattern accepted by the release workflow is `v[012].Y.Z`.

## After the release

The published Helm chart is private by default on GHCR. Make
`charts/expiring-secret-operator` public once (one-time, in the org's package
settings) so `helm install oci://ghcr.io/stakater/charts/…` works anonymously.

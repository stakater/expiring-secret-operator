Instructions for expiring-secrets

This is not a toy controller — it is structured the way Red Hat-style operators are typically built. It is not a simple script that runs in a loop. It is a full controller with a manager, reconciler, and uses the controller-runtime library.

## Project Overview

This repository is a **thorough, operator-grade design and implementation walkthrough** for a **Kubernetes Operator**, aligned with **OpenShift best practices**, and suitable for long-term production use.

## Problem statement
Many organizations use **Personal Access Tokens (PATs)**, or other forms of credentials/tokens/etc., to authenticate to external services like container registries (e.g., Docker Hub, Quay, GitHub Packages). These tokens often have expiration dates, and if they expire without notice, it can lead to **CI/CD pipeline failures**, **deployment issues**, and **downtime**.

# Development approach
1. **Design first**: Define CRD schema, metric contract, and overall architecture before coding.
2. **Test-driven**: Write unit tests for the reconciler logic using `envtest` before implementing the logic.
3. **Behavior-driven**: Use Ginkgo/Gomega for clear, behavior-focused tests.
4. **Iterative development**:
   * Build in small increments, starting with basic CRD and reconciliation,
     then adding metrics, status updates, and finally packaging.
5. **Best practices**:
   * Use Operator SDK (Go) for scaffolding
   * Follow OpenShift Operator guidelines
   * Implement proper RBAC
   * Ensure observability (metrics + status)

## Common make targets
- `make load-image`: Load local image into Kind (if present).
- `make docker-build`: builds the controller image locally
- `make deploy-core`: deploys minimal stack to Kind (core dependencies + controller)
- `make test`: runs the tests
- `make check-coverage`: checks code coverage against the defined threshold in .testcoverage-local.yml
- `make test-e2e`: runs the end-to-end tests
- `make test-e2e-dev`: runs the end-to-end tests locally with guaranteed cleanup even on failure

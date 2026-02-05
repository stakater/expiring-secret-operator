#!/bin/bash

export REPOSITORY=$(head -n 1 ./go.mod | cut -d " " -f2)
export OPERATOR_NAME=$(echo ${REPOSITORY} | cut -d "/" -f3)
export PROJECT_NAME="${OPERATOR_NAME}.stakater.com"

FILES=(
    "bundle.Dockerfile"
    "Makefile"
    "PROJECT"
    "DEPLOY.md"
    "README.md"
    "generate-catalog-index.sh"
    ".github/readme.md"
    "catalog/channels.yaml"
    "catalog/package.yaml"
    "config/default/kustomization.yaml"
    "config/default/metrics_service.yaml"
    "config/manager/manager.yaml"
    "config/manifests/kustomization.yaml"
    "config/manifests/bases/${OPERATOR_NAME}.clusterserviceversion.yaml"
    "config/network-policy/allow-metrics-traffic.yaml"
    "config/prometheus/monitor.yaml"
    "config/rbac/leader_election_role_binding.yaml"
    "config/rbac/leader_election_role.yaml"
    "config/rbac/role_binding.yaml"
    "config/rbac/role.yaml"
    "config/rbac/serviceaccount.yaml"
    "test/e2e/e2e_suite_test.go"
    "test/e2e/e2e_test.go"
)

for f in "${FILES[@]}"; do
    cat "${f}" | \
    sed "s/\${PROJECT_NAME}/${PROJECT_NAME}/g" | \
    sed "s/\${OPERATOR_NAME}/${OPERATOR_NAME}/g" | \
    sed "s/\${REPOSITORY}/${REPOSITORY}/g" \
    > "${f}"
done

mv "config/manifests/bases/clusterserviceversion.yaml" \
   "config/manifests/bases/${OPERATOR_NAME}.clusterserviceversion.yaml"

echo "DONE!"
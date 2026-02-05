# Workflow 

This repository uses shared workflows [`operator_pull_request.yaml`](https://github.com/stakater/.github/blob/main/.github/workflows/operator_pull_request.yaml) and [`operator_push.yaml`](https://github.com/stakater/.github/blob/main/.github/workflows/operator_pull_request.yaml) available in [`stakater/.github`](https://github.com/stakater/.github). These workflows are shared between [IPShield](https://github.com/stakater/IPShield), [UptimeGuardian](https://github.com/stakater/UptimeGuardian), and [${OPERATOR_NAME}](#)

## Steps

Following steps are performed by both `pull_request` and `push` workflows. Tag generation step has slightly different inputs depending on the workflow

1. Checkout code
1. Run `make lint`
1. Run `make test`
1. Generate Tags
1. Setup Docker (Login to image to repository)
1. Install Openshift tools
1. Run `make manifests build docker-build docker-push`
1. Run `make bundle bundle-build bundle-push`
1. Run `make catalog-render` to generate custom catalog index
1. Run `make catalog-build catalog-push`
1. Push git tag
1. Comment on PR
1. Notify Slack


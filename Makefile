VERSION ?= 0.0.1
OPERATOR_NAME ?= expiring-secret-operator
#OPERATOR_NAME ?= expiring-secrets
PROJECT_NAME ?= expiring-secrets.stakater.com
#vimTEST_CLUSTER_NAME ?= kind
#DOCKER_REPO_NAME ?= expiring-secret-operator
#SUPPRESS_OUTPUT ?= false

TEST_ARGS ?= -v -test.v -ginkgo.v

#.PHONY: all
#all: precheck style check_license lint build coverage

.PHONY: pre-commit
pre-commit: precheck check_license fmt vet lint

.PHONY: e2e
e2e: undeploy gh-action test-e2e

.PHONY: gh-action
gh-action:
#	@{ \
#		$(MAKE) manifests build docker-build; \
#		$(MAKE) bundle bundle-build; \
#		$(MAKE) docker-build bundle-build ; \
#		$(MAKE) catalog-render catalog-build; \
#		$(MAKE) deploy; \
#	};
	@{ \
		$(MAKE) manifests build docker-build; \
		$(MAKE) bundle bundle-build; \
		$(MAKE) deploy; \
	}

include Makefile.common

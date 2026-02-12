VERSION ?= 0.0.1
OPERATOR_NAME ?= expiring-secrets
PROJECT_NAME ?= expiring-secrets.stakater.com
TEST_CLUSTER_NAME ?= kind
DOCKER_REPO_NAME ?= expiring-secret-operator
#SUPPRESS_OUTPUT ?= false

TEST_ARGS ?= -v -test.v -ginkgo.v

#.PHONY: all
#all: precheck style check_license lint build coverage

.PHONY: pre-commit
pre-commit: precheck check_license fmt vet lint

include Makefile.common

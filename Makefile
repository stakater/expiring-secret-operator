VERSION ?= 0.0.1
OPERATOR_NAME ?= expiring-secrets
PROJECT_NAME ?= expiring-secrets.stakater.com
TEST_CLUSTER_NAME ?= kind
#SUPPRESS_OUTPUT ?= false

#TEST_ARGS ?= -v -test.v -ginkgo.v

#.PHONY: all
#all: precheck style check_license lint build coverage

.PHONY: pre-commit
pre-commit: precheck check_license fmt vet lint

.PHONY: do-e2e
#do-e2e: undeploy docker-build install-dependencies load-image deploy load-image
do-e2e: undeploy docker-build load-image deploy load-image
#	go test  ./test/e2e/ -v -test.v -ginkgo.v
	$(MAKE) run-e2e-test

include Makefile.common

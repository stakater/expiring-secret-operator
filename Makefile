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
pre-commit: precheck check_license fmt vet lint test-rules

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

PROMTOOL ?= $(LOCALBIN)/promtool
# NOTE: promtool cannot be installed via `go install pkg@version`. Every
# github.com/prometheus/prometheus tag published to the Go module proxy —
# both the v0.35.0-v0.55.1 line (Prometheus 2.x) and the v0.300.0-v0.314.0
# line (Prometheus 3.x) — carries `replace` or `exclude` directives in its
# go.mod, which `go install` unconditionally refuses to honor for a module
# that isn't the main module ("go.mod file ... contains one or more
# replace/exclude directives"). This was verified across the full v0.35-
# v0.55 and v0.300-v0.314 ranges; none are installable this way. We instead
# fetch the official prebuilt release tarball, the same pattern already
# used for helm/opm/operator-sdk below. PROMTOOL_VERSION is the real
# product tag (e.g. v3.9.1), not the Go module's remapped v0.x tag.
PROMTOOL_VERSION ?= v3.9.1

.PHONY: promtool
promtool: ## Download promtool locally if necessary.
	@if [ -f "$(PROMTOOL)" ]; then \
		echo ">> promtool already exists at $(PROMTOOL)"; \
	else \
		mkdir -p $(LOCALBIN); \
		echo ">> installing promtool $(PROMTOOL_VERSION) to $(PROMTOOL)"; \
		OS=$$(go env GOOS) && ARCH=$$(go env GOARCH) && \
		tmpdir=$$(mktemp -d) && \
		pkg="prometheus-$(PROMTOOL_VERSION:v%=%).$${OS}-$${ARCH}" && \
		curl -fsSL "https://github.com/prometheus/prometheus/releases/download/$(PROMTOOL_VERSION)/$${pkg}.tar.gz" -o $$tmpdir/promtool.tar.gz && \
		tar -xzf $$tmpdir/promtool.tar.gz -C $$tmpdir && \
		cp $$tmpdir/$${pkg}/promtool $(PROMTOOL) && \
		chmod +x $(PROMTOOL) && \
		rm -rf $$tmpdir; \
	fi

.PHONY: test-rules
test-rules: promtool ## Validate and unit-test the PrometheusRule alert rules.
	@command -v yq >/dev/null 2>&1 || { echo "yq is required by test-rules"; exit 1; }
	@echo ">> extracting rules from the PrometheusRule resource"
	yq '.spec' config/prometheus/rule.yaml > test/rules/rules.generated.yaml
	@echo ">> checking rule syntax"
	$(PROMTOOL) check rules test/rules/rules.generated.yaml
	@echo ">> running rule unit tests"
	$(PROMTOOL) test rules test/rules/rule_test.yaml

include makefiles/common.mk

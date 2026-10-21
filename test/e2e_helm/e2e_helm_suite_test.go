/*
Copyright 2025 Stakater.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package e2e_helm verifies the operator as installed from its published Helm
// chart, rather than from the raw kustomize manifests the main e2e suite uses.
// It lives in its own package (and runs under its own `make test-e2e-helm`
// target) so it never shares a cluster with the kustomize-deployed operator —
// two managers watching the same Monitors would reconcile against each other.
package e2e_helm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
	"github.com/stakater/expiring-secret-operator/test/utils"
)

var (
	k8sClient client.Client
	ctx       context.Context
	log       logr.Logger
)

// Configuration, overridable from the environment so the make target can point
// the install at a locally built image loaded into Kind. Defaults install the
// chart generated into ./charts and let the cluster pull the public image.
var (
	helmBin      = envOr("HELM_E2E_HELM_BIN", "helm")
	chartDir     = envOr("HELM_E2E_CHART", "../../charts/expiring-secret-operator")
	releaseName  = envOr("HELM_E2E_RELEASE", "eso-helm-e2e")
	operatorNS   = envOr("HELM_E2E_NAMESPACE", "eso-helm-e2e-system")
	imageRepoOvr = os.Getenv("HELM_E2E_IMAGE_REPO") // optional
	imageTagOvr  = os.Getenv("HELM_E2E_IMAGE_TAG")  // optional
	installWait  = envOr("HELM_E2E_INSTALL_TIMEOUT", "180s")
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Run e2e Helm-install tests using the Ginkgo runner.
func TestE2EHelm(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting expiring-secret-operator Helm-install suite\n")
	RunSpecs(t, "e2e helm-install suite")
}

var _ = BeforeSuite(func() {
	By("setting up the helm-install e2e suite")

	log = zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true))
	Expect(log).NotTo(BeNil())
	logf.SetLogger(log)
	ctx = context.Background()
	logf.IntoContext(ctx, log)

	By("  - kubernetes client")
	cfg, err := config.GetConfig()
	Expect(err).NotTo(HaveOccurred())
	Expect(expiringsecretv1alpha1.AddToScheme(scheme.Scheme)).To(Succeed())
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	By(fmt.Sprintf("installing the operator via Helm (release %q into namespace %q)", releaseName, operatorNS))
	args := []string{
		"upgrade", "--install", releaseName, chartDir,
		"--namespace", operatorNS, "--create-namespace",
		"--wait", "--timeout", installWait,
	}
	// Point the chart at a specific image when the caller provides one (CI
	// loads a freshly built image into Kind); otherwise the chart's own
	// default image (the public registry) is used.
	if imageRepoOvr != "" {
		args = append(args, "--set", "controllerManager.manager.image.repository="+imageRepoOvr)
	}
	if imageTagOvr != "" {
		args = append(args, "--set", "controllerManager.manager.image.tag="+imageTagOvr)
	}
	out, err := utils.Run(exec.Command(helmBin, args...))
	Expect(err).NotTo(HaveOccurred(), "helm install failed: %s", string(out))

	By("confirming the controller Deployment is Available")
	// helm --wait already blocks on readiness; assert explicitly so a failure
	// here is attributed to the install, not to the first spec. Select by the
	// control-plane label rather than a name, since the chart's fullname-based
	// Deployment name depends on the release name.
	rollout, err := utils.Run(exec.Command("kubectl", "wait",
		"--for=condition=Available", "deployment",
		"-l", "control-plane=controller-manager",
		"-n", operatorNS, "--timeout=120s"))
	Expect(err).NotTo(HaveOccurred(), "controller did not become available: %s", string(rollout))
})

var _ = AfterSuite(func() {
	if k8sClient == nil {
		return
	}
	By("uninstalling the Helm release")
	if out, err := utils.Run(exec.Command(helmBin, "uninstall", releaseName,
		"--namespace", operatorNS, "--wait", "--timeout", "120s")); err != nil {
		// Don't fail teardown; surface it for debugging.
		_, _ = fmt.Fprintf(GinkgoWriter, "helm uninstall warning: %v\n%s\n", err, string(out))
	}

	By("deleting the operator namespace")
	_, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", operatorNS,
		"--ignore-not-found=true", "--timeout=120s"))
})

// waitForNamespaceGone blocks until the named namespace is fully removed, so a
// re-run does not race the finalizer/GC of a previous run.
func waitForNamespaceGone(name string, timeout, interval time.Duration) {
	Eventually(func() bool {
		out, _ := utils.Run(exec.Command("kubectl", "get", "namespace", name,
			"--ignore-not-found=true", "-o", "name"))
		return len(out) == 0
	}, timeout, interval).Should(BeTrue())
}

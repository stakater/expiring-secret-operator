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

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2" //nolint:staticcheck
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secrets/api/v1alpha1"
)

var (
	ValidUntilLabel = "expiringsecret.stakater.com/validUntil"
)

func Log(format string, a ...any) {
	_, _ = fmt.Fprintf(GinkgoWriter, format+"\n", a...)
}

func WarnError(err error) {
	_, _ = fmt.Fprintf(GinkgoWriter, "warning: %v\n", err)
}

func GenerateSecret(ns types.NamespacedName, validUntil string, payload []byte) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ns.Name,
			Namespace: ns.Namespace,
			Labels:    map[string]string{},
		},
		Data: map[string][]byte{
			"token": payload,
		},
	}

	if validUntil != "" {
		secret.Labels[ValidUntilLabel] = validUntil
	}

	return secret
}

func GenerateMonitor(
	ns types.NamespacedName,
	service string,
	secretRef types.NamespacedName,
	alertThresholds *expiringsecretv1alpha1.AlertThresholds,
) *expiringsecretv1alpha1.Monitor {
	monitor := &expiringsecretv1alpha1.Monitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ns.Name,
			Namespace: ns.Namespace,
		},
		Spec: expiringsecretv1alpha1.MonitorSpec{
			Service: service,
			SecretRef: expiringsecretv1alpha1.SecretReference{
				Name:      secretRef.Name,
				Namespace: secretRef.Namespace,
			},
			AlertThresholds: alertThresholds,
		},
	}
	return monitor
}

// WaitForStatus waits until the specified condition is met for the given resource,
// or times out
// condition: the condition to wait for (e.g., "Established", "Ready")
// resource: the resource to check (e.g., "crd/myresource", "pod/mypod")
// namespace: the namespace of the resource (optional, can be empty for cluster-scoped resources)
// timeout: how long to wait before giving up (e.g., "30s", "1m")
func WaitForStatus(condition, resource, namespace, timeout string) error {
	if timeout == "" {
		timeout = "30s"
	}

	args := []string{
		"wait",
		fmt.Sprintf("--for=condition=%s", condition),
		fmt.Sprintf("--timeout=%s", timeout),
		resource,
	}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}

	cmd := exec.Command("kubectl", args...)
	_, err := Run(cmd)
	return err
}

// Run executes the provided command within this context
func Run(cmd *exec.Cmd) ([]byte, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "chdir dir: %s\n", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	_, _ = fmt.Fprintf(GinkgoWriter, "running: %s\n", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s failed with error: (%v) %s", command, err, string(output))
	}

	return output, nil
}

// LoadImageToKindClusterWithName loads a local docker image to the kind cluster
func LoadImageToKindClusterWithName(name string) error {
	cluster := "kind"
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	kindOptions := []string{"load", "docker-image", name, "--name", cluster}
	cmd := exec.Command("kind", kindOptions...)
	_, err := Run(cmd)
	return err
}

// GetNonEmptyLines converts given command output string into individual objects
// according to line breakers, and ignores the empty elements in it.
func GetNonEmptyLines(output string) []string {
	var res []string
	elements := strings.SplitSeq(output, "\n")
	for element := range elements {
		if element != "" {
			res = append(res, element)
		}
	}

	return res
}

// GetProjectDir will return the directory where the project is
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, err
	}
	wd = strings.ReplaceAll(wd, "/test/e2e", "")
	return wd, nil
}

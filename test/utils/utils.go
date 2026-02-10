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
)

func Log(format string, a ...any) {
	_, _ = fmt.Fprintf(GinkgoWriter, format+"\n", a...)
}

func WarnError(err error) {
	_, _ = fmt.Fprintf(GinkgoWriter, "warning: %v\n", err)
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

/*
func CheckOperatorReady(ns types.NamespacedName) error {
	// Get controller pod name
	cmd := exec.Command("kubectl", "get", "pods",
		"-l", "control-plane=controller-manager",
		"-n", ns.Namespace,
		"-o", "jsonpath=\"{.items[0].metadata.name}\"")
	podNameBytes, err := Run(cmd)
	if err != nil {
		return fmt.Errorf("failed to get controller pod name: %v", err)
	}
	podName := string(podNameBytes)
	if podName == "" {
		return fmt.Errorf("no controller pod found")
	}

	// Check readyz endpoint directly via kubectl exec
	cmd = exec.Command("kubectl", "exec", "-n", ns.Namespace, podName, "--",
		"wget", "-q", "-O-", "http://localhost:8081/readyz")
	_, err = Run(cmd)
	if err != nil {
		return fmt.Errorf("readyz endpoint not ready: %v", err)
	}

	return nil
}
*/

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

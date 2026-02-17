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

package main

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	expiringsecretv1alpha1 "github.com/stakater/expiring-secrets/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	// +kubebuilder:scaffold:imports
)

func TestMain(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Main Suite")
}

var _ = Describe("Main", func() {
	var (
		scheme = runtime.NewScheme()
	)

	It("should not error", func() {
		Expect(scheme).NotTo(BeNil())
		Expect(expiringsecretv1alpha1.AddToScheme(scheme)).NotTo(HaveOccurred())
	})

})

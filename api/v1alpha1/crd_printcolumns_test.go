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

package v1alpha1

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/yaml"
)

// A kubectl additionalPrinterColumn of type "date" is rendered as time elapsed
// since the value (like Age). For .status.expiresAt, which is a *future*
// timestamp, that elapsed duration is negative and kubectl prints "<invalid>"
// (see duration.HumanDuration). The column must therefore be type "string" so
// the actual expiry timestamp is shown. This guards against regenerating the
// CRD from a marker that reverts it to "date".
var _ = Describe("Monitor CRD printer columns", func() {
	It("renders the Expires At column as a string, not a date", func() {
		const crdPath = "../../config/crd/bases/expiring-secrets.stakater.com_monitors.yaml"

		data, err := os.ReadFile(crdPath)
		Expect(err).NotTo(HaveOccurred(), "reading CRD %s", crdPath)

		var crd struct {
			Spec struct {
				Versions []struct {
					Name                     string `json:"name"`
					AdditionalPrinterColumns []struct {
						Name     string `json:"name"`
						Type     string `json:"type"`
						JSONPath string `json:"jsonPath"`
					} `json:"additionalPrinterColumns"`
				} `json:"versions"`
			} `json:"spec"`
		}
		Expect(yaml.Unmarshal(data, &crd)).To(Succeed())

		found := false
		for _, v := range crd.Spec.Versions {
			for _, c := range v.AdditionalPrinterColumns {
				if c.JSONPath != ".status.expiresAt" {
					continue
				}
				found = true
				Expect(c.Type).To(Equal("string"),
					"version %s column %q (%s): a date column renders a future timestamp as \"<invalid>\"",
					v.Name, c.Name, c.JSONPath)
			}
		}
		Expect(found).To(BeTrue(), "no printer column for .status.expiresAt found in %s", crdPath)
	})
})

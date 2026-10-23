/*
Copyright 2026 Stakater.

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

package controller

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("newRateLimiter", func() {
	It("caps the per-item back-off at one minute", func() {
		l := newRateLimiter()
		req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "m", Namespace: "ns"}}
		var d time.Duration
		for i := 0; i < 40; i++ {
			d = l.When(req)
		}
		Expect(d).To(Equal(time.Minute))
	})
})

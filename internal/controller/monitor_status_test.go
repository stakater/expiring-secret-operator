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
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	expiringsecretv1alpha1 "github.com/stakater/expiring-secret-operator/api/v1alpha1"
)

var _ = Describe("Monitor status logic", func() {
	DescribeTable("calculating state",
		func(daysRemaining int, expected expiringsecretv1alpha1.MonitorState) {
			monitor := &expiringsecretv1alpha1.Monitor{
				Spec: expiringsecretv1alpha1.MonitorSpec{
					AlertThresholds: &expiringsecretv1alpha1.AlertThresholds{
						InfoDays:     30,
						WarningDays:  14,
						CriticalDays: 7,
					},
				},
			}
			now := time.Now()
			calculateState(monitor, now.Add(time.Duration(daysRemaining)*24*time.Hour), now)
			Expect(monitor.Status.State).To(Equal(expected))
			setStatusMessage(monitor)
			Expect(monitor.Status.Message).NotTo(BeEmpty())
		},
		Entry("should calculate Valid state correctly",
			31, expiringsecretv1alpha1.MonitorStateValid),
		Entry("should calculate Info state correctly",
			30, expiringsecretv1alpha1.MonitorStateInfo),
		Entry("should calculate Warning state correctly",
			10, expiringsecretv1alpha1.MonitorStateWarning),
		Entry("should calculate Critical state correctly",
			3, expiringsecretv1alpha1.MonitorStateCritical),
		Entry("should calculate Expired state correctly",
			-5, expiringsecretv1alpha1.MonitorStateExpired),
		Entry("should use default thresholds when not specified",
			10, expiringsecretv1alpha1.MonitorStateWarning),
		Entry("treats exactly zero seconds remaining as Expired",
			0, expiringsecretv1alpha1.MonitorStateExpired),
	)

	It("should handle setStatusMessage with nil ExpiresAt", func() {
		monitor := &expiringsecretv1alpha1.Monitor{
			Status: expiringsecretv1alpha1.MonitorStatus{
				State:            expiringsecretv1alpha1.MonitorStateWarning,
				SecondsRemaining: pointerInt64(86400),
			},
		}
		setStatusMessage(monitor)
		Expect(monitor.Status.Message).NotTo(BeEmpty())
	})

	It("should handle setStatusMessage with nil SecondsRemaining", func() {
		monitor := &expiringsecretv1alpha1.Monitor{
			Status: expiringsecretv1alpha1.MonitorStatus{
				State:     expiringsecretv1alpha1.MonitorStateExpired,
				ExpiresAt: &metav1.Time{Time: time.Now()},
			},
		}
		setStatusMessage(monitor)
		Expect(monitor.Status.Message).NotTo(BeEmpty())
	})

	It("should handle setStatusMessage with MonitorStateError", func() {
		monitor := &expiringsecretv1alpha1.Monitor{
			Status: expiringsecretv1alpha1.MonitorStatus{
				State: expiringsecretv1alpha1.MonitorStateError,
			},
		}
		setStatusMessage(monitor)
		Expect(monitor.Status.Message).
			To(Equal("Expiration date is not available"))
	})

	It("should use unknown message for unknown state", func() {
		monitor := &expiringsecretv1alpha1.Monitor{
			Status: expiringsecretv1alpha1.MonitorStatus{
				State:            expiringsecretv1alpha1.MonitorState("mystery"),
				ExpiresAt:        &metav1.Time{Time: time.Now()},
				SecondsRemaining: pointerInt64(3600),
			},
		}
		setStatusMessage(monitor)
		Expect(monitor.Status.Message).To(ContainSubstring("Unknown state"))
	})
	conditionStatus := func(m *expiringsecretv1alpha1.Monitor, t expiringsecretv1alpha1.MonitorConditionType) metav1.ConditionStatus {
		c := apimeta.FindStatusCondition(m.Status.Conditions, string(t))
		Expect(c).NotTo(BeNil(), string(t))
		return c.Status
	}

	DescribeTable("conditions by reason",
		func(reason string, want conditionSet) {
			Expect(conditionsFor(reason)).To(Equal(want))
			m := &expiringsecretv1alpha1.Monitor{}
			applyConditions(m, reason, "msg")
			Expect(conditionSet{
				Ready:            conditionStatus(m, expiringsecretv1alpha1.MonitorConditionReady),
				SourceAvailable:  conditionStatus(m, expiringsecretv1alpha1.MonitorConditionSourceAvailable),
				SourceLabelFound: conditionStatus(m, expiringsecretv1alpha1.MonitorConditionSourceLabelFound),
				SourceLabelValid: conditionStatus(m, expiringsecretv1alpha1.MonitorConditionSourceLabelValid),
			}).To(Equal(want))
		},
		Entry("ready", ReasonReady, conditionSet{
			metav1.ConditionTrue, metav1.ConditionTrue, metav1.ConditionTrue, metav1.ConditionTrue}),
		Entry("source not available", ReasonSourceNotAvailable, conditionSet{
			metav1.ConditionFalse, metav1.ConditionFalse, metav1.ConditionUnknown, metav1.ConditionUnknown}),
		Entry("label not found", ReasonSourceLabelNotFound, conditionSet{
			metav1.ConditionFalse, metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionUnknown}),
		Entry("label invalid", ReasonSourceLabelInvalid, conditionSet{
			metav1.ConditionFalse, metav1.ConditionTrue, metav1.ConditionTrue, metav1.ConditionFalse}),
		Entry("API error", ReasonAPIError, conditionSet{
			metav1.ConditionFalse, metav1.ConditionUnknown, metav1.ConditionUnknown, metav1.ConditionUnknown}),
	)

	It("stamps the generation on every condition and replaces them in place", func() {
		m := &expiringsecretv1alpha1.Monitor{ObjectMeta: metav1.ObjectMeta{Generation: 4}}
		applyConditions(m, ReasonSourceNotAvailable, "gone")
		applyConditions(m, ReasonReady, "Monitor is ready")

		Expect(m.Status.Conditions).To(HaveLen(4))
		for _, c := range m.Status.Conditions {
			Expect(c.ObservedGeneration).To(Equal(int64(4)), c.Type)
			Expect(c.Reason).To(Equal(c.Type))
		}
	})
})

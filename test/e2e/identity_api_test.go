/*
Copyright 2025.

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

package e2e

import (
	"encoding/json"
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"go.miloapis.com/auth-provider-zitadel/test/utils"
	identityv1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
)

// These tests verify the identity API endpoints (Session and UserIdentity)
// exposed by auth-provider-zitadel. They are designed to run against an
// existing deployment and do not require building/deploying the operator.
//
// To run these tests:
//   SKIP_BUILD=true go test -v ./test/e2e -ginkgo.focus="Identity API"
//
// Prerequisites:
//   - auth-provider-zitadel deployed in the cluster
//   - Milo API server accessible via kubectl
//   - Valid authentication configured

var _ = Describe("Identity API", Label("identity-api"), func() {

	// These tests can be run independently without building images
	// by setting SKIP_BUILD=true environment variable

	Context("Session API", func() {
		It("should have the sessions resource registered", func() {
			By("Checking if sessions API resource exists")
			cmd := exec.Command("kubectl", "api-resources", "--api-group=identity.miloapis.com")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to list API resources")
			Expect(output).To(ContainSubstring("sessions"),
				"sessions resource should be registered in identity.miloapis.com API group")
		})

		It("should be able to list Session resources", func() {
			By("Listing Session resources")
			cmd := exec.Command("kubectl", "get", "sessions",
				"--all-namespaces", "-o", "json")
			output, err := utils.Run(cmd)

			// The command should succeed even if there are no items
			Expect(err).NotTo(HaveOccurred(), "Failed to list Session resources")

			By("Verifying the response structure")
			var list identityv1alpha1.SessionList
			err = json.Unmarshal([]byte(output), &list)
			Expect(err).NotTo(HaveOccurred(), "Failed to parse Session list response")

			// Verify it's the correct API version
			Expect(list.APIVersion).To(Equal("identity.miloapis.com/v1alpha1"))
			Expect(list.Kind).To(Equal("SessionList"))
		})

		It("should return Session resources with correct schema if any exist", func() {
			By("Listing Session resources")
			cmd := exec.Command("kubectl", "get", "sessions",
				"--all-namespaces", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var list identityv1alpha1.SessionList
			err = json.Unmarshal([]byte(output), &list)
			Expect(err).NotTo(HaveOccurred())

			// If there are any Session resources, verify their schema
			if len(list.Items) > 0 {
				By("Verifying Session schema for first item")
				session := list.Items[0]

				// Verify metadata
				Expect(session.Name).NotTo(BeEmpty(), "Session should have a name")

				// Verify status fields
				Expect(session.Status.UserUID).NotTo(BeEmpty(),
					"Session status should have userUID")
				Expect(session.Status.Provider).NotTo(BeEmpty(),
					"Session status should have provider")
			} else {
				GinkgoWriter.Println("⚠️  No Session resources found - this is expected if no active sessions exist")
			}
		})

		It("should have correct API group and version", func() {
			By("Verifying API group and version for sessions")
			cmd := exec.Command("kubectl", "api-resources",
				"--api-group=identity.miloapis.com", "-o", "wide")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Expect(output).To(ContainSubstring("sessions"))
			Expect(output).To(ContainSubstring("identity.miloapis.com/v1alpha1"))
			Expect(output).To(ContainSubstring("session"),
				"Should have singular name 'session'")
		})
	})

	Context("UserIdentity API", func() {
		It("should have the useridentities resource registered", func() {
			By("Checking if useridentities API resource exists")
			cmd := exec.Command("kubectl", "api-resources", "--api-group=identity.miloapis.com")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to list API resources")
			Expect(output).To(ContainSubstring("useridentities"),
				"useridentities resource should be registered in identity.miloapis.com API group")
		})

		It("should be able to list UserIdentity resources", func() {
			By("Listing UserIdentity resources")
			cmd := exec.Command("kubectl", "get", "useridentities",
				"--all-namespaces", "-o", "json")
			output, err := utils.Run(cmd)

			// The command should succeed even if there are no items
			Expect(err).NotTo(HaveOccurred(), "Failed to list UserIdentity resources")

			By("Verifying the response structure")
			var list identityv1alpha1.UserIdentityList
			err = json.Unmarshal([]byte(output), &list)
			Expect(err).NotTo(HaveOccurred(), "Failed to parse UserIdentity list response")

			// Verify it's the correct API version
			Expect(list.APIVersion).To(Equal("identity.miloapis.com/v1alpha1"))
			Expect(list.Kind).To(Equal("UserIdentityList"))
		})

		It("should return UserIdentity resources with correct schema if any exist", func() {
			By("Listing UserIdentity resources")
			cmd := exec.Command("kubectl", "get", "useridentities",
				"--all-namespaces", "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			var list identityv1alpha1.UserIdentityList
			err = json.Unmarshal([]byte(output), &list)
			Expect(err).NotTo(HaveOccurred())

			// If there are any UserIdentity resources, verify their schema
			if len(list.Items) > 0 {
				By("Verifying UserIdentity schema for first item")
				userIdentity := list.Items[0]

				// Verify metadata
				Expect(userIdentity.Name).NotTo(BeEmpty(), "UserIdentity should have a name")

				// Verify status fields
				Expect(userIdentity.Status.UserUID).NotTo(BeEmpty(),
					"UserIdentity status should have userUID")
				Expect(userIdentity.Status.ProviderID).NotTo(BeEmpty(),
					"UserIdentity status should have providerID")
				Expect(userIdentity.Status.ProviderName).NotTo(BeEmpty(),
					"UserIdentity status should have providerName")
				Expect(userIdentity.Status.Username).NotTo(BeEmpty(),
					"UserIdentity status should have username")

				GinkgoWriter.Printf("✓ Found UserIdentity: %s (Provider: %s, Username: %s)\n",
					userIdentity.Name,
					userIdentity.Status.ProviderName,
					userIdentity.Status.Username)
			} else {
				GinkgoWriter.Println("⚠️  No UserIdentity resources found - this is expected if no external identities are linked")
			}
		})

		It("should have correct API group and version", func() {
			By("Verifying API group and version for useridentities")
			cmd := exec.Command("kubectl", "api-resources",
				"--api-group=identity.miloapis.com", "-o", "wide")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Expect(output).To(ContainSubstring("useridentities"))
			Expect(output).To(ContainSubstring("identity.miloapis.com/v1alpha1"))
			Expect(output).To(ContainSubstring("useridentity"),
				"Should have singular name 'useridentity'")
		})
	})

	Context("Identity API Integration", func() {
		It("should have both sessions and useridentities in the same API group", func() {
			By("Listing all identity.miloapis.com resources")
			cmd := exec.Command("kubectl", "api-resources", "--api-group=identity.miloapis.com")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			Expect(output).To(ContainSubstring("sessions"),
				"sessions should be in identity.miloapis.com")
			Expect(output).To(ContainSubstring("useridentities"),
				"useridentities should be in identity.miloapis.com")
		})

		It("should be able to describe both resource types", func() {
			By("Describing sessions resource")
			cmd := exec.Command("kubectl", "explain", "sessions")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Should be able to explain sessions resource")

			By("Describing useridentities resource")
			cmd = exec.Command("kubectl", "explain", "useridentities")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Should be able to explain useridentities resource")
		})
	})
})

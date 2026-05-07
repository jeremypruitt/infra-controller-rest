/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package activity

import (
	"context"
	"testing"

	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockIdentityManager builds a ManageMachineIdentity backed by a mock
// ForgeClient that satisfies all 8 identity RPCs (see testing.go in the
// grpc/client package).
func newMockIdentityManager() ManageMachineIdentity {
	mockCarbide := cClient.NewMockNICoClient()
	carbideAtomicClient := cClient.NewNICoCoreAtomicClient(&cClient.NICoCoreClientConfig{})
	carbideAtomicClient.SwapClient(mockCarbide)
	return NewManageMachineIdentity(carbideAtomicClient)
}

// TestManageMachineIdentity_SetIdentityConfigurationOnSite covers the activity wrapper.
func TestManageMachineIdentity_SetIdentityConfigurationOnSite(t *testing.T) {
	m := newMockIdentityManager()
	ctx := context.Background()

	t.Run("success echoes config and assigns keyId", func(t *testing.T) {
		req := &cwssaws.IdentityConfigRequest{
			OrganizationId: "acme-corp",
			Config: &cwssaws.IdentityConfig{
				Enabled:         true,
				Issuer:          "https://carbide.example.com/iss",
				DefaultAudience: "openbao",
				TokenTtlSec:     600,
			},
		}
		resp, err := m.SetIdentityConfigurationOnSite(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "acme-corp", resp.GetOrganizationId())
		assert.NotEmpty(t, resp.GetKeyId(), "site controller assigns a keyId")
		require.NotNil(t, resp.GetConfig())
		assert.Equal(t, "openbao", resp.GetConfig().GetDefaultAudience())
		// On simulated first-create, CreatedAt == UpdatedAt.
		assert.Equal(t, resp.GetCreatedAt().GetSeconds(), resp.GetUpdatedAt().GetSeconds())
	})

	t.Run("rejects nil request", func(t *testing.T) {
		_, err := m.SetIdentityConfigurationOnSite(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("rejects missing organization_id", func(t *testing.T) {
		_, err := m.SetIdentityConfigurationOnSite(ctx, &cwssaws.IdentityConfigRequest{
			Config: &cwssaws.IdentityConfig{DefaultAudience: "openbao"},
		})
		assert.Error(t, err)
	})

	t.Run("rejects missing config", func(t *testing.T) {
		_, err := m.SetIdentityConfigurationOnSite(ctx, &cwssaws.IdentityConfigRequest{
			OrganizationId: "acme-corp",
		})
		assert.Error(t, err)
	})
}

// TestManageMachineIdentity_GetIdentityConfigurationFromSite covers the activity wrapper.
func TestManageMachineIdentity_GetIdentityConfigurationFromSite(t *testing.T) {
	m := newMockIdentityManager()
	ctx := context.Background()

	t.Run("success returns the org's current config", func(t *testing.T) {
		resp, err := m.GetIdentityConfigurationFromSite(ctx, &cwssaws.GetIdentityConfigRequest{
			OrganizationId: "acme-corp",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "acme-corp", resp.GetOrganizationId())
		assert.Equal(t, "mock-key-id", resp.GetKeyId())
	})

	t.Run("rejects nil request", func(t *testing.T) {
		_, err := m.GetIdentityConfigurationFromSite(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("rejects missing organization_id", func(t *testing.T) {
		_, err := m.GetIdentityConfigurationFromSite(ctx, &cwssaws.GetIdentityConfigRequest{})
		assert.Error(t, err)
	})
}

// TestManageMachineIdentity_DeleteIdentityConfigurationOnSite covers the activity wrapper.
func TestManageMachineIdentity_DeleteIdentityConfigurationOnSite(t *testing.T) {
	m := newMockIdentityManager()
	ctx := context.Background()

	t.Run("success returns empty proto", func(t *testing.T) {
		resp, err := m.DeleteIdentityConfigurationOnSite(ctx, &cwssaws.GetIdentityConfigRequest{
			OrganizationId: "acme-corp",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("rejects nil request", func(t *testing.T) {
		_, err := m.DeleteIdentityConfigurationOnSite(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("rejects missing organization_id", func(t *testing.T) {
		_, err := m.DeleteIdentityConfigurationOnSite(ctx, &cwssaws.GetIdentityConfigRequest{})
		assert.Error(t, err)
	})
}

// TestManageMachineIdentity_SetTokenDelegationOnSite covers the activity wrapper.
func TestManageMachineIdentity_SetTokenDelegationOnSite(t *testing.T) {
	m := newMockIdentityManager()
	ctx := context.Background()

	t.Run("success with client_secret_basic (hash returned, raw never)", func(t *testing.T) {
		req := &cwssaws.TokenDelegationRequest{
			OrganizationId: "acme-corp",
			Config: &cwssaws.TokenDelegation{
				TokenEndpoint:        "https://auth.acme.com/oauth2/token",
				SubjectTokenAudience: "acme-exchange",
				AuthMethodConfig: &cwssaws.TokenDelegation_ClientSecretBasic{
					ClientSecretBasic: &cwssaws.ClientSecretBasic{
						ClientId:     "client-123",
						ClientSecret: "super-secret",
					},
				},
			},
		}
		resp, err := m.SetTokenDelegationOnSite(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "acme-corp", resp.GetOrganizationId())
		assert.Equal(t, "https://auth.acme.com/oauth2/token", resp.GetTokenEndpoint())
		basic := resp.GetClientSecretBasic()
		require.NotNil(t, basic, "response oneof should carry hashed client_secret")
		assert.Equal(t, "client-123", basic.GetClientId())
		assert.NotEmpty(t, basic.GetClientSecretHash())

		// Critical security invariant: the raw secret must never appear anywhere
		// in the response proto.
		assert.NotContains(t, basic.GetClientSecretHash(), "super-secret")
	})

	t.Run("success with auth method none (no client_secret_basic)", func(t *testing.T) {
		req := &cwssaws.TokenDelegationRequest{
			OrganizationId: "acme-corp",
			Config: &cwssaws.TokenDelegation{
				TokenEndpoint:        "https://auth.acme.com/oauth2/token",
				SubjectTokenAudience: "acme-exchange",
			},
		}
		resp, err := m.SetTokenDelegationOnSite(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Nil(t, resp.GetAuthMethodConfig(), "oneof should stay unset for auth method none")
	})

	t.Run("rejects nil request", func(t *testing.T) {
		_, err := m.SetTokenDelegationOnSite(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("rejects missing organization_id", func(t *testing.T) {
		_, err := m.SetTokenDelegationOnSite(ctx, &cwssaws.TokenDelegationRequest{
			Config: &cwssaws.TokenDelegation{TokenEndpoint: "https://example.com"},
		})
		assert.Error(t, err)
	})

	t.Run("rejects missing config", func(t *testing.T) {
		_, err := m.SetTokenDelegationOnSite(ctx, &cwssaws.TokenDelegationRequest{
			OrganizationId: "acme-corp",
		})
		assert.Error(t, err)
	})
}

// TestManageMachineIdentity_GetTokenDelegationFromSite covers the activity wrapper.
func TestManageMachineIdentity_GetTokenDelegationFromSite(t *testing.T) {
	m := newMockIdentityManager()
	ctx := context.Background()

	t.Run("success returns hashed secret, never raw", func(t *testing.T) {
		resp, err := m.GetTokenDelegationFromSite(ctx, &cwssaws.GetTokenDelegationRequest{
			OrganizationId: "acme-corp",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "acme-corp", resp.GetOrganizationId())
		basic := resp.GetClientSecretBasic()
		require.NotNil(t, basic)
		assert.NotEmpty(t, basic.GetClientSecretHash())
	})

	t.Run("rejects nil request", func(t *testing.T) {
		_, err := m.GetTokenDelegationFromSite(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("rejects missing organization_id", func(t *testing.T) {
		_, err := m.GetTokenDelegationFromSite(ctx, &cwssaws.GetTokenDelegationRequest{})
		assert.Error(t, err)
	})
}

// TestManageMachineIdentity_DeleteTokenDelegationOnSite covers the activity wrapper.
func TestManageMachineIdentity_DeleteTokenDelegationOnSite(t *testing.T) {
	m := newMockIdentityManager()
	ctx := context.Background()

	t.Run("success returns empty proto", func(t *testing.T) {
		resp, err := m.DeleteTokenDelegationOnSite(ctx, &cwssaws.GetTokenDelegationRequest{
			OrganizationId: "acme-corp",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("rejects nil request", func(t *testing.T) {
		_, err := m.DeleteTokenDelegationOnSite(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("rejects missing organization_id", func(t *testing.T) {
		_, err := m.DeleteTokenDelegationOnSite(ctx, &cwssaws.GetTokenDelegationRequest{})
		assert.Error(t, err)
	})
}

// TestManageMachineIdentity_GetJWKSFromSite covers the activity wrapper.
func TestManageMachineIdentity_GetJWKSFromSite(t *testing.T) {
	m := newMockIdentityManager()
	ctx := context.Background()

	t.Run("success oidc kind yields use=sig", func(t *testing.T) {
		kind := cwssaws.JwksKind_Oidc
		resp, err := m.GetJWKSFromSite(ctx, &cwssaws.JwksRequest{
			OrganizationId: "acme-corp",
			Kind:           &kind,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Contains(t, resp.GetJwks(), `"use":"sig"`)
	})

	t.Run("success spiffe kind yields use=jwt-svid", func(t *testing.T) {
		kind := cwssaws.JwksKind_Spiffe
		resp, err := m.GetJWKSFromSite(ctx, &cwssaws.JwksRequest{
			OrganizationId: "acme-corp",
			Kind:           &kind,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Contains(t, resp.GetJwks(), `"use":"jwt-svid"`)
	})

	t.Run("rejects nil request", func(t *testing.T) {
		_, err := m.GetJWKSFromSite(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("rejects missing organization_id", func(t *testing.T) {
		_, err := m.GetJWKSFromSite(ctx, &cwssaws.JwksRequest{})
		assert.Error(t, err)
	})
}

// TestManageMachineIdentity_GetOpenIDConfigurationFromSite covers the activity wrapper.
func TestManageMachineIdentity_GetOpenIDConfigurationFromSite(t *testing.T) {
	m := newMockIdentityManager()
	ctx := context.Background()

	t.Run("success returns well-formed discovery doc", func(t *testing.T) {
		resp, err := m.GetOpenIDConfigurationFromSite(ctx, &cwssaws.OpenIdConfigRequest{
			OrganizationId: "acme-corp",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.NotEmpty(t, resp.GetIssuer())
		assert.Contains(t, resp.GetJwksUri(), "/.well-known/jwks.json")
		assert.Contains(t, resp.GetSpiffeJwksUri(), "/.well-known/spiffe/jwks.json")
		assert.Equal(t, []string{"token"}, resp.GetResponseTypesSupported())
		assert.Empty(t, resp.GetIdTokenSigningAlgValuesSupported(),
			"Carbide does not issue OIDC id_tokens; this field must be empty")
	})

	t.Run("rejects nil request", func(t *testing.T) {
		_, err := m.GetOpenIDConfigurationFromSite(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("rejects missing organization_id", func(t *testing.T) {
		_, err := m.GetOpenIDConfigurationFromSite(ctx, &cwssaws.OpenIdConfigRequest{})
		assert.Error(t, err)
	})
}

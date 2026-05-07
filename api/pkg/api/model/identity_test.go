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

package model

import (
	"testing"
	"time"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func boolPtr(b bool) *bool       { return &b }
func uint32Ptr(u uint32) *uint32 { return &u }

// TestAPIIdentityConfigUpdateRequest_Validate covers the request validator.
func TestAPIIdentityConfigUpdateRequest_Validate(t *testing.T) {
	// validReq returns a baseline request that satisfies every required
	// field. Per-case overrides can drop or replace fields to exercise the
	// surrounding validation rules.
	validReq := func() APIIdentityConfigUpdateRequest {
		return APIIdentityConfigUpdateRequest{
			OrgID:           "acme-corp",
			DefaultAudience: "openbao",
			Issuer:          strPtr("https://issuer.example.com/"),
			TokenTtlSec:     uint32Ptr(600),
		}
	}

	withIssuer := func(s string) APIIdentityConfigUpdateRequest {
		r := validReq()
		r.Issuer = strPtr(s)
		return r
	}
	withTokenTtlSec := func(v uint32) APIIdentityConfigUpdateRequest {
		r := validReq()
		r.TokenTtlSec = uint32Ptr(v)
		return r
	}

	tests := []struct {
		name    string
		req     APIIdentityConfigUpdateRequest
		wantErr bool
	}{
		{name: "minimum valid", req: validReq()},
		{name: "omitted orgId allowed (URL is authoritative)",
			req: func() APIIdentityConfigUpdateRequest { r := validReq(); r.OrgID = ""; return r }()},
		{name: "missing defaultAudience",
			req:     func() APIIdentityConfigUpdateRequest { r := validReq(); r.DefaultAudience = ""; return r }(),
			wantErr: true},
		{name: "missing issuer",
			req:     func() APIIdentityConfigUpdateRequest { r := validReq(); r.Issuer = nil; return r }(),
			wantErr: true},
		{name: "missing tokenTtlSec",
			req:     func() APIIdentityConfigUpdateRequest { r := validReq(); r.TokenTtlSec = nil; return r }(),
			wantErr: true},
		{name: "empty allowedAudiences accepted",
			req: func() APIIdentityConfigUpdateRequest {
				r := validReq()
				r.AllowedAudiences = []string{}
				return r
			}()},

		{name: "issuer template with {org} placeholder accepted",
			req: withIssuer("https://issuer.example.com/{org}")},
		// REST only checks > 0; the site controller enforces its configured
		// token_ttl_min_sec / token_ttl_max_sec window and rejects with
		// INVALID_ARGUMENT (mapped to 400 by UnwrapWorkflowError).
		{name: "tokenTtlSec zero rejected",
			req:     withTokenTtlSec(0),
			wantErr: true},
		{name: "defaultAudience missing from non-empty allowedAudiences rejected",
			req: func() APIIdentityConfigUpdateRequest {
				r := validReq()
				r.AllowedAudiences = []string{"vault", "spire"}
				return r
			}(),
			wantErr: true},
		{name: "defaultAudience present in non-empty allowedAudiences accepted",
			req: func() APIIdentityConfigUpdateRequest {
				r := validReq()
				r.AllowedAudiences = []string{"openbao", "vault"}
				return r
			}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAPIIdentityConfigUpdateRequest_ToProto covers the request-to-proto mapping.
func TestAPIIdentityConfigUpdateRequest_ToProto(t *testing.T) {
	t.Run("populates all fields", func(t *testing.T) {
		p := APIIdentityConfigUpdateRequest{
			OrgID: "acme-corp", Enabled: boolPtr(true),
			Issuer: strPtr("https://carbide.example.com/iss"), DefaultAudience: "openbao",
			AllowedAudiences: []string{"openbao", "vault"}, TokenTtlSec: uint32Ptr(600),
			SubjectPrefix: strPtr("spiffe://carbide.nvidia.com"), RotateKey: true,
		}.ToProto()
		require.NotNil(t, p)
		assert.Equal(t, "acme-corp", p.GetOrganizationId())
		cfg := p.GetConfig()
		require.NotNil(t, cfg)
		assert.True(t, cfg.GetEnabled())
		assert.Equal(t, "https://carbide.example.com/iss", cfg.GetIssuer())
		assert.Equal(t, "openbao", cfg.GetDefaultAudience())
		assert.Equal(t, []string{"openbao", "vault"}, cfg.GetAllowedAudiences())
		assert.Equal(t, uint32(600), cfg.GetTokenTtlSec())
		assert.Equal(t, "spiffe://carbide.nvidia.com", cfg.GetSubjectPrefix())
		assert.True(t, cfg.GetRotateKey())
	})

	t.Run("enabled defaults to true when nil", func(t *testing.T) {
		p := APIIdentityConfigUpdateRequest{OrgID: "acme-corp", DefaultAudience: "openbao"}.ToProto()
		assert.True(t, p.GetConfig().GetEnabled())
	})

	t.Run("enabled false when explicitly false", func(t *testing.T) {
		p := APIIdentityConfigUpdateRequest{OrgID: "acme-corp", DefaultAudience: "openbao", Enabled: boolPtr(false)}.ToProto()
		assert.False(t, p.GetConfig().GetEnabled())
	})

	t.Run("nil subjectPrefix leaves proto field unset", func(t *testing.T) {
		p := APIIdentityConfigUpdateRequest{OrgID: "acme-corp", DefaultAudience: "openbao"}.ToProto()
		assert.Nil(t, p.GetConfig().SubjectPrefix)
	})
}

// TestNewAPIIdentityConfig covers the proto-to-response mapping.
func TestNewAPIIdentityConfig(t *testing.T) {
	t.Run("full proto", func(t *testing.T) {
		created := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
		updated := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
		subjectPrefix := "spiffe://carbide.nvidia.com"
		resp := NewAPIIdentityConfig(&cwssaws.IdentityConfigResponse{
			OrganizationId: "acme-corp",
			Config: &cwssaws.IdentityConfig{
				Enabled: true, Issuer: "https://carbide.example.com/iss",
				DefaultAudience: "openbao", AllowedAudiences: []string{"openbao"},
				TokenTtlSec: 600, SubjectPrefix: &subjectPrefix,
			},
			KeyId: "key-123", CreatedAt: timestamppb.New(created), UpdatedAt: timestamppb.New(updated),
		})
		require.NotNil(t, resp)
		assert.Equal(t, "acme-corp", resp.OrgID)
		assert.True(t, resp.Enabled)
		assert.Equal(t, "https://carbide.example.com/iss", resp.Issuer)
		assert.Equal(t, "openbao", resp.DefaultAudience)
		assert.Equal(t, []string{"openbao"}, resp.AllowedAudiences)
		assert.Equal(t, uint32(600), resp.TokenTtlSec)
		assert.Equal(t, "spiffe://carbide.nvidia.com", resp.SubjectPrefix)
		assert.Equal(t, "key-123", resp.KeyID)
		assert.Equal(t, "2026-04-20T12:00:00Z", resp.CreatedAt)
		assert.Equal(t, "2026-04-21T12:00:00Z", resp.UpdatedAt)
	})

	t.Run("minimal proto (no Config, no timestamps)", func(t *testing.T) {
		resp := NewAPIIdentityConfig(&cwssaws.IdentityConfigResponse{OrganizationId: "acme-corp", KeyId: "key-123"})
		require.NotNil(t, resp)
		assert.Equal(t, "acme-corp", resp.OrgID)
		assert.Equal(t, "key-123", resp.KeyID)
		assert.False(t, resp.Enabled)
		assert.Empty(t, resp.CreatedAt)
		assert.Empty(t, resp.UpdatedAt)
	})
}

// TestAPITokenDelegationUpdateRequest_Validate covers the request validator.
func TestAPITokenDelegationUpdateRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     APITokenDelegationUpdateRequest
		wantErr bool
	}{
		{name: "valid with client_secret_basic", req: APITokenDelegationUpdateRequest{
			TokenEndpoint:        "https://auth.acme.com/oauth2/token",
			ClientSecretBasic:    &APIClientSecretBasicRequest{ClientID: "client-123", ClientSecret: "super-secret"},
			SubjectTokenAudience: "acme-exchange",
		}},
		{name: "valid without clientSecretBasic (auth method none)",
			req: APITokenDelegationUpdateRequest{TokenEndpoint: "https://auth.acme.com/oauth2/token", SubjectTokenAudience: "acme-exchange"}},
		{name: "missing tokenEndpoint",
			req: APITokenDelegationUpdateRequest{SubjectTokenAudience: "acme-exchange"}, wantErr: true},
		{name: "missing subjectTokenAudience",
			req: APITokenDelegationUpdateRequest{TokenEndpoint: "https://auth.acme.com/oauth2/token"}, wantErr: true},
		{name: "clientSecretBasic missing clientId rejected",
			req: APITokenDelegationUpdateRequest{
				TokenEndpoint:        "https://auth.acme.com/oauth2/token",
				ClientSecretBasic:    &APIClientSecretBasicRequest{ClientSecret: "super-secret"},
				SubjectTokenAudience: "acme-exchange",
			},
			wantErr: true},
		{name: "clientSecretBasic missing clientSecret rejected",
			req: APITokenDelegationUpdateRequest{
				TokenEndpoint:        "https://auth.acme.com/oauth2/token",
				ClientSecretBasic:    &APIClientSecretBasicRequest{ClientID: "client-123"},
				SubjectTokenAudience: "acme-exchange",
			},
			wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAPITokenDelegationUpdateRequest_ToProto covers the request-to-proto mapping.
func TestAPITokenDelegationUpdateRequest_ToProto(t *testing.T) {
	t.Run("with client_secret_basic", func(t *testing.T) {
		p := APITokenDelegationUpdateRequest{
			TokenEndpoint:        "https://auth.acme.com/oauth2/token",
			ClientSecretBasic:    &APIClientSecretBasicRequest{ClientID: "client-123", ClientSecret: "super-secret"},
			SubjectTokenAudience: "acme-exchange",
		}.ToProto("acme-corp")
		require.NotNil(t, p)
		assert.Equal(t, "acme-corp", p.GetOrganizationId())
		cfg := p.GetConfig()
		require.NotNil(t, cfg)
		assert.Equal(t, "https://auth.acme.com/oauth2/token", cfg.GetTokenEndpoint())
		assert.Equal(t, "acme-exchange", cfg.GetSubjectTokenAudience())
		basic := cfg.GetClientSecretBasic()
		require.NotNil(t, basic)
		assert.Equal(t, "client-123", basic.GetClientId())
		assert.Equal(t, "super-secret", basic.GetClientSecret())
	})

	t.Run("without client_secret_basic (auth method none)", func(t *testing.T) {
		p := APITokenDelegationUpdateRequest{
			TokenEndpoint: "https://auth.acme.com/oauth2/token", SubjectTokenAudience: "acme-exchange",
		}.ToProto("acme-corp")
		assert.Nil(t, p.GetConfig().GetAuthMethodConfig())
	})
}

// TestNewAPITokenDelegation covers the proto-to-response mapping.
func TestNewAPITokenDelegation(t *testing.T) {
	t.Run("with client_secret_basic", func(t *testing.T) {
		created := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
		updated := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
		resp := NewAPITokenDelegation(&cwssaws.TokenDelegationResponse{
			OrganizationId:       "acme-corp",
			TokenEndpoint:        "https://auth.acme.com/oauth2/token",
			SubjectTokenAudience: "acme-exchange",
			AuthMethodConfig: &cwssaws.TokenDelegationResponse_ClientSecretBasic{
				ClientSecretBasic: &cwssaws.ClientSecretBasicResponse{
					ClientId: "client-123", ClientSecretHash: "sha256:abcd1234",
				},
			},
			CreatedAt: timestamppb.New(created), UpdatedAt: timestamppb.New(updated),
		})
		require.NotNil(t, resp)
		assert.Equal(t, "acme-corp", resp.OrgID)
		assert.Equal(t, "https://auth.acme.com/oauth2/token", resp.TokenEndpoint)
		assert.Equal(t, "acme-exchange", resp.SubjectTokenAudience)
		require.NotNil(t, resp.ClientSecretBasic)
		assert.Equal(t, "client-123", resp.ClientSecretBasic.ClientID)
		assert.Equal(t, "sha256:abcd1234", resp.ClientSecretBasic.ClientSecretHash)
		assert.Equal(t, "2026-04-20T12:00:00Z", resp.CreatedAt)
		assert.Equal(t, "2026-04-21T12:00:00Z", resp.UpdatedAt)
		assert.NotContains(t, resp.ClientSecretBasic.ClientSecretHash, "super-secret",
			"raw client secret must never appear in response")
	})

	t.Run("none auth method (oneof unset)", func(t *testing.T) {
		resp := NewAPITokenDelegation(&cwssaws.TokenDelegationResponse{
			OrganizationId: "acme-corp", TokenEndpoint: "https://auth.acme.com/oauth2/token",
			SubjectTokenAudience: "acme-exchange",
		})
		require.NotNil(t, resp)
		assert.Nil(t, resp.ClientSecretBasic)
	})
}

// TestNewAPIOpenIDConfiguration covers the proto-to-response mapping.
func TestNewAPIOpenIDConfiguration(t *testing.T) {
	resp := NewAPIOpenIDConfiguration(&cwssaws.OpenIdConfiguration{
		Issuer:                           "https://carbide.example.com/iss",
		JwksUri:                          "https://carbide.example.com/iss/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"token"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{},
		SpiffeJwksUri:                    "https://carbide.example.com/iss/.well-known/spiffe/jwks.json",
	})
	require.NotNil(t, resp)
	assert.Equal(t, "https://carbide.example.com/iss", resp.Issuer)
	assert.Equal(t, "https://carbide.example.com/iss/.well-known/jwks.json", resp.JwksURI)
	assert.Equal(t, []string{"token"}, resp.ResponseTypesSupported)
	assert.Equal(t, []string{"public"}, resp.SubjectTypesSupported)
	assert.Empty(t, resp.IDTokenSigningAlgValuesSupported)
	assert.Equal(t, "https://carbide.example.com/iss/.well-known/spiffe/jwks.json", resp.SpiffeJwksURI)
}

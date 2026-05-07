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
	"errors"
	"time"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// APIIdentityConfigUpdateRequest is the PUT /identity/config body.
type APIIdentityConfigUpdateRequest struct {
	OrgID            string   `json:"orgId,omitempty"`
	Enabled          *bool    `json:"enabled,omitempty"`
	Issuer           *string  `json:"issuer,omitempty"`
	DefaultAudience  string   `json:"defaultAudience"`
	AllowedAudiences []string `json:"allowedAudiences,omitempty"`
	TokenTtlSec      *uint32  `json:"tokenTtlSec,omitempty"`
	SubjectPrefix    *string  `json:"subjectPrefix,omitempty"`
	RotateKey        bool     `json:"rotateKey,omitempty"`
}

// Validate enforces the minimum REST-layer contract: required fields are
// present, `tokenTtlSec > 0`, and `defaultAudience` is a member of
// `allowedAudiences` when the allowlist is non-empty. The site controller
// is authoritative for everything else (issuer URL shape, token TTL window,
// SPIFFE subject prefix format, etc.) and rejects invalid values with
// `400 Bad Request`.
func (req APIIdentityConfigUpdateRequest) Validate() error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.Issuer, validation.Required.Error(validationErrorValueRequired)),
		validation.Field(&req.DefaultAudience, validation.Required.Error(validationErrorValueRequired)),
		validation.Field(&req.TokenTtlSec,
			validation.Required.Error(validationErrorValueRequired),
			validation.Min(uint32(1))),
	); err != nil {
		return err
	}
	if len(req.AllowedAudiences) > 0 {
		found := false
		for _, a := range req.AllowedAudiences {
			if a == req.DefaultAudience {
				found = true
				break
			}
		}
		if !found {
			return validation.Errors{
				"defaultAudience": errors.New("defaultAudience must be a member of non-empty allowedAudiences"),
			}
		}
	}
	return nil
}

// ToProto converts the request to its gRPC form.
func (req APIIdentityConfigUpdateRequest) ToProto() *cwssaws.IdentityConfigRequest {
	cfg := &cwssaws.IdentityConfig{
		DefaultAudience:  req.DefaultAudience,
		AllowedAudiences: req.AllowedAudiences,
		RotateKey:        req.RotateKey,
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	} else {
		cfg.Enabled = true
	}
	if req.Issuer != nil {
		cfg.Issuer = *req.Issuer
	}
	if req.TokenTtlSec != nil {
		cfg.TokenTtlSec = *req.TokenTtlSec
	}
	if req.SubjectPrefix != nil {
		cfg.SubjectPrefix = req.SubjectPrefix
	}

	return &cwssaws.IdentityConfigRequest{
		OrganizationId: req.OrgID,
		Config:         cfg,
	}
}

// APIIdentityConfig is the GET /identity/config response body.
type APIIdentityConfig struct {
	OrgID            string   `json:"orgId"`
	Enabled          bool     `json:"enabled"`
	Issuer           string   `json:"issuer"`
	DefaultAudience  string   `json:"defaultAudience"`
	AllowedAudiences []string `json:"allowedAudiences"`
	TokenTtlSec      uint32   `json:"tokenTtlSec"`
	SubjectPrefix    string   `json:"subjectPrefix"`
	KeyID            string   `json:"keyId"`
	CreatedAt        string   `json:"createdAt,omitempty"`
	UpdatedAt        string   `json:"updatedAt,omitempty"`
}

// NewAPIIdentityConfig builds the response from the gRPC reply.
func NewAPIIdentityConfig(proto *cwssaws.IdentityConfigResponse) *APIIdentityConfig {
	resp := &APIIdentityConfig{
		OrgID: proto.GetOrganizationId(),
		KeyID: proto.GetKeyId(),
	}
	if cfg := proto.GetConfig(); cfg != nil {
		resp.Enabled = cfg.GetEnabled()
		resp.Issuer = cfg.GetIssuer()
		resp.DefaultAudience = cfg.GetDefaultAudience()
		resp.AllowedAudiences = cfg.GetAllowedAudiences()
		resp.TokenTtlSec = cfg.GetTokenTtlSec()
		resp.SubjectPrefix = cfg.GetSubjectPrefix()
	}
	if ts := proto.GetCreatedAt(); ts != nil {
		resp.CreatedAt = ts.AsTime().UTC().Format(time.RFC3339)
	}
	if ts := proto.GetUpdatedAt(); ts != nil {
		resp.UpdatedAt = ts.AsTime().UTC().Format(time.RFC3339)
	}
	return resp
}

// APIClientSecretBasicRequest carries OAuth2 client_secret_basic credentials.
type APIClientSecretBasicRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// APIClientSecretBasicResponse carries the SHA-256 hash of the stored secret.
type APIClientSecretBasicResponse struct {
	ClientID         string `json:"clientId"`
	ClientSecretHash string `json:"clientSecretHash"`
}

// APITokenDelegationUpdateRequest is the PUT /identity/token-delegation body.
type APITokenDelegationUpdateRequest struct {
	TokenEndpoint        string                       `json:"tokenEndpoint"`
	ClientSecretBasic    *APIClientSecretBasicRequest `json:"clientSecretBasic,omitempty"`
	SubjectTokenAudience string                       `json:"subjectTokenAudience"`
}

// Validate enforces the minimum REST-layer contract: required fields are
// present and, when `clientSecretBasic` is set, its sub-fields are too.
// The site controller validates scheme / host of `tokenEndpoint` against
// its configured `token_endpoint_domain_allowlist` and rejects mismatches
// with `400 Bad Request`.
func (req APITokenDelegationUpdateRequest) Validate() error {
	if err := validation.ValidateStruct(&req,
		validation.Field(&req.TokenEndpoint, validation.Required.Error(validationErrorValueRequired)),
		validation.Field(&req.SubjectTokenAudience, validation.Required.Error(validationErrorValueRequired)),
	); err != nil {
		return err
	}
	if req.ClientSecretBasic != nil {
		return validation.ValidateStruct(req.ClientSecretBasic,
			validation.Field(&req.ClientSecretBasic.ClientID, validation.Required.Error(validationErrorValueRequired)),
			validation.Field(&req.ClientSecretBasic.ClientSecret, validation.Required.Error(validationErrorValueRequired)),
		)
	}
	return nil
}

// ToProto converts the request to its gRPC form.
func (req APITokenDelegationUpdateRequest) ToProto(orgID string) *cwssaws.TokenDelegationRequest {
	cfg := &cwssaws.TokenDelegation{
		TokenEndpoint:        req.TokenEndpoint,
		SubjectTokenAudience: req.SubjectTokenAudience,
	}
	if req.ClientSecretBasic != nil {
		cfg.AuthMethodConfig = &cwssaws.TokenDelegation_ClientSecretBasic{
			ClientSecretBasic: &cwssaws.ClientSecretBasic{
				ClientId:     req.ClientSecretBasic.ClientID,
				ClientSecret: req.ClientSecretBasic.ClientSecret,
			},
		}
	}
	return &cwssaws.TokenDelegationRequest{
		OrganizationId: orgID,
		Config:         cfg,
	}
}

// APITokenDelegation is the GET /identity/token-delegation response body.
type APITokenDelegation struct {
	OrgID                string                        `json:"orgId"`
	TokenEndpoint        string                        `json:"tokenEndpoint"`
	ClientSecretBasic    *APIClientSecretBasicResponse `json:"clientSecretBasic,omitempty"`
	SubjectTokenAudience string                        `json:"subjectTokenAudience"`
	CreatedAt            string                        `json:"createdAt,omitempty"`
	UpdatedAt            string                        `json:"updatedAt,omitempty"`
}

// NewAPITokenDelegation builds the response from the gRPC reply.
func NewAPITokenDelegation(proto *cwssaws.TokenDelegationResponse) *APITokenDelegation {
	resp := &APITokenDelegation{
		OrgID:                proto.GetOrganizationId(),
		TokenEndpoint:        proto.GetTokenEndpoint(),
		SubjectTokenAudience: proto.GetSubjectTokenAudience(),
	}
	if basic := proto.GetClientSecretBasic(); basic != nil {
		resp.ClientSecretBasic = &APIClientSecretBasicResponse{
			ClientID:         basic.GetClientId(),
			ClientSecretHash: basic.GetClientSecretHash(),
		}
	}
	if ts := proto.GetCreatedAt(); ts != nil {
		resp.CreatedAt = ts.AsTime().UTC().Format(time.RFC3339)
	}
	if ts := proto.GetUpdatedAt(); ts != nil {
		resp.UpdatedAt = ts.AsTime().UTC().Format(time.RFC3339)
	}
	return resp
}

// APIOpenIDConfiguration is the .well-known/openid-configuration response body.
type APIOpenIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	SpiffeJwksURI                    string   `json:"spiffe_jwks_uri,omitempty"`
}

// NewAPIOpenIDConfiguration builds the response from the gRPC reply.
func NewAPIOpenIDConfiguration(proto *cwssaws.OpenIdConfiguration) *APIOpenIDConfiguration {
	return &APIOpenIDConfiguration{
		Issuer:                           proto.GetIssuer(),
		JwksURI:                          proto.GetJwksUri(),
		ResponseTypesSupported:           proto.GetResponseTypesSupported(),
		SubjectTypesSupported:            proto.GetSubjectTypesSupported(),
		IDTokenSigningAlgValuesSupported: proto.GetIdTokenSigningAlgValuesSupported(),
		SpiffeJwksURI:                    proto.GetSpiffeJwksUri(),
	}
}

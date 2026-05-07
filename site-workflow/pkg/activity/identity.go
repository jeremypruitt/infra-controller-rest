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
	"errors"

	swe "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/error"
	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ManageMachineIdentity wraps the machine-identity activities.
type ManageMachineIdentity struct {
	NICoCoreAtomicClient *client.NICoCoreAtomicClient
}

// NewManageMachineIdentity returns a new ManageMachineIdentity activity manager.
func NewManageMachineIdentity(carbideClient *client.NICoCoreAtomicClient) ManageMachineIdentity {
	return ManageMachineIdentity{
		NICoCoreAtomicClient: carbideClient,
	}
}

// SetIdentityConfigurationOnSite calls Forge.SetIdentityConfiguration.
func (m *ManageMachineIdentity) SetIdentityConfigurationOnSite(
	ctx context.Context,
	request *cwssaws.IdentityConfigRequest,
) (*cwssaws.IdentityConfigResponse, error) {
	logger := log.With().Str("Activity", "SetIdentityConfigurationOnSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty SetIdentityConfiguration request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetOrganizationId() == "" {
		err := errors.New("received SetIdentityConfiguration request missing organization_id")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetConfig() == nil {
		err := errors.New("received SetIdentityConfiguration request missing config")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	carbideClient := m.NICoCoreAtomicClient.GetClient()
	if carbideClient == nil {
		return nil, client.ErrClientNotConnected
	}

	response, err := carbideClient.NICo().SetIdentityConfiguration(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to set identity configuration via Site Controller API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return response, nil
}

// GetIdentityConfigurationFromSite calls Forge.GetIdentityConfiguration.
func (m *ManageMachineIdentity) GetIdentityConfigurationFromSite(
	ctx context.Context,
	request *cwssaws.GetIdentityConfigRequest,
) (*cwssaws.IdentityConfigResponse, error) {
	logger := log.With().Str("Activity", "GetIdentityConfigurationFromSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty GetIdentityConfiguration request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetOrganizationId() == "" {
		err := errors.New("received GetIdentityConfiguration request missing organization_id")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	carbideClient := m.NICoCoreAtomicClient.GetClient()
	if carbideClient == nil {
		return nil, client.ErrClientNotConnected
	}

	response, err := carbideClient.NICo().GetIdentityConfiguration(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get identity configuration via Site Controller API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return response, nil
}

// DeleteIdentityConfigurationOnSite calls Forge.DeleteIdentityConfiguration.
func (m *ManageMachineIdentity) DeleteIdentityConfigurationOnSite(
	ctx context.Context,
	request *cwssaws.GetIdentityConfigRequest,
) (*emptypb.Empty, error) {
	logger := log.With().Str("Activity", "DeleteIdentityConfigurationOnSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty DeleteIdentityConfiguration request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetOrganizationId() == "" {
		err := errors.New("received DeleteIdentityConfiguration request missing organization_id")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	carbideClient := m.NICoCoreAtomicClient.GetClient()
	if carbideClient == nil {
		return nil, client.ErrClientNotConnected
	}

	response, err := carbideClient.NICo().DeleteIdentityConfiguration(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to delete identity configuration via Site Controller API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return response, nil
}

// SetTokenDelegationOnSite calls Forge.SetTokenDelegation.
func (m *ManageMachineIdentity) SetTokenDelegationOnSite(
	ctx context.Context,
	request *cwssaws.TokenDelegationRequest,
) (*cwssaws.TokenDelegationResponse, error) {
	logger := log.With().Str("Activity", "SetTokenDelegationOnSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty SetTokenDelegation request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetOrganizationId() == "" {
		err := errors.New("received SetTokenDelegation request missing organization_id")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetConfig() == nil {
		err := errors.New("received SetTokenDelegation request missing config")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	carbideClient := m.NICoCoreAtomicClient.GetClient()
	if carbideClient == nil {
		return nil, client.ErrClientNotConnected
	}

	response, err := carbideClient.NICo().SetTokenDelegation(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to set token delegation via Site Controller API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return response, nil
}

// GetTokenDelegationFromSite calls Forge.GetTokenDelegation.
func (m *ManageMachineIdentity) GetTokenDelegationFromSite(
	ctx context.Context,
	request *cwssaws.GetTokenDelegationRequest,
) (*cwssaws.TokenDelegationResponse, error) {
	logger := log.With().Str("Activity", "GetTokenDelegationFromSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty GetTokenDelegation request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetOrganizationId() == "" {
		err := errors.New("received GetTokenDelegation request missing organization_id")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	carbideClient := m.NICoCoreAtomicClient.GetClient()
	if carbideClient == nil {
		return nil, client.ErrClientNotConnected
	}

	response, err := carbideClient.NICo().GetTokenDelegation(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get token delegation via Site Controller API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return response, nil
}

// DeleteTokenDelegationOnSite calls Forge.DeleteTokenDelegation.
func (m *ManageMachineIdentity) DeleteTokenDelegationOnSite(
	ctx context.Context,
	request *cwssaws.GetTokenDelegationRequest,
) (*emptypb.Empty, error) {
	logger := log.With().Str("Activity", "DeleteTokenDelegationOnSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty DeleteTokenDelegation request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetOrganizationId() == "" {
		err := errors.New("received DeleteTokenDelegation request missing organization_id")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	carbideClient := m.NICoCoreAtomicClient.GetClient()
	if carbideClient == nil {
		return nil, client.ErrClientNotConnected
	}

	response, err := carbideClient.NICo().DeleteTokenDelegation(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to delete token delegation via Site Controller API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return response, nil
}

// GetJWKSFromSite calls Forge.GetJWKS.
func (m *ManageMachineIdentity) GetJWKSFromSite(
	ctx context.Context,
	request *cwssaws.JwksRequest,
) (*cwssaws.Jwks, error) {
	logger := log.With().Str("Activity", "GetJWKSFromSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty GetJWKS request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetOrganizationId() == "" {
		err := errors.New("received GetJWKS request missing organization_id")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	carbideClient := m.NICoCoreAtomicClient.GetClient()
	if carbideClient == nil {
		return nil, client.ErrClientNotConnected
	}

	response, err := carbideClient.NICo().GetJWKS(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get JWKS via Site Controller API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return response, nil
}

// GetOpenIDConfigurationFromSite calls Forge.GetOpenIDConfiguration.
func (m *ManageMachineIdentity) GetOpenIDConfigurationFromSite(
	ctx context.Context,
	request *cwssaws.OpenIdConfigRequest,
) (*cwssaws.OpenIdConfiguration, error) {
	logger := log.With().Str("Activity", "GetOpenIDConfigurationFromSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty GetOpenIDConfiguration request")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetOrganizationId() == "" {
		err := errors.New("received GetOpenIDConfiguration request missing organization_id")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	carbideClient := m.NICoCoreAtomicClient.GetClient()
	if carbideClient == nil {
		return nil, client.ErrClientNotConnected
	}

	response, err := carbideClient.NICo().GetOpenIDConfiguration(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get OpenID configuration via Site Controller API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return response, nil
}

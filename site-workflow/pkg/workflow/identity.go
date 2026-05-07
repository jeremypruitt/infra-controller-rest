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

package workflow

import (
	"time"

	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/types/known/emptypb"
)

// machineIdentityActivityOptions are the activity options for identity workflows.
func machineIdentityActivityOptions() workflow.ActivityOptions {
	return workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    1 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumInterval:    10 * time.Second,
			MaximumAttempts:    3,
		},
	}
}

// SetIdentityConfiguration proxies PUT /identity/config to the site controller.
func SetIdentityConfiguration(ctx workflow.Context, request *cwssaws.IdentityConfigRequest) (*cwssaws.IdentityConfigResponse, error) {
	logger := log.With().Str("Workflow", "SetIdentityConfiguration").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, machineIdentityActivityOptions())

	var manager activity.ManageMachineIdentity
	var response cwssaws.IdentityConfigResponse
	if err := workflow.ExecuteActivity(ctx, manager.SetIdentityConfigurationOnSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "SetIdentityConfigurationOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// GetIdentityConfiguration proxies GET /identity/config to the site controller.
func GetIdentityConfiguration(ctx workflow.Context, request *cwssaws.GetIdentityConfigRequest) (*cwssaws.IdentityConfigResponse, error) {
	logger := log.With().Str("Workflow", "GetIdentityConfiguration").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, machineIdentityActivityOptions())

	var manager activity.ManageMachineIdentity
	var response cwssaws.IdentityConfigResponse
	if err := workflow.ExecuteActivity(ctx, manager.GetIdentityConfigurationFromSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "GetIdentityConfigurationFromSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// DeleteIdentityConfiguration proxies DELETE /identity/config to the site controller.
func DeleteIdentityConfiguration(ctx workflow.Context, request *cwssaws.GetIdentityConfigRequest) (*emptypb.Empty, error) {
	logger := log.With().Str("Workflow", "DeleteIdentityConfiguration").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, machineIdentityActivityOptions())

	var manager activity.ManageMachineIdentity
	var response emptypb.Empty
	if err := workflow.ExecuteActivity(ctx, manager.DeleteIdentityConfigurationOnSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteIdentityConfigurationOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// SetTokenDelegation proxies PUT /identity/token-delegation to the site controller.
func SetTokenDelegation(ctx workflow.Context, request *cwssaws.TokenDelegationRequest) (*cwssaws.TokenDelegationResponse, error) {
	logger := log.With().Str("Workflow", "SetTokenDelegation").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, machineIdentityActivityOptions())

	var manager activity.ManageMachineIdentity
	var response cwssaws.TokenDelegationResponse
	if err := workflow.ExecuteActivity(ctx, manager.SetTokenDelegationOnSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "SetTokenDelegationOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// GetTokenDelegation proxies GET /identity/token-delegation to the site controller.
func GetTokenDelegation(ctx workflow.Context, request *cwssaws.GetTokenDelegationRequest) (*cwssaws.TokenDelegationResponse, error) {
	logger := log.With().Str("Workflow", "GetTokenDelegation").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, machineIdentityActivityOptions())

	var manager activity.ManageMachineIdentity
	var response cwssaws.TokenDelegationResponse
	if err := workflow.ExecuteActivity(ctx, manager.GetTokenDelegationFromSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "GetTokenDelegationFromSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// DeleteTokenDelegation proxies DELETE /identity/token-delegation to the site controller.
func DeleteTokenDelegation(ctx workflow.Context, request *cwssaws.GetTokenDelegationRequest) (*emptypb.Empty, error) {
	logger := log.With().Str("Workflow", "DeleteTokenDelegation").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, machineIdentityActivityOptions())

	var manager activity.ManageMachineIdentity
	var response emptypb.Empty
	if err := workflow.ExecuteActivity(ctx, manager.DeleteTokenDelegationOnSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteTokenDelegationOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// GetJWKS proxies GET /.well-known/jwks.json to the site controller.
func GetJWKS(ctx workflow.Context, request *cwssaws.JwksRequest) (*cwssaws.Jwks, error) {
	logger := log.With().Str("Workflow", "GetJWKS").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, machineIdentityActivityOptions())

	var manager activity.ManageMachineIdentity
	var response cwssaws.Jwks
	if err := workflow.ExecuteActivity(ctx, manager.GetJWKSFromSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "GetJWKSFromSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// GetOpenIDConfiguration proxies GET /.well-known/openid-configuration to the site controller.
func GetOpenIDConfiguration(ctx workflow.Context, request *cwssaws.OpenIdConfigRequest) (*cwssaws.OpenIdConfiguration, error) {
	logger := log.With().Str("Workflow", "GetOpenIDConfiguration").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, machineIdentityActivityOptions())

	var manager activity.ManageMachineIdentity
	var response cwssaws.OpenIdConfiguration
	if err := workflow.ExecuteActivity(ctx, manager.GetOpenIDConfigurationFromSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "GetOpenIDConfigurationFromSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

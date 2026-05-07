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

package identity

import (
	swa "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	sww "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/workflow"
)

// RegisterSubscriber registers the MachineIdentity workflows/activities with
// the Temporal worker — one workflow+activity pair per Forge identity RPC.
func (MachineIdentity *API) RegisterSubscriber() error {
	ManagerAccess.Data.EB.Log.Info().Msg("MachineIdentity: Registering the subscribers")

	manager := swa.NewManageMachineIdentity(ManagerAccess.Data.EB.Managers.NICo.Client)
	w := ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker

	// Identity configuration workflows (PUT/GET/DELETE /identity/config)
	w.RegisterWorkflow(sww.SetIdentityConfiguration)
	w.RegisterActivity(manager.SetIdentityConfigurationOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("MachineIdentity: successfully registered SetIdentityConfiguration workflow + activity")

	w.RegisterWorkflow(sww.GetIdentityConfiguration)
	w.RegisterActivity(manager.GetIdentityConfigurationFromSite)
	ManagerAccess.Data.EB.Log.Info().Msg("MachineIdentity: successfully registered GetIdentityConfiguration workflow + activity")

	w.RegisterWorkflow(sww.DeleteIdentityConfiguration)
	w.RegisterActivity(manager.DeleteIdentityConfigurationOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("MachineIdentity: successfully registered DeleteIdentityConfiguration workflow + activity")

	// Token delegation workflows (PUT/GET/DELETE /identity/token-delegation)
	w.RegisterWorkflow(sww.SetTokenDelegation)
	w.RegisterActivity(manager.SetTokenDelegationOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("MachineIdentity: successfully registered SetTokenDelegation workflow + activity")

	w.RegisterWorkflow(sww.GetTokenDelegation)
	w.RegisterActivity(manager.GetTokenDelegationFromSite)
	ManagerAccess.Data.EB.Log.Info().Msg("MachineIdentity: successfully registered GetTokenDelegation workflow + activity")

	w.RegisterWorkflow(sww.DeleteTokenDelegation)
	w.RegisterActivity(manager.DeleteTokenDelegationOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("MachineIdentity: successfully registered DeleteTokenDelegation workflow + activity")

	// Public .well-known workflows (GET JWKS + OIDC discovery)
	w.RegisterWorkflow(sww.GetJWKS)
	w.RegisterActivity(manager.GetJWKSFromSite)
	ManagerAccess.Data.EB.Log.Info().Msg("MachineIdentity: successfully registered GetJWKS workflow + activity")

	w.RegisterWorkflow(sww.GetOpenIDConfiguration)
	w.RegisterActivity(manager.GetOpenIDConfigurationFromSite)
	ManagerAccess.Data.EB.Log.Info().Msg("MachineIdentity: successfully registered GetOpenIDConfiguration workflow + activity")

	return nil
}

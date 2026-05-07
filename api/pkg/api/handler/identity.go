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

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	oteltrace "go.opentelemetry.io/otel/trace"
	temporalEnums "go.temporal.io/api/enums/v1"
	tclient "go.temporal.io/sdk/client"
	tp "go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller-rest/api/pkg/client/site"
	auth "github.com/NVIDIA/infra-controller-rest/auth/pkg/authorization"
	cutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/NVIDIA/infra-controller-rest/workflow/pkg/queue"
)

// payloadHash returns a deterministic short hex digest of the proto message.
func payloadHash(m proto.Message) (string, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8]), nil
}

// putStatusFromTimestamps decides between 201 Created and 200 OK for the
// idempotent PUT identity-config / token-delegation handlers.
//
// The site controller stamps `created_at` and `updated_at` from the same
// transaction on a brand-new row, so equality of the two protobuf timestamps
// is a faithful "this PUT just created the resource" signal. On any
// subsequent PUT, only `updated_at` advances and the timestamps differ.
//
// If either timestamp is missing (older controller versions, mocks) we fall
// back to 200, matching pre-fix behavior.
func putStatusFromTimestamps(createdAt, updatedAt *timestamppb.Timestamp) int {
	if createdAt == nil || updatedAt == nil {
		return http.StatusOK
	}
	if !createdAt.AsTime().Equal(updatedAt.AsTime()) {
		return http.StatusOK
	}
	return http.StatusCreated
}

// ~~~~~ Shared Setup ~~~~~ //

// setupAuthedIdentityHandler runs the auth and site lookup shared by the
// authenticated identity handlers.
func setupAuthedIdentityHandler(
	c echo.Context,
	modelName, handlerName string,
	dbSession *cdb.Session,
	scp *sc.ClientPool,
	tracerSpan *cutil.TracerSpan,
) (org string, site *cdbm.Site, temporalClient tclient.Client, span oteltrace.Span, logger zerolog.Logger, ctx context.Context, apiErr error) {
	var dbUser *cdbm.User
	org, dbUser, ctx, logger, span = common.SetupHandler(modelName, handlerName, c, tracerSpan)

	if dbUser == nil {
		return "", nil, nil, span, logger, ctx, cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	siteID := c.Param("siteID")
	if siteID == "" {
		return "", nil, nil, span, logger, ctx, cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Missing siteID path parameter", nil)
	}

	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return "", nil, nil, span, logger, ctx, cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role, access denied")
		return "", nil, nil, span, logger, ctx, cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	if _, err = common.GetTenantForOrg(ctx, nil, dbSession, org); err != nil {
		if err == common.ErrOrgTenantNotFound {
			return "", nil, nil, span, logger, ctx, cutil.NewAPIErrorResponse(c, http.StatusNotFound, fmt.Sprintf("Org '%s' does not have a Tenant", org), nil)
		}
		logger.Error().Err(err).Msg("error retrieving Tenant for this org")
		return "", nil, nil, span, logger, ctx, cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Tenant", nil)
	}

	site, err = common.GetSiteFromIDString(ctx, nil, siteID, dbSession)
	if err != nil {
		logger.Warn().Err(err).Str("Site ID", siteID).Msg("error getting site from request")
		return "", nil, nil, span, logger, ctx, cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error retrieving Site in request", nil)
	}

	temporalClient, err = scp.GetClientByID(site.ID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve Temporal client for Site")
		return "", nil, nil, span, logger, ctx, cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve client for Site", nil)
	}
	return org, site, temporalClient, span, logger, ctx, nil
}

var errPublicIdentityAbsent = errors.New("public identity: no material available for (org, site)")

// setupPublicIdentityHandler resolves the site and tenant for a .well-known
// route. Validation is intentionally limited to "Site is known" and "org has
// a Tenant"; the site controller is authoritative for whether key material
// actually exists, and JWT-SVIDs may stay valid past any allocation lifetime,
// so allocation state must not gate JWKS lookup. "No keys available" is
// surfaced by the JWKS handler as an empty keyset and by the OIDC handler as
// 404.
func setupPublicIdentityHandler(
	c echo.Context,
	dbSession *cdb.Session,
	scp *sc.ClientPool,
) (org string, site *cdbm.Site, temporalClient tclient.Client, logger zerolog.Logger, ctx context.Context, apiErr error) {
	ctx = c.Request().Context()
	org = strings.ToLower(c.Param("orgName"))
	siteID := c.Param("siteID")
	logger = zerolog.Ctx(ctx).With().
		Str("Model", "MachineIdentity").
		Str("Handler", "WellKnown").
		Str("Org", org).
		Str("Site ID", siteID).
		Logger()

	if org == "" || siteID == "" {
		logger.Warn().Msg("missing orgName or siteID path parameter")
		return "", nil, nil, logger, ctx, errPublicIdentityAbsent
	}

	site, err := common.GetSiteFromIDString(ctx, nil, siteID, dbSession)
	if err != nil {
		logger.Warn().Err(err).Msg("error getting Site from request")
		return "", nil, nil, logger, ctx, errPublicIdentityAbsent
	}

	if _, err := common.GetTenantForOrg(ctx, nil, dbSession, org); err != nil {
		if err == common.ErrOrgTenantNotFound {
			logger.Info().Msg("Org does not have a Tenant")
			return "", nil, nil, logger, ctx, errPublicIdentityAbsent
		}
		logger.Error().Err(err).Msg("error retrieving Tenant for Org")
		return "", nil, nil, logger, ctx, cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Tenant", nil)
	}

	temporalClient, err = scp.GetClientByID(site.ID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve Temporal client for Site")
		return "", nil, nil, logger, ctx, cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve client for Site", nil)
	}
	return org, site, temporalClient, logger, ctx, nil
}

// writeEmptyJWKS writes an empty JWKS response. Content-Type is set
// explicitly because raw Write would otherwise let net/http sniff the body
// and ship it as text/plain.
func writeEmptyJWKS(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	_, werr := c.Response().Write([]byte(`{"keys":[]}`))
	return werr
}

// ~~~~~ Update Handler ~~~~~ //

// UpdateIdentityConfigHandler handles PUT /identity/config.
type UpdateIdentityConfigHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewUpdateIdentityConfigHandler returns a new UpdateIdentityConfigHandler.
func NewUpdateIdentityConfigHandler(dbSession *cdb.Session, scp *sc.ClientPool) UpdateIdentityConfigHandler {
	return UpdateIdentityConfigHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Update Machine Identity Configuration
// @Description Create or update the per-tenant machine identity (SPIFFE JWT-SVID) configuration. First call for a tenant generates the signing keypair.
// @Tags MachineIdentity
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteID path string true "ID of Site"
// @Param message body model.APIIdentityConfigUpdateRequest true "Machine Identity Configuration update request"
// @Success 201 {object} model.APIIdentityConfig "Configuration created on first call"
// @Success 200 {object} model.APIIdentityConfig "Configuration replaced/updated"
// @Failure 503 {object} util.APIError
// @Router /v2/org/{org}/carbide/site/{siteID}/identity/config [put]
func (uich UpdateIdentityConfigHandler) Handle(c echo.Context) error {
	org, site, temporalClient, span, logger, ctx, apiErr := setupAuthedIdentityHandler(c, "MachineIdentity", "Update", uich.dbSession, uich.scp, uich.tracerSpan)
	if span != nil {
		defer span.End()
	}
	if apiErr != nil {
		return apiErr
	}

	apiRequest := model.APIIdentityConfigUpdateRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}
	if verr := apiRequest.Validate(); verr != nil {
		logger.Warn().Err(verr).Msg("error validating Machine Identity Configuration update request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating Machine Identity Configuration update request data", verr)
	}

	if apiRequest.OrgID != "" && apiRequest.OrgID != org {
		logger.Warn().Str("urlOrg", org).Str("bodyOrgId", apiRequest.OrgID).Msg("orgId in request body does not match URL")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "If provided, orgId in request body must match URL org", nil)
	}
	apiRequest.OrgID = org

	protoRequest := apiRequest.ToProto()

	hash, err := payloadHash(protoRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to hash request payload for workflow ID")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to hash request payload", nil)
	}
	workflowOptions := tclient.StartWorkflowOptions{
		ID:                       "machine-identity-update-config-" + org + "-" + site.ID.String() + "-" + hash,
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
		WorkflowIDConflictPolicy: temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}

	ctx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := temporalClient.ExecuteWorkflow(ctx, workflowOptions, "SetIdentityConfiguration", protoRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to synchronously start Temporal workflow to set Machine Identity Configuration")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to start workflow to set Machine Identity Configuration", nil)
	}

	wid := we.GetID()
	logger.Info().Str("Workflow ID", wid).Msg("executed synchronous set Machine Identity Configuration workflow")

	var protoResponse cwssaws.IdentityConfigResponse
	err = we.Get(ctx, &protoResponse)
	if err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || ctx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, temporalClient, wid, err, "MachineIdentity", "SetIdentityConfiguration")
		}

		code, unwrapped := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to set Machine Identity Configuration")
		return cutil.NewAPIErrorResponse(c, code, "Failed to set Machine Identity Configuration", nil)
	}

	status := putStatusFromTimestamps(protoResponse.GetCreatedAt(), protoResponse.GetUpdatedAt())
	return c.JSON(status, model.NewAPIIdentityConfig(&protoResponse))
}

// ~~~~~ Get Handler ~~~~~ //

// GetIdentityConfigHandler handles GET /identity/config.
type GetIdentityConfigHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewGetIdentityConfigHandler returns a new GetIdentityConfigHandler.
func NewGetIdentityConfigHandler(dbSession *cdb.Session, scp *sc.ClientPool) GetIdentityConfigHandler {
	return GetIdentityConfigHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Retrieve Machine Identity Configuration for an org
// @Description Retrieve the current per-org machine identity configuration and active key ID.
// @Tags MachineIdentity
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteID path string true "ID of Site"
// @Success 200 {object} model.APIIdentityConfig
// @Router /v2/org/{org}/carbide/site/{siteID}/identity/config [get]
func (gich GetIdentityConfigHandler) Handle(c echo.Context) error {
	org, site, temporalClient, span, logger, ctx, apiErr := setupAuthedIdentityHandler(c, "MachineIdentity", "Get", gich.dbSession, gich.scp, gich.tracerSpan)
	if span != nil {
		defer span.End()
	}
	if apiErr != nil {
		return apiErr
	}

	protoRequest := &cwssaws.GetIdentityConfigRequest{OrganizationId: org}

	workflowOptions := tclient.StartWorkflowOptions{
		ID:                       "machine-identity-get-config-" + org + "-" + site.ID.String(),
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
		WorkflowIDConflictPolicy: temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}

	ctx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := temporalClient.ExecuteWorkflow(ctx, workflowOptions, "GetIdentityConfiguration", protoRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to synchronously start Temporal workflow to get Machine Identity Configuration")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to start workflow to get Machine Identity Configuration", nil)
	}

	wid := we.GetID()
	logger.Info().Str("Workflow ID", wid).Msg("executed synchronous get Machine Identity Configuration workflow")

	var protoResponse cwssaws.IdentityConfigResponse
	err = we.Get(ctx, &protoResponse)
	if err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || ctx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, temporalClient, wid, err, "MachineIdentity", "GetIdentityConfiguration")
		}

		code, unwrapped := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to get Machine Identity Configuration")
		return cutil.NewAPIErrorResponse(c, code, "Failed to get Machine Identity Configuration", nil)
	}

	return c.JSON(http.StatusOK, model.NewAPIIdentityConfig(&protoResponse))
}

// ~~~~~ Delete Handler ~~~~~ //

// DeleteIdentityConfigHandler handles DELETE /identity/config.
type DeleteIdentityConfigHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewDeleteIdentityConfigHandler returns a new DeleteIdentityConfigHandler.
func NewDeleteIdentityConfigHandler(dbSession *cdb.Session, scp *sc.ClientPool) DeleteIdentityConfigHandler {
	return DeleteIdentityConfigHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Delete Machine Identity Configuration
// @Description Remove the per-org machine identity configuration and signing key. In-flight tokens remain valid until natural expiry.
// @Tags MachineIdentity
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteID path string true "ID of Site"
// @Success 204
// @Router /v2/org/{org}/carbide/site/{siteID}/identity/config [delete]
func (dich DeleteIdentityConfigHandler) Handle(c echo.Context) error {
	org, site, temporalClient, span, logger, ctx, apiErr := setupAuthedIdentityHandler(c, "MachineIdentity", "Delete", dich.dbSession, dich.scp, dich.tracerSpan)
	if span != nil {
		defer span.End()
	}
	if apiErr != nil {
		return apiErr
	}

	protoRequest := &cwssaws.GetIdentityConfigRequest{OrganizationId: org}

	workflowOptions := tclient.StartWorkflowOptions{
		ID:                       "machine-identity-delete-config-" + org + "-" + site.ID.String(),
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
		WorkflowIDConflictPolicy: temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}

	ctx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := temporalClient.ExecuteWorkflow(ctx, workflowOptions, "DeleteIdentityConfiguration", protoRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to synchronously start Temporal workflow to delete Machine Identity Configuration")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to start workflow to delete Machine Identity Configuration", nil)
	}

	wid := we.GetID()
	logger.Info().Str("Workflow ID", wid).Msg("executed synchronous delete Machine Identity Configuration workflow")

	err = we.Get(ctx, nil)
	if err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || ctx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, temporalClient, wid, err, "MachineIdentity", "DeleteIdentityConfiguration")
		}

		code, unwrapped := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to delete Machine Identity Configuration")
		return cutil.NewAPIErrorResponse(c, code, "Failed to delete Machine Identity Configuration", nil)
	}

	return c.NoContent(http.StatusNoContent)
}

// ~~~~~ Update Token Delegation Handler ~~~~~ //

// UpdateTokenDelegationHandler handles PUT /identity/token-delegation.
type UpdateTokenDelegationHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewUpdateTokenDelegationHandler returns a new UpdateTokenDelegationHandler.
func NewUpdateTokenDelegationHandler(dbSession *cdb.Session, scp *sc.ClientPool) UpdateTokenDelegationHandler {
	return UpdateTokenDelegationHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Update Token Delegation
// @Description Register an RFC 8693 token exchange callback URL for the org. Requires identity/config to exist first.
// @Tags MachineIdentity
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteID path string true "ID of Site"
// @Param message body model.APITokenDelegationUpdateRequest true "Token Delegation update request"
// @Success 201 {object} model.APITokenDelegation "Token delegation created on first call"
// @Success 200 {object} model.APITokenDelegation "Token delegation replaced/updated"
// @Failure 503 {object} util.APIError
// @Router /v2/org/{org}/carbide/site/{siteID}/identity/token-delegation [put]
func (utdh UpdateTokenDelegationHandler) Handle(c echo.Context) error {
	org, site, temporalClient, span, logger, ctx, apiErr := setupAuthedIdentityHandler(c, "TokenDelegation", "Update", utdh.dbSession, utdh.scp, utdh.tracerSpan)
	if span != nil {
		defer span.End()
	}
	if apiErr != nil {
		return apiErr
	}

	apiRequest := model.APITokenDelegationUpdateRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}
	if verr := apiRequest.Validate(); verr != nil {
		logger.Warn().Err(verr).Msg("error validating Token Delegation update request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating Token Delegation update request data", verr)
	}

	protoRequest := apiRequest.ToProto(org)

	hash, err := payloadHash(protoRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to hash request payload for workflow ID")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to hash request payload", nil)
	}
	workflowOptions := tclient.StartWorkflowOptions{
		ID:                       "machine-identity-update-token-delegation-" + org + "-" + site.ID.String() + "-" + hash,
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
		WorkflowIDConflictPolicy: temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}

	ctx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := temporalClient.ExecuteWorkflow(ctx, workflowOptions, "SetTokenDelegation", protoRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to synchronously start Temporal workflow to set Token Delegation")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to start workflow to set Token Delegation", nil)
	}

	wid := we.GetID()
	logger.Info().Str("Workflow ID", wid).Msg("executed synchronous set Token Delegation workflow")

	var protoResponse cwssaws.TokenDelegationResponse
	err = we.Get(ctx, &protoResponse)
	if err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || ctx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, temporalClient, wid, err, "TokenDelegation", "SetTokenDelegation")
		}

		code, unwrapped := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to set Token Delegation")
		return cutil.NewAPIErrorResponse(c, code, "Failed to set Token Delegation", nil)
	}

	status := putStatusFromTimestamps(protoResponse.GetCreatedAt(), protoResponse.GetUpdatedAt())
	return c.JSON(status, model.NewAPITokenDelegation(&protoResponse))
}

// ~~~~~ Get Token Delegation Handler ~~~~~ //

// GetTokenDelegationHandler handles GET /identity/token-delegation.
type GetTokenDelegationHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewGetTokenDelegationHandler returns a new GetTokenDelegationHandler.
func NewGetTokenDelegationHandler(dbSession *cdb.Session, scp *sc.ClientPool) GetTokenDelegationHandler {
	return GetTokenDelegationHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Retrieve Token Delegation for an org
// @Description Retrieve the currently registered token exchange endpoint. The raw secret is never returned; only its SHA-256 hash.
// @Tags MachineIdentity
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteID path string true "ID of Site"
// @Success 200 {object} model.APITokenDelegation
// @Router /v2/org/{org}/carbide/site/{siteID}/identity/token-delegation [get]
func (gtdh GetTokenDelegationHandler) Handle(c echo.Context) error {
	org, site, temporalClient, span, logger, ctx, apiErr := setupAuthedIdentityHandler(c, "TokenDelegation", "Get", gtdh.dbSession, gtdh.scp, gtdh.tracerSpan)
	if span != nil {
		defer span.End()
	}
	if apiErr != nil {
		return apiErr
	}

	protoRequest := &cwssaws.GetTokenDelegationRequest{OrganizationId: org}

	workflowOptions := tclient.StartWorkflowOptions{
		ID:                       "machine-identity-get-token-delegation-" + org + "-" + site.ID.String(),
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
		WorkflowIDConflictPolicy: temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}

	ctx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := temporalClient.ExecuteWorkflow(ctx, workflowOptions, "GetTokenDelegation", protoRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to synchronously start Temporal workflow to get Token Delegation")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to start workflow to get Token Delegation", nil)
	}

	wid := we.GetID()
	logger.Info().Str("Workflow ID", wid).Msg("executed synchronous get Token Delegation workflow")

	var protoResponse cwssaws.TokenDelegationResponse
	err = we.Get(ctx, &protoResponse)
	if err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || ctx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, temporalClient, wid, err, "TokenDelegation", "GetTokenDelegation")
		}

		code, unwrapped := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to get Token Delegation")
		return cutil.NewAPIErrorResponse(c, code, "Failed to get Token Delegation", nil)
	}

	return c.JSON(http.StatusOK, model.NewAPITokenDelegation(&protoResponse))
}

// ~~~~~ Delete Token Delegation Handler ~~~~~ //

// DeleteTokenDelegationHandler handles DELETE /identity/token-delegation.
type DeleteTokenDelegationHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewDeleteTokenDelegationHandler returns a new DeleteTokenDelegationHandler.
func NewDeleteTokenDelegationHandler(dbSession *cdb.Session, scp *sc.ClientPool) DeleteTokenDelegationHandler {
	return DeleteTokenDelegationHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Delete Token Delegation
// @Description Remove the RFC 8693 token exchange callback. Subsequent IMDS requests revert to direct token issuance.
// @Tags MachineIdentity
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteID path string true "ID of Site"
// @Success 204
// @Router /v2/org/{org}/carbide/site/{siteID}/identity/token-delegation [delete]
func (dtdh DeleteTokenDelegationHandler) Handle(c echo.Context) error {
	org, site, temporalClient, span, logger, ctx, apiErr := setupAuthedIdentityHandler(c, "TokenDelegation", "Delete", dtdh.dbSession, dtdh.scp, dtdh.tracerSpan)
	if span != nil {
		defer span.End()
	}
	if apiErr != nil {
		return apiErr
	}

	protoRequest := &cwssaws.GetTokenDelegationRequest{OrganizationId: org}

	workflowOptions := tclient.StartWorkflowOptions{
		ID:                       "machine-identity-delete-token-delegation-" + org + "-" + site.ID.String(),
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
		WorkflowIDConflictPolicy: temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}

	ctx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := temporalClient.ExecuteWorkflow(ctx, workflowOptions, "DeleteTokenDelegation", protoRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to synchronously start Temporal workflow to delete Token Delegation")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to start workflow to delete Token Delegation", nil)
	}

	wid := we.GetID()
	logger.Info().Str("Workflow ID", wid).Msg("executed synchronous delete Token Delegation workflow")

	err = we.Get(ctx, nil)
	if err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || ctx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, temporalClient, wid, err, "TokenDelegation", "DeleteTokenDelegation")
		}

		code, unwrapped := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to delete Token Delegation")
		return cutil.NewAPIErrorResponse(c, code, "Failed to delete Token Delegation", nil)
	}

	return c.NoContent(http.StatusNoContent)
}

// ~~~~~ Get JWKS Handler ~~~~~ //

// GetJWKSHandler handles GET /.well-known/jwks.json and the SPIFFE variant.
type GetJWKSHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
	kind       cwssaws.JwksKind
}

// NewGetJWKSHandler returns a new GetJWKSHandler.
func NewGetJWKSHandler(dbSession *cdb.Session, scp *sc.ClientPool, kind cwssaws.JwksKind) GetJWKSHandler {
	return GetJWKSHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
		kind:       kind,
	}
}

// Handle godoc
// @Summary Retrieve JWKS
// @Description Public JSON Web Key Set for JWT-SVID signature verification. No authentication required. Returns an empty keyset when the site has no key material.
// @Tags MachineIdentity
// @Produce json
// @Param org path string true "Name of NGC organization"
// @Param siteID path string true "ID of Site"
// @Success 200 {string} string "JWKS JSON document"
// @Router /v2/org/{org}/carbide/site/{siteID}/.well-known/jwks.json [get]
func (gjh GetJWKSHandler) Handle(c echo.Context) error {
	org, site, temporalClient, logger, ctx, apiErr := setupPublicIdentityHandler(c, gjh.dbSession, gjh.scp)
	if apiErr != nil {
		if errors.Is(apiErr, errPublicIdentityAbsent) {
			return writeEmptyJWKS(c)
		}
		return apiErr
	}

	kind := gjh.kind
	protoRequest := &cwssaws.JwksRequest{OrganizationId: org, Kind: &kind}

	workflowOptions := tclient.StartWorkflowOptions{
		ID:                       "machine-identity-get-jwks-" + org + "-" + site.ID.String() + "-" + kind.String(),
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
		WorkflowIDConflictPolicy: temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}

	ctx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := temporalClient.ExecuteWorkflow(ctx, workflowOptions, "GetJWKS", protoRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to synchronously start Temporal workflow to get JWKS")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to start workflow to get JWKS", nil)
	}

	wid := we.GetID()
	logger.Info().Str("Workflow ID", wid).Msg("executed synchronous get JWKS workflow")

	var protoResponse cwssaws.Jwks
	err = we.Get(ctx, &protoResponse)
	if err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || ctx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, temporalClient, wid, err, "MachineIdentity", "GetJWKS")
		}

		code, unwrapped := common.UnwrapWorkflowError(err)
		if code == http.StatusNotFound {
			logger.Info().Err(unwrapped).Str("orgName", org).Msg("public JWKS: site controller reported NOT_FOUND — normalizing to empty keyset")
			return writeEmptyJWKS(c)
		}
		logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to get JWKS")
		return cutil.NewAPIErrorResponse(c, code, "Failed to get JWKS", nil)
	}

	raw := protoResponse.GetJwks()
	if strings.TrimSpace(raw) == "" {
		logger.Info().Str("orgName", org).
			Msg("public JWKS: site controller returned empty body — normalizing to empty keyset")
		return writeEmptyJWKS(c)
	}
	var probe struct {
		Keys json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil || probe.Keys == nil {
		logger.Error().Err(err).Str("orgName", org).
			Msg("public JWKS: site controller returned malformed JWKS")
		return cutil.NewAPIErrorResponse(c, http.StatusBadGateway, "Site controller returned malformed JWKS", nil)
	}

	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	_, werr := c.Response().Write([]byte(raw))
	return werr
}

// ~~~~~ Get OpenID Configuration Handler ~~~~~ //

// GetOpenIDConfigurationHandler handles GET /.well-known/openid-configuration.
type GetOpenIDConfigurationHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewGetOpenIDConfigurationHandler returns a new GetOpenIDConfigurationHandler.
func NewGetOpenIDConfigurationHandler(dbSession *cdb.Session, scp *sc.ClientPool) GetOpenIDConfigurationHandler {
	return GetOpenIDConfigurationHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Retrieve OpenID Configuration
// @Description Public OIDC discovery document pointing at this org's JWKS URIs. No authentication required. Returns 404 when no identity material exists for this org/site.
// @Tags MachineIdentity
// @Produce json
// @Param org path string true "Name of NGC organization"
// @Param siteID path string true "ID of Site"
// @Success 200 {object} model.APIOpenIDConfiguration
// @Router /v2/org/{org}/carbide/site/{siteID}/.well-known/openid-configuration [get]
func (goich GetOpenIDConfigurationHandler) Handle(c echo.Context) error {
	org, site, temporalClient, logger, ctx, apiErr := setupPublicIdentityHandler(c, goich.dbSession, goich.scp)
	if apiErr != nil {
		if errors.Is(apiErr, errPublicIdentityAbsent) {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "OpenID Configuration not available", nil)
		}
		return apiErr
	}

	protoRequest := &cwssaws.OpenIdConfigRequest{OrganizationId: org}

	workflowOptions := tclient.StartWorkflowOptions{
		ID:                       "machine-identity-get-oidc-" + org + "-" + site.ID.String(),
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
		WorkflowIDConflictPolicy: temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}

	ctx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := temporalClient.ExecuteWorkflow(ctx, workflowOptions, "GetOpenIDConfiguration", protoRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to synchronously start Temporal workflow to get OpenID Configuration")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to start workflow to get OpenID Configuration", nil)
	}

	wid := we.GetID()
	logger.Info().Str("Workflow ID", wid).Msg("executed synchronous get OpenID Configuration workflow")

	var protoResponse cwssaws.OpenIdConfiguration
	err = we.Get(ctx, &protoResponse)
	if err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || ctx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, temporalClient, wid, err, "MachineIdentity", "GetOpenIDConfiguration")
		}

		code, unwrapped := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to get OpenID Configuration")
		return cutil.NewAPIErrorResponse(c, code, "Failed to get OpenID Configuration", nil)
	}

	return c.JSON(http.StatusOK, model.NewAPIOpenIDConfiguration(&protoResponse))
}

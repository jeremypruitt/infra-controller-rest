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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.temporal.io/api/enums/v1"
	tclient "go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
	tp "go.temporal.io/sdk/temporal"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller-rest/api/pkg/client/site"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

func strPtr(s string) *string    { return &s }
func uint32Ptr(u uint32) *uint32 { return &u }

func countMockCalls(m *mock.Mock, method string) int {
	n := 0
	for _, c := range m.Calls {
		if c.Method == method {
			n++
		}
	}
	return n
}

// TestIdentityHandlers_TimeoutReturns500AndTerminatesWorkflow covers the timeout path.
func TestIdentityHandlers_TimeoutReturns500AndTerminatesWorkflow(t *testing.T) {
	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.InfrastructureProvider)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Tenant)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Site)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Allocation)(nil)))

	const (
		testTenantOrg   = "test-identity-tenant-org"
		testProviderOrg = "test-identity-provider-org"
	)
	tenantUser := testVPCBuildUser(t, dbSession, "test-identity-tenant-user", testTenantOrg, []string{"FORGE_TENANT_ADMIN"})
	tenant := testVPCBuildTenant(t, dbSession, "test-identity-tenant", testTenantOrg, tenantUser)
	providerUser := testVPCBuildUser(t, dbSession, "test-identity-provider-user", testProviderOrg, []string{"FORGE_PROVIDER_ADMIN"})
	ip := testVPCSiteBuildInfrastructureProvider(t, dbSession, "test-identity-ip", testProviderOrg, providerUser)
	site := testVPCBuildSite(t, dbSession, ip, "test-identity-site", false, false, cdbm.SiteStatusRegistered, providerUser)
	_ = testBuildAllocation(t, dbSession, site, tenant, "test-identity-alloc", tenantUser)

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	tc := &tmocks.Client{}
	scp := sc.NewClientPool(tcfg)
	scp.IDClientMap[site.ID.String()] = tc

	timeoutRun := &tmocks.WorkflowRun{}
	timeoutRun.On("GetID").Return("test-identity-timeout-wf-id")
	timeoutRun.Mock.On("Get", mock.Anything, mock.Anything).
		Return(tp.NewTimeoutError(enums.TIMEOUT_TYPE_UNSPECIFIED, nil, nil))
	tc.Mock.On("ExecuteWorkflow",
		mock.Anything,
		mock.AnythingOfType("internal.StartWorkflowOptions"),
		mock.AnythingOfType("string"),
		mock.Anything,
	).Return(timeoutRun, nil)
	tc.Mock.On("TerminateWorkflow",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(nil)

	e := echo.New()
	siteIDStr := site.ID.String()

	updateConfigBody, err := json.Marshal(model.APIIdentityConfigUpdateRequest{
		DefaultAudience: "spiffe://test/aud",
		Issuer:          cdb.GetStrPtr("https://issuer.test/{org}"),
		TokenTtlSec:     uint32Ptr(3600),
	})
	require.NoError(t, err)
	updateTokenDelegationBody, err := json.Marshal(model.APITokenDelegationUpdateRequest{
		TokenEndpoint:        "https://callback.test/exchange",
		SubjectTokenAudience: "https://aud.test",
	})
	require.NoError(t, err)

	tests := []struct {
		name       string
		method     string
		body       []byte
		entity     string
		workflow   string
		user       *cdbm.User
		newHandler func() echo.HandlerFunc
	}{
		{
			name: "PUT identity/config", method: http.MethodPut, body: updateConfigBody,
			entity: "MachineIdentity", workflow: "SetIdentityConfiguration", user: tenantUser,
			newHandler: func() echo.HandlerFunc { return NewUpdateIdentityConfigHandler(dbSession, scp).Handle },
		},
		{
			name: "GET identity/config", method: http.MethodGet,
			entity: "MachineIdentity", workflow: "GetIdentityConfiguration", user: tenantUser,
			newHandler: func() echo.HandlerFunc { return NewGetIdentityConfigHandler(dbSession, scp).Handle },
		},
		{
			name: "DELETE identity/config", method: http.MethodDelete,
			entity: "MachineIdentity", workflow: "DeleteIdentityConfiguration", user: tenantUser,
			newHandler: func() echo.HandlerFunc { return NewDeleteIdentityConfigHandler(dbSession, scp).Handle },
		},
		{
			name: "PUT identity/token-delegation", method: http.MethodPut, body: updateTokenDelegationBody,
			entity: "TokenDelegation", workflow: "SetTokenDelegation", user: tenantUser,
			newHandler: func() echo.HandlerFunc { return NewUpdateTokenDelegationHandler(dbSession, scp).Handle },
		},
		{
			name: "GET identity/token-delegation", method: http.MethodGet,
			entity: "TokenDelegation", workflow: "GetTokenDelegation", user: tenantUser,
			newHandler: func() echo.HandlerFunc { return NewGetTokenDelegationHandler(dbSession, scp).Handle },
		},
		{
			name: "DELETE identity/token-delegation", method: http.MethodDelete,
			entity: "TokenDelegation", workflow: "DeleteTokenDelegation", user: tenantUser,
			newHandler: func() echo.HandlerFunc { return NewDeleteTokenDelegationHandler(dbSession, scp).Handle },
		},
		{
			name: "GET .well-known/jwks.json (oidc)", method: http.MethodGet,
			entity: "MachineIdentity", workflow: "GetJWKS", user: nil,
			newHandler: func() echo.HandlerFunc {
				return NewGetJWKSHandler(dbSession, scp, cwssaws.JwksKind_Oidc).Handle
			},
		},
		{
			name: "GET .well-known/openid-configuration", method: http.MethodGet,
			entity: "MachineIdentity", workflow: "GetOpenIDConfiguration", user: nil,
			newHandler: func() echo.HandlerFunc { return NewGetOpenIDConfigurationHandler(dbSession, scp).Handle },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeTerminate := countMockCalls(&tc.Mock, "TerminateWorkflow")

			body := strings.NewReader("")
			if tt.body != nil {
				body = strings.NewReader(string(tt.body))
			}
			req := httptest.NewRequest(tt.method, "/", body)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "siteID")
			ec.SetParamValues(testTenantOrg, siteIDStr)
			if tt.user != nil {
				ec.Set("user", tt.user)
			}

			require.NoError(t, tt.newHandler()(ec))
			require.Equal(t, http.StatusInternalServerError, rec.Code, "body=%s", rec.Body.String())
			expected := "Failed to perform " + tt.entity + " " + tt.workflow + " - timeout occurred executing workflow on Site"
			assert.Contains(t, rec.Body.String(), expected)
			assert.Equal(t, beforeTerminate+1, countMockCalls(&tc.Mock, "TerminateWorkflow"),
				"expected exactly one TerminateWorkflow call for %s", tt.workflow)
		})
	}
}

// TestUpdateIdentityConfig_BodyOrgIDContract covers URL-vs-body OrgID handling.
func TestUpdateIdentityConfig_BodyOrgIDContract(t *testing.T) {
	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.InfrastructureProvider)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Tenant)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Site)(nil)))

	const (
		urlTenantOrg    = "test-orgid-contract-tenant"
		otherTenantOrg  = "some-other-tenant"
		testProviderOrg = "test-orgid-contract-provider"
	)
	tenantUser := testVPCBuildUser(t, dbSession, "test-orgid-contract-tu", urlTenantOrg, []string{"FORGE_TENANT_ADMIN"})
	_ = testVPCBuildTenant(t, dbSession, "test-orgid-contract-tn", urlTenantOrg, tenantUser)
	providerUser := testVPCBuildUser(t, dbSession, "test-orgid-contract-pu", testProviderOrg, []string{"FORGE_PROVIDER_ADMIN"})
	ip := testVPCSiteBuildInfrastructureProvider(t, dbSession, "test-orgid-contract-ip", testProviderOrg, providerUser)
	site := testVPCBuildSite(t, dbSession, ip, "test-orgid-contract-site", false, false, cdbm.SiteStatusRegistered, providerUser)

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	tc := &tmocks.Client{}
	scp := sc.NewClientPool(tcfg)
	scp.IDClientMap[site.ID.String()] = tc

	matchRun := &tmocks.WorkflowRun{}
	matchRun.On("GetID").Return("test-orgid-contract-wf-id")
	matchRun.Mock.On("Get", mock.Anything, mock.Anything).Return(nil)
	tc.Mock.On("ExecuteWorkflow",
		mock.Anything,
		mock.AnythingOfType("internal.StartWorkflowOptions"),
		mock.AnythingOfType("string"),
		mock.Anything,
	).Return(matchRun, nil)

	e := echo.New()
	siteIDStr := site.ID.String()

	tests := []struct {
		name        string
		bodyOrgID   string
		wantStatus  int
		wantBodyHas string
	}{
		{name: "matches URL -> 200", bodyOrgID: urlTenantOrg, wantStatus: http.StatusOK},
		{name: "omitted -> 200", bodyOrgID: "", wantStatus: http.StatusOK},
		{name: "mismatches URL -> 400", bodyOrgID: otherTenantOrg, wantStatus: http.StatusBadRequest,
			wantBodyHas: "If provided, orgId in request body must match URL org"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(model.APIIdentityConfigUpdateRequest{
				OrgID:           tt.bodyOrgID,
				DefaultAudience: "spiffe://test/aud",
				Issuer:          cdb.GetStrPtr("https://issuer.test/{org}"),
				TokenTtlSec:     uint32Ptr(3600),
			})
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(string(body)))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "siteID")
			ec.SetParamValues(urlTenantOrg, siteIDStr)
			ec.Set("user", tenantUser)

			require.NoError(t, NewUpdateIdentityConfigHandler(dbSession, scp).Handle(ec))
			require.Equal(t, tt.wantStatus, rec.Code, "body=%s", rec.Body.String())
			if tt.wantBodyHas != "" {
				assert.Contains(t, rec.Body.String(), tt.wantBodyHas)
			}
		})
	}
}

// TestGetJWKS_AbsentCasesReturnEmptyKeysetAndPresentPassesThrough covers JWKS
// absent and present paths.
//
// The public resolver intentionally does NOT require an allocation: a tenant
// whose identity config exists on the site controller but who has no current
// allocation on the site MUST still receive its real JWKS, because the
// already-issued JWT-SVIDs remain valid until natural expiry. The "no
// allocation on site" case below pins that behavior by asserting the real
// keyset comes back.
//
// The remaining empty-keyset paths are: unknown site, unknown org, and the
// site controller's NOT_FOUND for a real tenant — all independent of
// allocation lifecycle and treated as valid normalizations.
func TestGetJWKS_AbsentCasesReturnEmptyKeysetAndPresentPassesThrough(t *testing.T) {
	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.InfrastructureProvider)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Tenant)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Site)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Allocation)(nil)))

	const (
		realTenantOrg    = "test-jwks-tenant"
		noAllocTenantOrg = "test-jwks-tenant-no-alloc"
		unknownOrg       = "no-such-tenant"
		testProviderOrg  = "test-jwks-provider"
	)
	tenantUser := testVPCBuildUser(t, dbSession, "test-jwks-tu", realTenantOrg, []string{"FORGE_TENANT_ADMIN"})
	tenant := testVPCBuildTenant(t, dbSession, "test-jwks-tn", realTenantOrg, tenantUser)
	noAllocTenantUser := testVPCBuildUser(t, dbSession, "test-jwks-tu-noalloc", noAllocTenantOrg, []string{"FORGE_TENANT_ADMIN"})
	_ = testVPCBuildTenant(t, dbSession, "test-jwks-tn-noalloc", noAllocTenantOrg, noAllocTenantUser)
	providerUser := testVPCBuildUser(t, dbSession, "test-jwks-pu", testProviderOrg, []string{"FORGE_PROVIDER_ADMIN"})
	ip := testVPCSiteBuildInfrastructureProvider(t, dbSession, "test-jwks-ip", testProviderOrg, providerUser)
	site := testVPCBuildSite(t, dbSession, ip, "test-jwks-site", false, false, cdbm.SiteStatusRegistered, providerUser)
	_ = testBuildAllocation(t, dbSession, site, tenant, "test-jwks-alloc", tenantUser)

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	tc := &tmocks.Client{}
	scp := sc.NewClientPool(tcfg)
	scp.IDClientMap[site.ID.String()] = tc

	notFoundRun := &tmocks.WorkflowRun{}
	notFoundRun.On("GetID").Return("test-jwks-notfound-wf-id")
	notFoundRun.Mock.On("Get", mock.Anything, mock.Anything).
		Return(grpcstatus.Error(grpccodes.NotFound, "tenant has no identity config"))

	successRun := &tmocks.WorkflowRun{}
	successRun.On("GetID").Return("test-jwks-success-wf-id")
	successRun.Mock.On("Get", mock.Anything, mock.Anything).
		Return(nil).Run(func(args mock.Arguments) {
		out := args.Get(1).(*cwssaws.Jwks)
		out.Jwks = `{"keys":[{"kty":"EC","kid":"real-key-id","alg":"ES256","crv":"P-256","x":"xxxx","y":"yyyy"}]}`
	})

	tc.Mock.On("ExecuteWorkflow",
		mock.Anything,
		mock.MatchedBy(func(opts tclient.StartWorkflowOptions) bool { return strings.HasSuffix(opts.ID, "-Spiffe") }),
		mock.AnythingOfType("string"),
		mock.Anything,
	).Return(notFoundRun, nil)
	tc.Mock.On("ExecuteWorkflow",
		mock.Anything,
		mock.MatchedBy(func(opts tclient.StartWorkflowOptions) bool { return strings.HasSuffix(opts.ID, "-Oidc") }),
		mock.AnythingOfType("string"),
		mock.Anything,
	).Return(successRun, nil)

	const (
		emptyBody    = `{"keys":[]}`
		realJWKSBody = `{"keys":[{"kty":"EC","kid":"real-key-id","alg":"ES256","crv":"P-256","x":"xxxx","y":"yyyy"}]}`
	)

	e := echo.New()
	siteIDStr := site.ID.String()
	bogusSiteID := "00000000-0000-0000-0000-000000000000"

	tests := []struct {
		name     string
		orgName  string
		siteID   string
		kind     cwssaws.JwksKind
		wantBody string
	}{
		{name: "absent: unknown site", orgName: realTenantOrg, siteID: bogusSiteID, kind: cwssaws.JwksKind_Oidc, wantBody: emptyBody},
		{name: "absent: org is not a Tenant", orgName: unknownOrg, siteID: siteIDStr, kind: cwssaws.JwksKind_Oidc, wantBody: emptyBody},
		{name: "absent: site controller NOT_FOUND", orgName: realTenantOrg, siteID: siteIDStr, kind: cwssaws.JwksKind_Spiffe, wantBody: emptyBody},
		{name: "present: real JWKS pass-through", orgName: realTenantOrg, siteID: siteIDStr, kind: cwssaws.JwksKind_Oidc, wantBody: realJWKSBody},
		// Tenant exists, no allocation on the site, but the controller still
		// has identity config / keys. Allocation must NOT gate JWKS lookup,
		// otherwise verification of unexpired tokens would break — we route
		// to the controller and serve the real JWKS.
		{name: "present: tenant has no allocation, controller has keys", orgName: noAllocTenantOrg, siteID: siteIDStr, kind: cwssaws.JwksKind_Oidc, wantBody: realJWKSBody},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "siteID")
			ec.SetParamValues(tt.orgName, tt.siteID)

			require.NoError(t, NewGetJWKSHandler(dbSession, scp, tt.kind).Handle(ec))
			assert.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
			assert.Equal(t, tt.wantBody, rec.Body.String())
			assert.Equal(t, echo.MIMEApplicationJSON, rec.Header().Get(echo.HeaderContentType))
		})
	}
}

// TestGetJWKS_BodyValidation pins the JWKS pass-through guard: the
// controller's response body is sanity-checked before it is shipped as
// `application/json`. Empty bodies are normalized to `{"keys":[]}`,
// malformed bodies surface as 502 Bad Gateway.
func TestGetJWKS_BodyValidation(t *testing.T) {
	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.InfrastructureProvider)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Tenant)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Site)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Allocation)(nil)))

	const (
		tenantOrg = "test-jwks-bodyval-tenant"
		provOrg   = "test-jwks-bodyval-provider"
	)
	tenantUser := testVPCBuildUser(t, dbSession, "test-jwks-bv-tu", tenantOrg, []string{"FORGE_TENANT_ADMIN"})
	tenant := testVPCBuildTenant(t, dbSession, "test-jwks-bv-tn", tenantOrg, tenantUser)
	provUser := testVPCBuildUser(t, dbSession, "test-jwks-bv-pu", provOrg, []string{"FORGE_PROVIDER_ADMIN"})
	ip := testVPCSiteBuildInfrastructureProvider(t, dbSession, "test-jwks-bv-ip", provOrg, provUser)
	site := testVPCBuildSite(t, dbSession, ip, "test-jwks-bv-site", false, false, cdbm.SiteStatusRegistered, provUser)
	_ = testBuildAllocation(t, dbSession, site, tenant, "test-jwks-bv-alloc", tenantUser)

	cfg := common.GetTestConfig()

	type bodyCase struct {
		name      string
		controlle string
		wantCode  int
		wantBody  string
	}
	cases := []bodyCase{
		{name: "empty body normalized to empty keyset", controlle: "", wantCode: http.StatusOK, wantBody: `{"keys":[]}`},
		{name: "whitespace body normalized to empty keyset", controlle: "  \n\t ", wantCode: http.StatusOK, wantBody: `{"keys":[]}`},
		{name: "non-JSON body -> 502 Bad Gateway", controlle: "not-json", wantCode: http.StatusBadGateway},
		{name: "JSON without keys field -> 502 Bad Gateway", controlle: `{"foo":"bar"}`, wantCode: http.StatusBadGateway},
		{name: "JSON array (not object) -> 502 Bad Gateway", controlle: `[]`, wantCode: http.StatusBadGateway},
		{name: "valid keyset passes through unchanged", controlle: `{"keys":[{"kty":"EC","kid":"k1"}]}`,
			wantCode: http.StatusOK, wantBody: `{"keys":[{"kty":"EC","kid":"k1"}]}`},
	}

	e := echo.New()
	siteIDStr := site.ID.String()

	tcfg, _ := cfg.GetTemporalConfig()

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := &tmocks.Client{}
			scp := sc.NewClientPool(tcfg)
			scp.IDClientMap[site.ID.String()] = tc

			run := &tmocks.WorkflowRun{}
			run.On("GetID").Return("test-jwks-bv-wf-id")
			body := tt.controlle
			run.Mock.On("Get", mock.Anything, mock.Anything).
				Return(nil).Run(func(args mock.Arguments) {
				out := args.Get(1).(*cwssaws.Jwks)
				out.Jwks = body
			})
			tc.Mock.On("ExecuteWorkflow",
				mock.Anything, mock.Anything, mock.AnythingOfType("string"), mock.Anything,
			).Return(run, nil)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			ec := e.NewContext(req, rec)
			ec.SetParamNames("orgName", "siteID")
			ec.SetParamValues(tenantOrg, siteIDStr)

			require.NoError(t, NewGetJWKSHandler(dbSession, scp, cwssaws.JwksKind_Oidc).Handle(ec))
			assert.Equal(t, tt.wantCode, rec.Code, "body=%s", rec.Body.String())
			if tt.wantBody != "" {
				assert.Equal(t, tt.wantBody, rec.Body.String())
				assert.Equal(t, echo.MIMEApplicationJSON, rec.Header().Get(echo.HeaderContentType))
			}
		})
	}
}

// TestIdentityPUT_WorkflowIDIncludesPayloadHash covers payload-hashed workflow IDs.
func TestIdentityPUT_WorkflowIDIncludesPayloadHash(t *testing.T) {
	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.InfrastructureProvider)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Tenant)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Site)(nil)))

	const (
		tenantOrg = "test-payload-hash-tenant"
		provOrg   = "test-payload-hash-provider"
	)
	tenantUser := testVPCBuildUser(t, dbSession, "test-ph-tu", tenantOrg, []string{"FORGE_TENANT_ADMIN"})
	_ = testVPCBuildTenant(t, dbSession, "test-ph-tn", tenantOrg, tenantUser)
	provUser := testVPCBuildUser(t, dbSession, "test-ph-pu", provOrg, []string{"FORGE_PROVIDER_ADMIN"})
	ip := testVPCSiteBuildInfrastructureProvider(t, dbSession, "test-ph-ip", provOrg, provUser)
	site := testVPCBuildSite(t, dbSession, ip, "test-ph-site", false, false, cdbm.SiteStatusRegistered, provUser)

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	tc := &tmocks.Client{}
	scp := sc.NewClientPool(tcfg)
	scp.IDClientMap[site.ID.String()] = tc

	var capturedIDs []string
	run := &tmocks.WorkflowRun{}
	run.On("GetID").Return("test-payload-hash-wf-id")
	run.Mock.On("Get", mock.Anything, mock.Anything).Return(nil)
	tc.Mock.On("ExecuteWorkflow",
		mock.Anything,
		mock.MatchedBy(func(opts tclient.StartWorkflowOptions) bool {
			capturedIDs = append(capturedIDs, opts.ID)
			return true
		}),
		mock.AnythingOfType("string"),
		mock.Anything,
	).Return(run, nil)

	e := echo.New()
	siteIDStr := site.ID.String()

	doPUT := func(t *testing.T, h echo.HandlerFunc, body []byte) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(string(body)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ec := e.NewContext(req, rec)
		ec.SetParamNames("orgName", "siteID")
		ec.SetParamValues(tenantOrg, siteIDStr)
		ec.Set("user", tenantUser)
		require.NoError(t, h(ec))
		require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	}

	assertHashInvariant := func(t *testing.T, wantPrefix string, ids []string) {
		t.Helper()
		require.Len(t, ids, 3)
		assert.NotEqual(t, ids[0], ids[1], "different payloads must produce different IDs")
		assert.Equal(t, ids[0], ids[2], "identical payloads must produce identical IDs")
		assert.True(t, strings.HasPrefix(ids[0], wantPrefix), "ID must keep op-org-site prefix: %q", ids[0])
	}

	t.Run("PUT identity/config", func(t *testing.T) {
		mk := func(audience string) []byte {
			body, err := json.Marshal(model.APIIdentityConfigUpdateRequest{
				DefaultAudience: audience,
				Issuer:          strPtr("https://issuer.test/" + tenantOrg),
				TokenTtlSec:     uint32Ptr(3600),
			})
			require.NoError(t, err)
			return body
		}
		base := len(capturedIDs)
		h := NewUpdateIdentityConfigHandler(dbSession, scp).Handle
		doPUT(t, h, mk("openbao-A"))
		doPUT(t, h, mk("openbao-B"))
		doPUT(t, h, mk("openbao-A"))
		assertHashInvariant(t, "machine-identity-update-config-"+tenantOrg+"-"+siteIDStr+"-", capturedIDs[base:base+3])
	})

	t.Run("PUT identity/token-delegation", func(t *testing.T) {
		mk := func(endpoint string) []byte {
			body, err := json.Marshal(model.APITokenDelegationUpdateRequest{
				TokenEndpoint:        endpoint,
				SubjectTokenAudience: "exchange-aud",
			})
			require.NoError(t, err)
			return body
		}
		base := len(capturedIDs)
		h := NewUpdateTokenDelegationHandler(dbSession, scp).Handle
		doPUT(t, h, mk("https://auth-a.example.com/oauth2/token"))
		doPUT(t, h, mk("https://auth-b.example.com/oauth2/token"))
		doPUT(t, h, mk("https://auth-a.example.com/oauth2/token"))
		assertHashInvariant(t, "machine-identity-update-token-delegation-"+tenantOrg+"-"+siteIDStr+"-", capturedIDs[base:base+3])
	})
}

// TestPutStatusFromTimestamps unit-covers the helper that picks 201 vs 200 for
// PUT identity-config / token-delegation. A controller stamps `created_at` and
// `updated_at` from the same transaction on first create, so equality means
// "newly created". Any inequality (or missing field) collapses to 200.
func TestPutStatusFromTimestamps(t *testing.T) {
	now := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	later := now.Add(5 * time.Second)
	ts := func(v time.Time) *timestamppb.Timestamp { return timestamppb.New(v) }

	tests := []struct {
		name      string
		createdAt *timestamppb.Timestamp
		updatedAt *timestamppb.Timestamp
		want      int
	}{
		{name: "first create -> 201", createdAt: ts(now), updatedAt: ts(now), want: http.StatusCreated},
		{name: "subsequent update -> 200", createdAt: ts(now), updatedAt: ts(later), want: http.StatusOK},
		{name: "missing createdAt -> 200", updatedAt: ts(now), want: http.StatusOK},
		{name: "missing updatedAt -> 200", createdAt: ts(now), want: http.StatusOK},
		{name: "both missing -> 200", want: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, putStatusFromTimestamps(tt.createdAt, tt.updatedAt))
		})
	}
}

// TestUpdateIdentityPUT_StatusReflectsCreateVsUpdate covers the integration
// path: the handler picks 201 on first create (CreatedAt == UpdatedAt) and
// 200 on subsequent updates (UpdatedAt advanced).
func TestUpdateIdentityPUT_StatusReflectsCreateVsUpdate(t *testing.T) {
	dbSession := testSiteInitDB(t)
	defer dbSession.Close()

	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.User)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.InfrastructureProvider)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Tenant)(nil)))
	require.NoError(t, dbSession.DB.ResetModel(context.Background(), (*cdbm.Site)(nil)))

	const (
		tenantOrg = "test-status-tenant"
		provOrg   = "test-status-provider"
	)
	tenantUser := testVPCBuildUser(t, dbSession, "test-status-tu", tenantOrg, []string{"FORGE_TENANT_ADMIN"})
	_ = testVPCBuildTenant(t, dbSession, "test-status-tn", tenantOrg, tenantUser)
	provUser := testVPCBuildUser(t, dbSession, "test-status-pu", provOrg, []string{"FORGE_PROVIDER_ADMIN"})
	ip := testVPCSiteBuildInfrastructureProvider(t, dbSession, "test-status-ip", provOrg, provUser)
	site := testVPCBuildSite(t, dbSession, ip, "test-status-site", false, false, cdbm.SiteStatusRegistered, provUser)

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	tc := &tmocks.Client{}
	scp := sc.NewClientPool(tcfg)
	scp.IDClientMap[site.ID.String()] = tc

	now := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	later := now.Add(time.Minute)

	// One mock run per scenario: the .Run callback shapes the protobuf
	// response timestamps the handler will see.
	createdConfigRun := &tmocks.WorkflowRun{}
	createdConfigRun.On("GetID").Return("test-status-cfg-create-wf-id")
	createdConfigRun.Mock.On("Get", mock.Anything, mock.Anything).
		Return(nil).Run(func(args mock.Arguments) {
		out := args.Get(1).(*cwssaws.IdentityConfigResponse)
		out.OrganizationId = tenantOrg
		out.CreatedAt = timestamppb.New(now)
		out.UpdatedAt = timestamppb.New(now)
	})
	updatedConfigRun := &tmocks.WorkflowRun{}
	updatedConfigRun.On("GetID").Return("test-status-cfg-update-wf-id")
	updatedConfigRun.Mock.On("Get", mock.Anything, mock.Anything).
		Return(nil).Run(func(args mock.Arguments) {
		out := args.Get(1).(*cwssaws.IdentityConfigResponse)
		out.OrganizationId = tenantOrg
		out.CreatedAt = timestamppb.New(now)
		out.UpdatedAt = timestamppb.New(later)
	})

	createdDelegRun := &tmocks.WorkflowRun{}
	createdDelegRun.On("GetID").Return("test-status-deleg-create-wf-id")
	createdDelegRun.Mock.On("Get", mock.Anything, mock.Anything).
		Return(nil).Run(func(args mock.Arguments) {
		out := args.Get(1).(*cwssaws.TokenDelegationResponse)
		out.OrganizationId = tenantOrg
		out.CreatedAt = timestamppb.New(now)
		out.UpdatedAt = timestamppb.New(now)
	})
	updatedDelegRun := &tmocks.WorkflowRun{}
	updatedDelegRun.On("GetID").Return("test-status-deleg-update-wf-id")
	updatedDelegRun.Mock.On("Get", mock.Anything, mock.Anything).
		Return(nil).Run(func(args mock.Arguments) {
		out := args.Get(1).(*cwssaws.TokenDelegationResponse)
		out.OrganizationId = tenantOrg
		out.CreatedAt = timestamppb.New(now)
		out.UpdatedAt = timestamppb.New(later)
	})

	// Differentiate the four runs by the workflow name argument so each
	// scenario routes to its scripted response. A unique payload-hash suffix
	// in the workflow ID also keeps the four responses isolated.
	tc.Mock.On("ExecuteWorkflow",
		mock.Anything, mock.Anything,
		"SetIdentityConfiguration", mock.Anything,
	).Return(createdConfigRun, nil).Once()
	tc.Mock.On("ExecuteWorkflow",
		mock.Anything, mock.Anything,
		"SetIdentityConfiguration", mock.Anything,
	).Return(updatedConfigRun, nil).Once()
	tc.Mock.On("ExecuteWorkflow",
		mock.Anything, mock.Anything,
		"SetTokenDelegation", mock.Anything,
	).Return(createdDelegRun, nil).Once()
	tc.Mock.On("ExecuteWorkflow",
		mock.Anything, mock.Anything,
		"SetTokenDelegation", mock.Anything,
	).Return(updatedDelegRun, nil).Once()

	e := echo.New()
	siteIDStr := site.ID.String()

	doConfigPUT := func(t *testing.T, audience string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(model.APIIdentityConfigUpdateRequest{
			DefaultAudience: audience,
			Issuer:          strPtr("https://issuer.test/" + tenantOrg),
			TokenTtlSec:     uint32Ptr(3600),
		})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(string(body)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ec := e.NewContext(req, rec)
		ec.SetParamNames("orgName", "siteID")
		ec.SetParamValues(tenantOrg, siteIDStr)
		ec.Set("user", tenantUser)
		require.NoError(t, NewUpdateIdentityConfigHandler(dbSession, scp).Handle(ec))
		return rec
	}
	doDelegPUT := func(t *testing.T, endpoint string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(model.APITokenDelegationUpdateRequest{
			TokenEndpoint:        endpoint,
			SubjectTokenAudience: "exchange-aud",
		})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(string(body)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ec := e.NewContext(req, rec)
		ec.SetParamNames("orgName", "siteID")
		ec.SetParamValues(tenantOrg, siteIDStr)
		ec.Set("user", tenantUser)
		require.NoError(t, NewUpdateTokenDelegationHandler(dbSession, scp).Handle(ec))
		return rec
	}

	t.Run("identity/config first create returns 201", func(t *testing.T) {
		rec := doConfigPUT(t, "openbao-create")
		assert.Equal(t, http.StatusCreated, rec.Code, "body=%s", rec.Body.String())
	})
	t.Run("identity/config subsequent update returns 200", func(t *testing.T) {
		rec := doConfigPUT(t, "openbao-update")
		assert.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	})
	t.Run("token-delegation first create returns 201", func(t *testing.T) {
		rec := doDelegPUT(t, "https://auth-create.example.com/oauth2/token")
		assert.Equal(t, http.StatusCreated, rec.Code, "body=%s", rec.Body.String())
	})
	t.Run("token-delegation subsequent update returns 200", func(t *testing.T) {
		rec := doDelegPUT(t, "https://auth-update.example.com/oauth2/token")
		assert.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	})
}

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

package api

import (
	"testing"

	"github.com/NVIDIA/infra-controller-rest/api/internal/config"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	sc "github.com/NVIDIA/infra-controller-rest/api/pkg/client/site"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/stretchr/testify/assert"

	temporalClient "go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
)

func TestNewAPIRoutes(t *testing.T) {
	type args struct {
		dbSession *cdb.Session
		tc        temporalClient.Client
		tnc       temporalClient.NamespaceClient
		scp       *sc.ClientPool
		cfg       *config.Config
	}

	tc := &tmocks.Client{}
	tnc := &tmocks.NamespaceClient{}

	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	routeCount := map[string]int{
		"metadata":                  1,
		"service-account":           1,
		"infrastructure-provider":   4,
		"tenant":                    4,
		"tenant-account":            5,
		"site":                      6,
		"vpc":                       6,
		"vpcpeering":                4,
		"vpcprefix":                 5,
		"ip-block":                  6,
		"instance":                  8,
		"interface":                 1,
		"infiniband-interface":      2,
		"infiniband-partition":      5,
		"nvlink-interface":          2,
		"nvlink-logical-partition":  4,
		"expected-machine":          5,
		"expected-power-shelf":      5,
		"expected-rack":             7,
		"expected-switch":           5,
		"instance-type":             5,
		"machine":                   5,
		"allocation":                6,
		"subnet":                    5,
		"machine-instance-type":     3,
		"user":                      1,
		"operating-system":          5,
		"sshkey":                    5,
		"sshkeygroup":               5,
		"machine-capability":        1,
		"audit":                     2,
		"network-security-group":    5,
		"machine-validation":        11,
		"dpu-extension-service":     7,
		"sku":                       2,
		"rack":                      12,
		"tray":                      8,
		"stats":                     4,
		"identity-config":           3,
		"identity-token-delegation": 3,
	}

	totalRouteCount := 0
	for _, v := range routeCount {
		totalRouteCount += v
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "test initializing API routes",
			args: args{
				dbSession: &cdb.Session{},
				tc:        tc,
				tnc:       tnc,
				scp:       scp,
				cfg:       cfg,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAPIRoutes(tt.args.dbSession, tt.args.tc, tt.args.tnc, tt.args.scp, tt.args.cfg)

			assert.Equal(t, totalRouteCount, len(got))

			for _, route := range got {
				assert.Contains(t, route.Path, "/org/:orgName/"+cfg.GetAPIName())
			}
		})
	}
}

// TestNewWellKnownRoutes guards the unauthenticated .well-known/* surface
// returned by NewWellKnownRoutes. These routes are mounted on the root echo
// (before the versioned auth middleware in server.go) so that JWT verifiers
// without credentials can fetch JWKS / OIDC discovery; any drift in the count
// or path shape of this set is security-relevant and must fail loudly.
func TestNewWellKnownRoutes(t *testing.T) {
	cfg := common.GetTestConfig()
	tcfg, _ := cfg.GetTemporalConfig()
	scp := sc.NewClientPool(tcfg)

	got := NewWellKnownRoutes(&cdb.Session{}, scp, cfg)

	wantPaths := map[string]string{
		"/org/:orgName/" + cfg.GetAPIName() + "/site/:siteID/.well-known/jwks.json":            "GET",
		"/org/:orgName/" + cfg.GetAPIName() + "/site/:siteID/.well-known/openid-configuration": "GET",
		"/org/:orgName/" + cfg.GetAPIName() + "/site/:siteID/.well-known/spiffe/jwks.json":     "GET",
	}

	assert.Equal(t, len(wantPaths), len(got))

	gotByPath := make(map[string]string, len(got))
	for _, r := range got {
		gotByPath[r.Path] = r.Method
	}
	for path, method := range wantPaths {
		assert.Equal(t, method, gotByPath[path], "well-known route %s missing or wrong method", path)
	}
}

// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ic

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/coreos/go-oidc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/module"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/test"

	pb "google3/third_party/hcls_federated_access/ic/api/v1/go_proto"
)

const (
	domain     = "example.com"
	oidcIssuer = "https://" + domain + "/oidc"
)

func init() {
	err := os.Setenv("SERVICE_DOMAIN", domain)
	if err != nil {
		log.Fatal("Setenv SERVICE_DOMAIN:", err)
	}
}

type mockRoundTripper struct {
	handler http.Handler
}

func (m *mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	m.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

func TestOidcEndpoints(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "test/config")
	s := NewService(domain, domain, store, module.NewBasicModule())
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	identity := &ga4gh.Identity{
		Subject: "sub",
	}
	tok, err := s.createToken(identity, "openid", oidcIssuer, "azp", storage.DefaultRealm, time.Now(), time.Hour*1, cfg, nil)
	if err != nil {
		t.Fatalf("creating token: %v", err)
	}

	// Inject the mock http client to oidc client.
	client := &http.Client{
		Transport: &mockRoundTripper{
			handler: s.Handler,
		},
	}
	ctx := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(ctx, oidcIssuer)
	if err != nil {
		t.Fatal(err)
	}
	verifier := provider.Verifier(&oidc.Config{
		// TODO we should set correct "aud".
		ClientID: oidcIssuer,
	})

	_, err = verifier.Verify(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUserinfoClaims(t *testing.T) {
	damStore := storage.NewMemoryStorage("dam-min", "test/config")
	store := storage.NewMemoryStorage("ic-min", "test/config")
	s := NewService(domain, domain, store, module.NewTestModule(t, damStore, storage.DefaultRealm))
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	longStr := strings.Repeat("a", 1000)

	identity := &ga4gh.Identity{
		Subject: "sub",
		GA4GH: map[string][]ga4gh.Claim{
			ga4gh.ClaimResearcherStatus: []ga4gh.Claim{ga4gh.Claim{
				Value: longStr,
			}},
			ga4gh.ClaimAcceptedTermsAndPolicies: []ga4gh.Claim{ga4gh.Claim{
				Value: longStr,
			}},
		},
	}

	tok, err := s.createToken(identity, "openid ga4gh", oidcIssuer, "azp", storage.DefaultRealm, time.Now(), time.Hour*1, cfg, nil)
	if err != nil {
		t.Fatalf("creating token: %v", err)
	}

	id, err := common.ConvertTokenToIdentityUnsafe(tok)
	if len(id.GA4GH) != 0 {
		t.Errorf("wants token with no 'ga4gh' claims, got %d claims", len(id.GA4GH))
	}

	expectUserinfoClaims := []string{
		ga4ghClaimNamePrefix + ga4gh.ClaimAcceptedTermsAndPolicies,
		ga4ghClaimNamePrefix + ga4gh.ClaimResearcherStatus,
	}
	sort.Strings(expectUserinfoClaims)
	sort.Strings(id.UserinfoClaims)

	if !cmp.Equal(id.UserinfoClaims, expectUserinfoClaims) {
		t.Errorf("wants userinfo claim %v, got %v", expectUserinfoClaims, id.UserinfoClaims)
	}
}

func TestHandlers(t *testing.T) {
	damStore := storage.NewMemoryStorage("dam-min", "test/config")
	store := storage.NewMemoryStorage("ic-min", "test/config")
	s := NewService(domain, domain, store, module.NewTestModule(t, damStore, storage.DefaultRealm))
	cfg, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	identity := &ga4gh.Identity{
		Issuer:  s.getIssuerString(),
		Subject: "someone-account",
	}
	refreshToken1 := createTestToken(t, s, identity, "openid refresh", cfg)
	refreshToken2 := createTestToken(t, s, identity, "openid refresh", cfg)
	tests := []test.HandlerTest{
		{
			Name:   "Get a self-owned token",
			Method: "GET",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `{"tokenMetadata":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh identities profiles openid","identityProvider":"elixir"}}`,
			Status: http.StatusOK,
		},
		{
			Name:    "Get someone else's token as an admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/token/someone-account/1a2-3b4",
			Persona: "admin",
			Output:  `{"tokenMetadata":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh openid","identityProvider":"google"}}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get someone else's token as an non-admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/token/dr_joe_elixir/1a2-3b4",
			Persona: "non-admin",
			Output:  `^.*token not found.*`,
			Status:  http.StatusNotFound,
		},
		{
			Name:   "Post a self-owned token",
			Method: "POST",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*exists`,
			Status: http.StatusConflict,
		},
		{
			Name:   "Put a self-owned token",
			Method: "PUT",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "Patch a self-owned token",
			Method: "PATCH",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "Delete a self-owned token",
			Method: "DELETE",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: "",
			Status: http.StatusOK,
		},
		{
			Name:   "Get a deleted token",
			Method: "GET",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*token not found.*`,
			Status: http.StatusNotFound,
		},
		{
			Name:   "Request an unsupported method at the /revoke endpoint",
			Method: "GET",
			Path:   "/identity/v1alpha/test/revoke",
			Input:  `token=6ImtpZCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpY19lOWIxMDA2MDd`,
			IsForm: true,
			Output: `^.*method not supported.*`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "Delete a malformed token",
			Method: "POST",
			Path:   "/identity/v1alpha/test/revoke",
			Input:  `token=6ImtpZCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpY19lOWIxMDA2MDd`,
			IsForm: true,
			Output: `^.*inspecting token.*`,
			Status: http.StatusUnauthorized,
		},
		{
			Name:    "Delete someone else's token as an admin",
			Method:  "POST",
			Path:    "/identity/v1alpha/test/revoke",
			Persona: "admin",
			Input:   "token=" + refreshToken1,
			IsForm:  true,
			Output:  "",
			Status:  http.StatusOK,
		},
		{
			Name:    "Delete someone else's token as a non-admin",
			Method:  "POST",
			Path:    "/identity/v1alpha/test/revoke",
			Input:   "token=" + refreshToken2,
			IsForm:  true,
			Persona: "non-admin",
			Output:  "",
			Status:  http.StatusOK,
		},
	}
	test.HandlerTests(t, s.Handler, tests)
}

func createTestToken(t *testing.T, s *Service, id *ga4gh.Identity, scope string, cfg *pb.IcConfig) string {
	token, err := s.createToken(id, scope, "", "", "test", time.Now(), time.Hour, cfg, nil)
	if err != nil {
		t.Fatalf("creating test token: %v", err)
	}
	return token
}

func TestAdminHandlers(t *testing.T) {
	damStore := storage.NewMemoryStorage("dam-min", "test/config")
	store := storage.NewMemoryStorage("ic-min", "test/config")
	s := NewService(domain, domain, store, module.NewTestModule(t, damStore, storage.DefaultRealm))
	tests := []test.HandlerTest{
		{
			Name:    "List all tokens of all users as a non-admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "non-admin",
			Output: `^.*user is not an administrator	*`,
			Status: http.StatusForbidden,
		},
		{
			Name:    "List all tokens of all users as an admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "admin",
			Output:  `{"tokensMetadata":{"dr_joe_elixir/123-456":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh identities profiles openid","identityProvider":"elixir"},"someone-account/1a2-3b4":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh openid","identityProvider":"google"}}}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Delete all tokens of all users as a non-admin",
			Method:  "DELETE",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "non-admin",
			Output: `^.*user is not an administrator	*`,
			Status: http.StatusForbidden,
		},
		{
			Name:    "Delete all tokens of all users as an admin",
			Method:  "DELETE",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get deleted tokens of all users as an admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "admin",
			Output:  `{"tokensMetadata":{}}`,
			Status:  http.StatusOK,
		},
	}
	test.HandlerTests(t, s.Handler, tests)
}

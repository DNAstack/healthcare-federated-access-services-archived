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

package dam

import (
	"net/http"
	"net/url"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"golang.org/x/oauth2" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	stateIDInHydra = "state"
)

// HydraLogin handles login request from hydra.
func (s *Service) HydraLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// Use login_challenge fetch information from hydra.
	challenge, status := hydra.ExtractLoginChallenge(r)
	if status != nil {
		httputil.WriteStatus(w, status)
		return
	}

	login, err := hydra.GetLoginRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	if hydra.LoginSkip(w, r, s.httpClient, login, s.hydraAdminURL, challenge) {
		return
	}

	u, err := url.Parse(login.RequestURL)
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	in := authHandlerIn{
		challenge: challenge,
	}

	// Request tokens for call DAM endpoints, if scope includes "identities".
	if common.ListContains(login.RequestedScope, "identities") {
		in.tokenType = pb.ResourceTokenRequestState_ENDPOINT
		in.realm = u.Query().Get("realm")
		if len(in.realm) == 0 {
			in.realm = storage.DefaultRealm
		}
	} else {
		in.tokenType = pb.ResourceTokenRequestState_DATASET
		in.ttl, err = extractTTL(u.Query().Get("max_age"), u.Query().Get("ttl"))
		if err != nil {
			httputil.HandleError(http.StatusBadRequest, err, w)
			return
		}

		list := u.Query()["resource"]
		in.resources, err = s.resourceViewRoleFromRequest(list)
		if err != nil {
			httputil.HandleError(http.StatusBadRequest, err, w)
			return
		}

		in.responseKeyFile = u.Query().Get("response_type") == "key-file-type"
	}

	out, st, err := s.auth(r.Context(), in)
	if err != nil {
		httputil.HandleError(st, err, w)
		return
	}

	var opts []oauth2.AuthCodeOption
	loginHint := u.Query().Get("login_hint")
	if len(loginHint) != 0 {
		opt := oauth2.SetAuthURLParam("login_hint", loginHint)
		opts = append(opts, opt)
	}

	auth := out.oauth.AuthCodeURL(out.stateID, opts...)

	sendRedirect(auth, r, w)
}

// HydraConsent handles consent request from hydra.
func (s *Service) HydraConsent(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// Use consent_challenge fetch information from hydra.
	challenge, status := hydra.ExtractConsentChallenge(r)
	if status != nil {
		httputil.WriteStatus(w, status)
		return
	}

	consent, err := hydra.GetConsentRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	identities, status := hydra.ExtractIdentitiesInConsent(consent)
	if status != nil {
		httputil.WriteStatus(w, status)
		return
	}

	var stateID string
	if len(identities) == 0 {
		stateID, status = hydra.ExtractStateIDInConsent(consent)
		if status != nil {
			httputil.WriteStatus(w, status)
			return
		}
	}

	req := &hydraapi.HandledConsentRequest{
		GrantedAudience: append(consent.RequestedAudience, consent.Client.ClientID),
		GrantedScope:    consent.RequestedScope,
		Session: &hydraapi.ConsentRequestSessionData{
			AccessToken: map[string]interface{}{},
		},
	}

	if len(stateID) > 0 {
		req.Session.AccessToken["cart"] = stateID
	} else if len(identities) > 0 {
		req.Session.AccessToken["identities"] = identities
	}

	resp, err := hydra.AcceptConsent(s.httpClient, s.hydraAdminURL, challenge, req)
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	httputil.SendRedirect(resp.RedirectTo, r, w)
}

func (s *Service) extractCartFromAccessToken(token string) (string, error) {
	claims, err := hydra.Introspect(s.httpClient, s.hydraAdminURL, token)
	if err != nil {
		return "", err
	}

	v, ok := claims.Extra["cart"]
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "token does not have 'cart' claim")
	}

	cart, ok := v.(string)
	if !ok {
		return "", status.Errorf(codes.Internal, "token 'cart' claim have unwanted type")
	}

	return cart, nil
}

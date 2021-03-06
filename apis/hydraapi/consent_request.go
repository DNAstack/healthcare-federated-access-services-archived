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

// Code generated by go-swagger; DO NOT EDIT.

package hydraapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

// ConsentRequest Contains information on an ongoing consent request.
// swagger:model ConsentRequest
type ConsentRequest struct {

	// ACR represents the Authentication AuthorizationContext Class Reference value for this authentication session. You can use it
	// to express that, for example, a user authenticated using two factor authentication.
	ACR string `json:"acr,omitempty"`

	// Challenge is the identifier ("authorization challenge") of the consent authorization request. It is used to
	// identify the session.
	Challenge string `json:"challenge,omitempty"`

	// Context contains arbitrary information set by the login endpoint or is empty if not set.
	Context map[string]interface{} `json:"context,omitempty"`

	// LoginChallenge is the login challenge this consent challenge belongs to. It can be used to associate
	// a login and consent request in the login & consent app.
	LoginChallenge string `json:"login_challenge,omitempty"`

	// LoginSessionID is the login session ID. If the user-agent reuses a login session (via cookie / remember flag)
	// this ID will remain the same. If the user-agent did not have an existing authentication session (e.g. remember is false)
	// this will be a new random value. This value is used as the "sid" parameter in the ID Token and in OIDC Front-/Back-
	// channel logout. It's value can generally be used to associate consecutive login requests by a certain user.
	LoginSessionID string `json:"login_session_id,omitempty"`

	// RequestURL is the original OAuth 2.0 Authorization URL requested by the OAuth 2.0 client. It is the URL which
	// initiates the OAuth 2.0 Authorization Code or OAuth 2.0 Implicit flow. This URL is typically not needed, but
	// might come in handy if you want to deal with additional request parameters.
	RequestURL string `json:"request_url,omitempty"`

	// RequestedScope contains the access token audience as requested by the OAuth 2.0 Client.
	RequestedAudience []string `json:"requested_access_token_audience"`

	// RequestedScope contains the OAuth 2.0 Scope requested by the OAuth 2.0 Client.
	RequestedScope []string `json:"requested_scope"`

	// Skip, if true, implies that the client has requested the same scopes from the same user previously.
	// If true, you must not ask the user to grant the requested scopes. You must however either allow or deny the
	// consent request using the usual API call.
	Skip bool `json:"skip,omitempty"`

	// Subject is the user ID of the end-user that authenticated. Now, that end user needs to grant or deny the scope
	// requested by the OAuth 2.0 client.
	Subject string `json:"subject,omitempty"`

	// client
	Client *Client `json:"client,omitempty"`

	// oidc context
	OidcContext *OpenIDConnectContext `json:"oidc_context,omitempty"`
}

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

const (
	assetPath      = "/identity/static"
	staticFilePath = "/identity/static/"

	// ---------------------------------------------------------------------------
	// The following are the main IC endpoints.
	// ---------------------------------------------------------------------------
	// Redirected here from login page and selecting an IdP.
	loginPath = "/identity/v1alpha/{realm}/login/{name}"
	// Redirected here from an IdP.
	finishLoginPath = "/identity/v1alpha/{realm}/loggedin/{name}"
	// Redirected here from claim release consent page.
	acceptInformationReleasePath = "/identity/v1alpha/{realm}/inforelease"
	// Redirected to here from Hydra login.
	hydraLoginPath = "/identity/login"
	// Redirected to here from Hydra consent.
	hydraConsentPath = "/identity/consent"
	// Redirected to here from Identity Broker.
	acceptLoginPath = "/identity/loggedin"

	// ---------------------------------------------------------------------------
	// The following are administration endpoints for managing DAM.
	// ---------------------------------------------------------------------------

	// infoPath: metadata about the service, like versions of various services.
	// Required permission: admin
	infoPath = "/identity"

	// The following are for managing realms.
	realmPath = "/identity/v1alpha/{realm}"

	// The following are used to manage configuration of DAM.
	// Required permission: admin
	// TODO: remove the sub-paths and use filter and update mask parameters instead.
	configPath                  = "/identity/v1alpha/{realm}/config"
	configIdentityProvidersPath = "/identity/v1alpha/{realm}/config/identityProviders/{name}"
	configClientsPath           = "/identity/v1alpha/{realm}/config/clients/{name}"
	configOptionsPath           = "/identity/v1alpha/{realm}/config/options"

	// ConfigReset: resets the config to its initial state read from configuration file.
	// Required permission: admin
	configResetPath = "/identity/v1alpha/{realm}/config/reset"

	// ConfigHistory: history of configuration changes.
	// Required permission: admin
	configHistoryPath         = "/identity/v1alpha/{realm}/config/history"
	configHistoryRevisionPath = "/identity/v1alpha/{realm}/config/history/{name}"

	// Part of SCIM V2 for managing users. See "proto/scim/v2/users.proto"
	scimUsersPath = "/identity/scim/v2/{realm}/Users"
	scimUserPath  = "/identity/scim/v2/{realm}/Users/{name}"
	scimMePath    = "/identity/scim/v2/{realm}/Me"

	// End-point for managing tokens. See "proto/tokens/v1/consents.proto"
	tokensPath = "/tokens"
	tokenPath  = "/tokens/"

	// End-point for managing consents. See "proto/tokens/v1/tokens.proto"
	consentsPath = "/consents"
	consentPath  = "/consents/"

	// ---------------------------------------------------------------------------
	// The following are read-only non-admin access to configurations of IC.
	// ---------------------------------------------------------------------------
	// The following provide read-only access to non-admins for various parts of
	// DAM configuration. They filter out sensitive parts of the configuration.
	// See the configuration endpoints above.
	// TODO: remove these and reuse the config endpoint when the caller does not
	// have admin permission.
	identityProvidersPath = "/identity/v1alpha/{realm}/identityProviders"
	clientPath            = "/identity/v1alpha/{realm}/clients/{name}"
	translatorsPath       = "/identity/v1alpha/{realm}/passportTranslators"

	// ---------------------------------------------------------------------------
	// The following are unsupported and to be removed.
	// ---------------------------------------------------------------------------
	accountPath            = "/identity/v1alpha/{realm}/accounts/{name}"
	accountSubjectPath     = "/identity/v1alpha/{realm}/accounts/{name}/subjects/{subject}"
	adminClaimsPath        = "/identity/v1alpha/{realm}/admin/subjects/{name}/account/claims"
	adminTokenMetadataPath = "/identity/v1alpha/{realm}/admin/tokens"
)

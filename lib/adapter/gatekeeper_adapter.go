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

package adapter

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	gatekeeperName        = "gatekeeper"
	gatekeeperAdapterName = "token:jwt:gatekeeper"
	gatekeeperPlatform    = "dam"
	secretsName           = "secrets"
	mainID                = "main"
	keyID                 = "kid"
)

// GatekeeperToken is the token format that is minted here.
type GatekeeperToken struct {
	*jwt.StandardClaims
	AuthorizedParty string   `json:"azp,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
}

// GatekeeperAdapter generates downstream access tokens.
type GatekeeperAdapter struct {
	desc       map[string]*pb.ServiceDescriptor
	privateKey string
}

// NewGatekeeperAdapter creates a GatekeeperAdapter.
func NewGatekeeperAdapter(store storage.Store, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets, adapters *ServiceAdapters) (ServiceAdapter, error) {
	var msg pb.ServicesResponse
	path := adapterFilePath(gatekeeperName)
	if err := srcutil.LoadProto(path, &msg); err != nil {
		return nil, fmt.Errorf("reading %q service descriptors from path %q: %v", aggregatorName, path, err)
	}
	keys := secrets.GetGatekeeperTokenKeys()
	if keys == nil {
		return nil, fmt.Errorf("gatekeeper token keys not found")
	}

	return &GatekeeperAdapter{
		desc:       msg.Services,
		privateKey: keys.PrivateKey,
	}, nil
}

// Name returns the name identifier of the adapter as used in configurations.
func (a *GatekeeperAdapter) Name() string {
	return gatekeeperAdapterName
}

// Platform returns the name identifier of the platform on which this adapter operates.
func (a *GatekeeperAdapter) Platform() string {
	return gatekeeperPlatform
}

// Descriptors returns a map of ServiceAdapter descriptors.
func (a *GatekeeperAdapter) Descriptors() map[string]*pb.ServiceDescriptor {
	return a.desc
}

// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
func (a *GatekeeperAdapter) IsAggregator() bool {
	return false
}

// CheckConfig validates that a new configuration is compatible with this adapter.
func (a *GatekeeperAdapter) CheckConfig(templateName string, template *pb.ServiceTemplate, resName, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *ServiceAdapters) (string, error) {
	if view != nil && len(view.Items) > 1 {
		return httputils.StatusPath("resources", resName, "views", viewName, "items"), fmt.Errorf("view %q has more than one target item defined", viewName)
	}
	return "", nil
}

// MintToken has the adapter mint a token.
func (a *GatekeeperAdapter) MintToken(ctx context.Context, input *Action) (*MintTokenResult, error) {
	if input.MaxTTL > 0 && input.TTL > input.MaxTTL {
		return nil, fmt.Errorf("minting gatekeeper token: TTL of %q exceeds max TTL of %q", timeutil.TTLString(input.TTL), timeutil.TTLString(input.MaxTTL))
	}
	block, _ := pem.Decode([]byte(a.privateKey))
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %v", err)
	}
	now := time.Now()
	aud := ""
	// TODO: support standard audience formats instead of space-delimited.
	for _, item := range input.View.Items {
		if item.Args == nil {
			continue
		}
		if a, ok := item.Args["aud"]; ok {
			if aud != "" {
				aud += " "
			}
			aud += a
		}
	}
	scopes := []string{}
	arg, ok := input.ServiceRole.ServiceArgs["scopes"]
	if ok {
		scopes = arg.Values
	}

	claims := &GatekeeperToken{
		StandardClaims: &jwt.StandardClaims{
			Issuer:    input.Issuer,
			Subject:   input.Identity.Subject,
			Audience:  aud,
			ExpiresAt: now.Add(input.TTL).Unix(),
			NotBefore: now.Add(-1 * time.Minute).Unix(),
			IssuedAt:  now.Unix(),
			Id:        uuid.New(),
		},
		Scopes: scopes,
	}

	jot := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// TODO: should set key id properly and sync with JWKS.
	jot.Header[keyID] = keyID
	token, err := jot.SignedString(priv)
	if err != nil {
		return nil, err
	}
	return &MintTokenResult{
		Credentials: map[string]string{
			"account":      input.Identity.Subject,
			"access_token": token,
		},
		TokenFormat: "base64",
	}, nil
}

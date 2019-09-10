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

package clouds

import (
	"context"
	"fmt"
	"time"

	compb "google3/third_party/hcls_federated_access/common/models/go_proto"
)

type MockTokenCreatorEntry struct {
	AccountID string
	TokenID   string
	TTL       time.Duration
	MaxTTL    time.Duration
	NumKeys   int
	Params    ResourceTokenCreationParams
	IssuedAt  int64
	Expires   int64
	Token     string
}

// MockTokenCreator provides a token creator implementation for testing.
type MockTokenCreator struct {
	includeParams bool
	calls         []MockTokenCreatorEntry
	tokens        map[string][]*compb.TokenMetadata
	tokID         int64
}

// NewMockTokenCreator creates a mock ResourceTokenCreator.
func NewMockTokenCreator(includeParams bool) *MockTokenCreator {
	return &MockTokenCreator{
		includeParams: includeParams,
		calls:         []MockTokenCreatorEntry{},
		tokens:        make(map[string][]*compb.TokenMetadata),
		tokID:         0,
	}
}

// RegisterAccountProject registers account hosting project in key garbage collector.
func (m *MockTokenCreator) RegisterAccountProject(realm, project string, maxRequestedTTL int, keysPerAccount int) error {
	return nil
}

// GetTokenWithTTL returns an account and a resource token for resource accessing.
func (m *MockTokenCreator) GetTokenWithTTL(ctx context.Context, id string, ttl, maxTTL time.Duration, numKeys int, params *ResourceTokenCreationParams) (string, string, error) {
	m.tokID++
	tokenID := fmt.Sprintf("%d", m.tokID)
	entry := MockTokenCreatorEntry{
		AccountID: id,
		TokenID:   tokenID,
		TTL:       ttl,
		MaxTTL:    maxTTL,
		NumKeys:   numKeys,
		IssuedAt:  m.tokID,
		Expires:   m.tokID + 1000,
		Token:     "token_" + tokenID,
	}
	if m.includeParams {
		entry.Params = *params
	}
	tokenUser := testTokenUser(params.AccountProject, id)
	list, ok := m.tokens[tokenUser]
	if !ok {
		list = []*compb.TokenMetadata{}
	}
	m.tokens[tokenUser] = append(list, &compb.TokenMetadata{
		Name:     entry.TokenID,
		IssuedAt: fmt.Sprintf("%d", entry.IssuedAt),
		Expires:  fmt.Sprintf("%d", entry.Expires),
	})
	m.calls = append(m.calls, entry)
	if ttl > maxTTL {
		return "", "", fmt.Errorf("TTL of %v exceeds max TTL of %v", ttl, maxTTL)
	}
	return "acct", entry.Token, nil
}

func testTokenUser(project, id string) string {
	return project + "/" + id
}

// ListTokens returns a list of outstanding access tokens.
func (m *MockTokenCreator) ListTokens(ctx context.Context, project, id string) ([]*compb.TokenMetadata, error) {
	tokenUser := testTokenUser(project, id)
	list, ok := m.tokens[tokenUser]
	if !ok {
		return []*compb.TokenMetadata{}, nil
	}
	return list, nil
}

// DeleteTokens removes tokens belonging to 'id' with given names.
// If 'names' is empty, delete all tokens belonging to 'id'.
func (m *MockTokenCreator) DeleteTokens(ctx context.Context, project, id string, names []string) error {
	tokenUser := testTokenUser(project, id)
	if len(names) == 0 {
		delete(m.tokens, tokenUser)
		return nil
	}
	list, ok := m.tokens[tokenUser]
	if !ok {
		return fmt.Errorf("namespace %q empty (cannot delete %d entries)", tokenUser, len(names))
	}
	for _, name := range names {
		found := false
		for i, entry := range list {
			if entry.Name == name {
				list = append(list[:i-1], list[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("namespace %q token %q not found", tokenUser, name)
		}
	}
	return nil
}

func (m *MockTokenCreator) Calls() []MockTokenCreatorEntry {
	c := m.calls
	m.calls = []MockTokenCreatorEntry{}
	return c
}

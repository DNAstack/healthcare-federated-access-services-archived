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

// Package common contains codes share between IC and DAM.
package common

import (
	"fmt"
	"net/http"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/models"
)

// Permissions type exposes functions access user permissions.
type Permissions struct {
	perm *pb.Permissions
}

// LoadPermissions loads permission from storage/config.
func LoadPermissions(store storage.Store) (*Permissions, error) {
	info := store.Info()
	service := info["service"]
	path := info["path"]
	if service == "" || path == "" {
		return nil, fmt.Errorf("cannot obtain service and path from storage layer")
	}

	// TODO Save these in real storage.
	fs := storage.NewFileStorage(service, path)
	perms := &pb.Permissions{}

	if err := fs.Read(storage.PermissionsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, perms); err != nil {
		return nil, err
	}
	return &Permissions{perm: perms}, nil
}

// CheckAdmin returns http status forbidden and error message if user does not have validate admin permission.
func (p *Permissions) CheckAdmin(id *ga4gh.Identity) (int, error) {
	if !p.isAdmin(id) {
		return http.StatusForbidden, fmt.Errorf("user is not an administrator")
	}
	return http.StatusOK, nil
}

// CheckSubjectOrAdmin returns http status forbidden and an error message if the client isn't the
// subject being requested and also isn't an admin.
func (p *Permissions) CheckSubjectOrAdmin(id *ga4gh.Identity, sub string) (int, error) {
	if id.Subject != sub {
		return p.CheckAdmin(id)
	}
	return http.StatusOK, nil
}

func (p *Permissions) isAdmin(id *ga4gh.Identity) bool {
	now := GetNowInUnixNano()
	if p.isAdminUser(id.Subject, now) {
		return true
	}
	for user := range id.Identities {
		if p.isAdminUser(user, now) {
			return true
		}
	}
	return false
}

func (p *Permissions) isAdminUser(user string, now float64) bool {
	u, ok := p.perm.Users[user]
	if !ok {
		return false
	}
	r, ok := u.Roles["admin"]
	if ok && (r < 0 || r > int64(now)) {
		return true
	}
	return false
}

// IncludeTags returns user's tags and matched tags passed in.
func (p *Permissions) IncludeTags(subject string, tags []string, tagDefs map[string]*pb.AccountTag) []string {
	out := []string{}
	user, ok := p.perm.Users[subject]
	if ok && len(user.Tags) > 0 {
		out = append(out, user.Tags...)
	}
	if len(tags) == 0 || tagDefs == nil {
		return out
	}
	for _, tag := range tags {
		_, ok := tagDefs[tag]
		if !ok {
			continue
		}
		out = append(out, tag)
	}
	return out
}

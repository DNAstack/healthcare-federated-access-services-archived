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

package common

import (
	"reflect"
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	pb "google3/third_party/hcls_federated_access/common/models/go_proto"
)

const (
	testConfigPath = "test/config"
	testService    = "permissions"
)

func TestIncludeTags(t *testing.T) {
	fs := storage.NewMemoryStorage(testService, testConfigPath)

	perm, err := LoadPermissions(fs)
	if err != nil {
		t.Fatalf("cannot load permission config")
	}

	type includeTagsTest struct {
		testName    string
		subject     string
		tags        []string
		tagDefs     []string
		expectation []string
	}

	tests := []includeTagsTest{
		{
			testName:    "tags in permission settings",
			subject:     "admin_and_has_tags",
			tags:        []string{},
			tagDefs:     []string{},
			expectation: []string{"t1", "t2"},
		},
		{
			testName: "no tags in permission settings, tags in pass in tags and tagDefs",
			subject:  "no_tags",
			tags:     []string{"t3", "t4", "t5"},
			tagDefs:  []string{"t3", "t4"},
			// no t5 since t5 not in tagDefs
			expectation: []string{"t3", "t4"},
		},
		{
			testName: "user not in permission settings",
			subject:  "not_a_user",
			tags:     []string{"t3", "t4", "t5"},
			tagDefs:  []string{"t3", "t4"},
			// no t5 since t5 not in tagDefs
			expectation: []string{"t3", "t4"},
		},
		{
			testName: "tags in  pass in tags and tagDefs",
			subject:  "admin_and_has_tags",
			tags:     []string{"t3", "t4", "t5"},
			tagDefs:  []string{"t3", "t4"},
			// no t5 since t5 not in tagDefs
			expectation: []string{"t1", "t2", "t3", "t4"},
		},
	}

	for _, test := range tests {
		tagDefs := make(map[string]*pb.AccountTag)
		for _, tagDef := range test.tagDefs {
			tagDefs[tagDef] = &pb.AccountTag{}
		}

		result := perm.IncludeTags(test.subject, test.tags, tagDefs)
		if !reflect.DeepEqual(result, test.expectation) {
			t.Fatalf("Test case [%q] failed. expected includedTags is %q, actual is %q", test.testName, test.expectation, result)
		}
	}
}

func TestCheckAdmin(t *testing.T) {
	fs := storage.NewMemoryStorage(testService, testConfigPath)

	perm, err := LoadPermissions(fs)
	if err != nil {
		t.Fatalf("cannot load permission config")
	}

	type adminTest struct {
		testName      string
		subject       string
		identities    []string
		expectIsAdmin bool
	}

	tests := []adminTest{
		{
			testName:      "admin user in subject",
			subject:       "admin_and_has_tags",
			identities:    []string{},
			expectIsAdmin: true,
		},
		{
			testName:      "admin user in identities",
			subject:       "no_admin",
			identities:    []string{"admin_and_has_tags"},
			expectIsAdmin: true,
		},
		{
			testName:      "not admin user",
			subject:       "no_admin",
			identities:    []string{},
			expectIsAdmin: false,
		},
		{
			testName:      "admin expired",
			subject:       "expire_admin",
			identities:    []string{},
			expectIsAdmin: false,
		},
	}

	for _, test := range tests {
		identities := make(map[string][]string)
		for _, identity := range test.identities {
			identities[identity] = []string{}
		}
		id := &ga4gh.Identity{
			Subject:    test.subject,
			Identities: identities,
		}
		_, err := perm.CheckAdmin(id)
		if test.expectIsAdmin != (err == nil) {
			t.Fatalf("Test case [%q] failed. expected IsAdmin is %v, actual is %v", test.testName, test.expectIsAdmin, err == nil)
		}
	}
}

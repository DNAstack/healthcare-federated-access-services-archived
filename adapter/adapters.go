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

// Package adapter allows the DAM to take actions.
package adapter

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	pb "google3/third_party/hcls_federated_access/dam/api/v1/go_proto"
	ga4gh "github.com/GoogleCloudPlatform/healthcare-federated-access-services"
)

const (
	// AdapterDataType is the name of adapter file types.
	AdapterDataType = "adapter"
)

// AggregateView defines an aggregated view.
type AggregateView struct {
	Index int
	Res   *pb.Resource
	View  *pb.View
}

// Action provides inputs to action methods on adapters.
type Action struct {
	Aggregates      []*AggregateView
	ClientID        string
	Config          *pb.DamConfig
	GrantRole       string
	Identity        *ga4gh.Identity
	Issuer          string
	MaxTTL          time.Duration
	Request         *http.Request
	Resource        *pb.Resource
	ServiceRole     *pb.ServiceRole
	ServiceTemplate *pb.ServiceTemplate
	TTL             time.Duration
	View            *pb.View
}

// Adapter defines the interface for all DAM adapters that take access actions.
type Adapter interface {
	// Name returns the name identifier of the adapter as used in configurations.
	Name() string

	// Descriptor returns a TargetAdapter descriptor.
	Descriptor() *pb.TargetAdapter

	// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
	IsAggregator() bool

	// CheckConfig validates that a new configuration is compatible with this adapter.
	CheckConfig(templateName string, template *pb.ServiceTemplate, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *TargetAdapters) error

	// MintToken has the adapter mint a token and return <account>, <token>, error.
	MintToken(input *Action) (string, string, error)
}

// TargetAdapters includes all adapters that are registered with the system.
type TargetAdapters struct {
	ByName      map[string]Adapter
	Descriptors map[string]*pb.TargetAdapter
	VariableREs map[string]map[string]map[string]*regexp.Regexp // adapterName.itemFormat.variableName.regexp
	errors      []error
}

// CreateAdapters registers and collects all adapters with the system.
func CreateAdapters(store storage.Store, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets) (*TargetAdapters, error) {
	adapters := &TargetAdapters{
		ByName:      make(map[string]Adapter),
		Descriptors: make(map[string]*pb.TargetAdapter),
		errors:      []error{},
	}
	registerAdapter(adapters, store, warehouse, secrets, NewSawAdapter)
	registerAdapter(adapters, store, warehouse, secrets, NewGatekeeperAdapter)
	registerAdapter(adapters, store, warehouse, secrets, NewAggregatorAdapter)

	if len(adapters.errors) > 0 {
		return nil, adapters.errors[0]
	}

	adapters.VariableREs = createVariableREs(adapters.Descriptors)

	return adapters, nil
}

// GetItemVariables returns a map of variables and their values for a given view item.
func GetItemVariables(adapters *TargetAdapters, targetAdapter, itemFormat string, item *pb.View_Item) (map[string]string, error) {
	adapter, ok := adapters.Descriptors[targetAdapter]
	if !ok {
		return nil, fmt.Errorf("target adapter %q is undefined", targetAdapter)
	}
	format, ok := adapter.ItemFormats[itemFormat]
	if !ok {
		return nil, fmt.Errorf("target adapter %q item format %q is undefined", targetAdapter, itemFormat)
	}
	for varname, val := range item.Vars {
		_, ok := format.Variables[varname]
		if !ok {
			return nil, fmt.Errorf("target adapter %q item format %q variable %q is undefined", targetAdapter, itemFormat, varname)
		}
		re, ok := adapters.VariableREs[targetAdapter][itemFormat][varname]
		if !ok {
			continue
		}
		if !re.Match([]byte(val)) {
			return nil, fmt.Errorf("target adapter %q item format %q variable %q value %q does not match expected regexp", targetAdapter, itemFormat, varname, val)
		}
	}
	return item.Vars, nil
}

// ResolveServiceRole is a helper function that returns a ServiceRole structure from a role name on a view.
func ResolveServiceRole(roleName string, view *pb.View, res *pb.Resource, cfg *pb.DamConfig) (*pb.ServiceRole, error) {
	st, ok := cfg.ServiceTemplates[view.ServiceTemplate]
	if !ok {
		return nil, fmt.Errorf("internal reference to service template %q not found", view.ServiceTemplate)
	}
	sRole, ok := st.ServiceRoles[roleName]
	if !ok {
		return nil, fmt.Errorf("internal reference to service template %q role %q not found", view.ServiceTemplate, roleName)
	}
	return sRole, nil
}

func registerAdapter(adapters *TargetAdapters, store storage.Store, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets, init func(storage.Store, clouds.ResourceTokenCreator, *pb.DamSecrets, *TargetAdapters) (Adapter, error)) {
	adapter, err := init(store, warehouse, secrets, adapters)
	if err != nil {
		adapters.errors = append(adapters.errors, err)
		return
	}
	name := adapter.Name()
	adapters.ByName[name] = adapter
	adapters.Descriptors[name] = adapter.Descriptor()
}

func createVariableREs(descriptors map[string]*pb.TargetAdapter) map[string]map[string]map[string]*regexp.Regexp {
	// Create a compiled set of regular expressions for adapter variable formats
	// of the form: map[<adapterName>]map[<itemFormat>]map[<variableName>]*regexp.Regexp.
	varRE := make(map[string]map[string]map[string]*regexp.Regexp)
	for k, v := range descriptors {
		if len(v.ItemFormats) > 0 {
			fEntry := make(map[string]map[string]*regexp.Regexp)
			varRE[k] = fEntry
			for fk, fv := range v.ItemFormats {
				vEntry := make(map[string]*regexp.Regexp)
				fEntry[fk] = vEntry
				for vk, vv := range fv.Variables {
					if len(vv.Regexp) > 0 {
						vEntry[vk] = regexp.MustCompile(vv.Regexp)
					}
				}
			}
		}
	}
	return varRE
}

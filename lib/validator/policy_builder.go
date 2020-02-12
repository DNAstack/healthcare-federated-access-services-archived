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

package validator

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

var (
	byValues = map[string]bool{
		"self":   true,
		"peer":   true,
		"system": true,
		"so":     true,
		"dac":    true,
	}
)

// BuildPolicyValidator creates a new policy validator.
func BuildPolicyValidator(ctx context.Context, policy *pb.Policy, defs map[string]*pb.ClaimDefinition, sources map[string]*pb.TrustedSource, args map[string]string) (*Policy, error) {
	allow, err := policyValidator(ctx, policy.AnyOf, defs, sources, args)
	if err != nil {
		return nil, err
	}
	return NewPolicy(allow, nil), nil
}

func policyValidator(ctx context.Context, anyOf []*cpb.ConditionSet, defs map[string]*pb.ClaimDefinition, sources map[string]*pb.TrustedSource, args map[string]string) (Validator, error) {
	if len(anyOf) == 0 {
		return nil, nil
	}
	var vor []Validator
	for _, any := range anyOf {
		var vand []Validator
		for _, clause := range any.AllOf {
			if err := validateVisaType(clause.Type, defs); err != nil {
				return nil, err
			}
			srcs, err := expandSources(clause.Type, clause.Source, sources)
			if err != nil {
				return nil, err
			}
			vals, err := expandValues(clause.Value, args)
			if err != nil {
				return nil, err
			}
			by, err := expandBy(clause.By)
			if err != nil {
				return nil, err
			}
			v, err := NewClaimValidator(clause.Type, vals, "", srcs, by)
			if err != nil {
				return nil, err
			}
			vand = append(vand, v)
		}
		vor = append(vor, And(vand))
	}
	return Or(vor), nil
}

func expandSources(claim string, src string, sources map[string]*pb.TrustedSource) (map[string]bool, error) {
	from, err := expandField(src)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool)
	for _, f := range from {
		if common.IsURL(f) {
			out[f] = true
			continue
		}
		source, ok := sources[f]
		if !ok {
			return nil, fmt.Errorf("from %q name is not a valid source name", f)
		}
		for _, src := range source.Sources {
			out[src] = true
		}
	}
	if len(from) == 0 {
		for sname, source := range sources {
			incl := false
			if len(source.Claims) == 0 {
				incl = true
			} else {
				for cidx, c := range source.Claims {
					if len(c) > 1 && c[0] == '^' {
						// Regexp
						re, err := regexp.Compile(c)
						if err != nil {
							return nil, fmt.Errorf("source %q claim %d invalid regular expression %q: %v", sname, cidx, c, err)
						}
						if re.Match([]byte(claim)) {
							incl = true
							break
						}
					} else if c == claim {
						incl = true
						break
					}
				}
			}
			if !incl {
				continue
			}
			for _, src := range source.Sources {
				out[src] = true
			}
		}
	}
	return out, nil
}

func expandValues(input string, args map[string]string) ([]string, error) {
	vals, err := expandField(input)
	if err != nil {
		return nil, err
	}
	if args == nil {
		return vals, err
	}
	for i, v := range vals {
		out, err := common.ReplaceVariables(v, args)
		if err != nil {
			return nil, err
		}
		vals[i] = out
	}
	return vals, nil
}

func expandBy(input string) (map[string]bool, error) {
	list, err := expandField(input)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool)
	for _, by := range list {
		if _, ok := byValues[by]; !ok {
			return nil, fmt.Errorf("by %q is not supported", by)
		}
		out[by] = true
	}
	return out, nil
}

func expandField(input string) ([]string, error) {
	if len(input) == 0 {
		return nil, nil
	}
	i := strings.Index(input, ":")
	if i < 0 {
		return nil, fmt.Errorf("missing pattern type")
	}
	prefix := input[:i]
	suffix := input[i+1:]
	if len(suffix) == 0 {
		return nil, fmt.Errorf("empty suffix")
	}
	// TODO: change this when using the new policy engine
	switch prefix {
	case "const":
		return []string{suffix}, nil
	case "pattern":
		return []string{toPattern(suffix)}, nil
	case "split_pattern":
		sp := strings.Split(suffix, ";")
		for i, s := range sp {
			sp[i] = toPattern(s)
		}
		return sp, nil
	}
	return nil, fmt.Errorf("pattern type %q not supported", prefix)
}

// TODO: remove this helper function
func toPattern(input string) string {
	if !strings.Contains(input, "*") && !strings.Contains(input, "?") {
		return input
	}

	all := regexp.QuoteMeta("*")
	any := regexp.QuoteMeta("?")
	q := regexp.QuoteMeta(input)
	q = strings.ReplaceAll(q, all, ".*")
	q = strings.ReplaceAll(q, any, ".")
	q = "^" + q + "$"

	return q
}

func validateVisaType(typ string, defs map[string]*pb.ClaimDefinition) error {
	if _, ok := defs[typ]; !ok {
		return fmt.Errorf("visa type %q is undefined", typ)
	}
	return nil
}

// ValidatePolicy does basic validation for a policy and (optionally) the variable "args" that a policy instantiation uses.
func ValidatePolicy(policy *pb.Policy, defs map[string]*pb.ClaimDefinition, sources map[string]*pb.TrustedSource, args map[string]string) (string, error) {
	usedArgs := make(map[string]bool)
	valArgs := args
	if valArgs == nil {
		// To allow variable substitution to be attempted, set up variables to substitute based on definitions (regex match not required).
		valArgs = make(map[string]string)
		for v := range policy.VariableDefinitions {
			valArgs[v] = "a"
		}
	}
	for i, any := range policy.AnyOf {
		for j, clause := range any.AllOf {
			if err := validateVisaType(clause.Type, defs); err != nil {
				return httputil.StatusPath("anyOf", strconv.Itoa(i), "allOf", strconv.Itoa(j), "type"), err
			}
			if _, err := expandSources(clause.Type, clause.Source, sources); err != nil {
				return httputil.StatusPath("anyOf", strconv.Itoa(i), "allOf", strconv.Itoa(j), "source"), err
			}
			if _, err := expandValues(clause.Value, valArgs); err != nil {
				return httputil.StatusPath("anyOf", strconv.Itoa(i), "allOf", strconv.Itoa(j), "value"), err
			}
			valArgs, err := common.ExtractVariables(clause.Value)
			if err != nil {
				return httputil.StatusPath("anyOf", strconv.Itoa(i), "allOf", strconv.Itoa(j), "value"), err
			}
			for arg := range valArgs {
				usedArgs[arg] = true
			}
			if _, err := expandBy(clause.By); err != nil {
				return httputil.StatusPath("anyOf", strconv.Itoa(i), "allOf", strconv.Itoa(j), "by"), err
			}
		}
	}
	for name, v := range policy.VariableDefinitions {
		if len(v.Regexp) == 0 {
			return httputil.StatusPath("variableDefinitions", name, "regexp"), fmt.Errorf("regular expression not specified")
		}
		re, err := regexp.Compile(v.Regexp)
		if err != nil {
			return httputil.StatusPath("variableDefinitions", name, "regexp"), fmt.Errorf("invalid regular expression: %v", err)
		}
		if args != nil {
			arg, ok := args[name]
			if !ok {
				return httputil.StatusPath("variableDefinitions", name), fmt.Errorf("variable not provided")
			}
			if !re.Match([]byte(arg)) {
				return httputil.StatusPath("variableDefinitions", name), fmt.Errorf("variable value %q invalid format", arg)
			}
		}
		if v.Ui == nil || v.Ui[common.UIDescription] == "" {
			return httputil.StatusPath("variableDefinitions", name, "ui", common.UIDescription), fmt.Errorf("description not provided")
		}
	}

	prefix := "variableDefinitions"
	if args != nil {
		prefix = "vars"
	}
	for arg := range usedArgs {
		if len(policy.VariableDefinitions) == 0 {
			return httputil.StatusPath(prefix, arg), fmt.Errorf("policy does not use variables")
		}
		if _, ok := policy.VariableDefinitions[arg]; !ok {
			return httputil.StatusPath(prefix, arg), fmt.Errorf("undefined variable")
		}
		if args != nil {
			if _, ok := args[arg]; !ok {
				return httputil.StatusPath(prefix, arg), fmt.Errorf("undefined variable")
			}
		}
	}
	for arg := range args {
		if _, ok := usedArgs[arg]; !ok {
			return httputil.StatusPath(prefix, arg), fmt.Errorf("unused variable")
		}
	}
	return "", nil
}

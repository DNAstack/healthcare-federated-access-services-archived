package adapter

import (
	"context"
	"fmt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/aws"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

const (
	AwsAdapterName = "aws"
    PlatformName   = "aws"
)

type AwsAdapter struct {
	desc      map[string]*pb.ServiceDescriptor
	warehouse *aws.AccountWarehouse
}

func NewAwsAdapter(store storage.Store, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets, adapters *ServiceAdapters) (ServiceAdapter, error) {
	var msg pb.ServicesResponse
	path := adapterFilePath(AwsAdapterName)
	if err := srcutil.LoadProto(path, &msg); err != nil {
		return nil, fmt.Errorf("reading %q service descriptors from path %q: %v", aggregatorName, path, err)
	}
	ctx := context.Background()
	wh, err := aws.NewWarehouse(store, ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS key warehouse: %v", err)
	}

	//Register Accounts
	if err := aws.RegisterAccountGC(store, wh); err != nil {
		return nil, fmt.Errorf("error registering AWS account key GC: %v", err)
	}

	return &AwsAdapter{
		desc: msg.Services,
		warehouse: wh,
	}, nil
}

func (a *AwsAdapter) Name() string {
	return AwsAdapterName
}

func (a *AwsAdapter) Descriptors() map[string]*pb.ServiceDescriptor {
	return a.desc
}

func (a *AwsAdapter) Platform() string {
	return PlatformName
}

func (a *AwsAdapter) IsAggregator() bool {
	return false
}

func (a *AwsAdapter) CheckConfig(templateName string, template *pb.ServiceTemplate, resName, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *ServiceAdapters) (string, error) {
	return "", nil
}

func (a *AwsAdapter) MintToken(ctx context.Context, input *Action) (*MintTokenResult, error) {
	if a.warehouse == nil {
		return nil, fmt.Errorf("AWS minting token: DAM service account warehouse not configured")
	}
	userID := ga4gh.TokenUserID(input.Identity, SawMaxUserIDLength)
	params, err := createAwsResourceTokenCreationParams(userID, input)
	if err != nil {
		return nil, fmt.Errorf("AWS minting token: %v", err)
	}
	result, err := a.warehouse.MintTokenWithTTL(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("AWS minting token: %v", err)
	}

	return &MintTokenResult{
		Credentials: map[string]string{
			"account":       result.Account,
			"access_key_id": result.AccessKeyId,
			"secret":        result.SecretAccessKey,
			"session_token": result.SessionToken,

		},
		TokenFormat: result.Format,
	}, nil
}

func createAwsResourceTokenCreationParams(userID string, input *Action) (*aws.ResourceParams, error) {
	var roles []string
	var scopes []string
	if input.ServiceRole != nil {
		rolesArg := input.ServiceRole.ServiceArgs["roles"]
		if rolesArg != nil && rolesArg.GetValues() != nil && len(rolesArg.GetValues()) > 0 {
			roles = append(roles, rolesArg.GetValues()...)
		}
		scopesArg := input.ServiceRole.ServiceArgs["scopes"]
		if scopesArg != nil && scopesArg.GetValues() != nil && len(scopesArg.GetValues()) > 0 {
			scopes = append(scopes, scopesArg.GetValues()...)
		}
	}
	var vars map[string]string
	if len(input.View.Items) == 0 {
		vars = make(map[string]string, 0)
	} else if len(input.View.Items) == 1 {
		vars = scrubVars(input.View.Items[0].Args)
	} else {
		return nil, fmt.Errorf("too many items declared")
	}
	maxKeyTTL := timeutil.ParseDurationWithDefault(input.Config.Options.GcpManagedKeysMaxRequestedTtl, input.MaxTTL)

	return &aws.ResourceParams{
		UserId:                userID,
		Ttl:                   input.TTL,
		MaxKeyTtl:             maxKeyTTL,
		ManagedKeysPerAccount: int(input.Config.Options.GcpManagedKeysPerAccount),
		Vars:                  vars,
		TargetRoles:           roles,
		TargetScopes:          scopes,
		TokenFormat:           input.TokenFormat,
		DamResourceId:         input.ResourceId,
		DamViewId:             input.ViewId,
		DamRoleId:             input.GrantRole,
		View:                  input.View,
		ServiceTemplate:       input.ServiceTemplate,
	}, nil
}

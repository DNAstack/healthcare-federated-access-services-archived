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

// Package gcp abstracts interacting with certain aspects of Google Cloud
// Platform, such as creating service account keys and access tokens.
package aws

import (
	"context"
	"fmt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/processaws"
	v1 "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/cenkalti/backoff"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"crypto/sha1"
	"hash"
)

const (
	TemporaryCredMaxTtl = 12 * time.Hour
	S3ItemFormat        = "s3bucket"
	RedshiftItemFormat  = "redshift"
)

type principalType int

const (
	emptyPType principalType = iota
	userType
	roleType
)

type resourceType int

const (
	otherRType resourceType = iota
	bucketType
)

const (
	backoffInitialInterval     = 1 * time.Second
	backoffRandomizationFactor = 0.5
	backoffMultiplier          = 1.5
	backoffMaxInterval         = 3 * time.Second
	backoffMaxElapsedTime      = 10 * time.Second
)

const (
	defaultGcFrequency = 1 * 24 * time.Hour /* 1 day */
	defaultKeysPerAccount = 1 //FIXME my assumption is there is only one key per account
)

var (
	exponentialBackoff = &backoff.ExponentialBackOff{
		InitialInterval:     backoffInitialInterval,
		RandomizationFactor: backoffRandomizationFactor,
		Multiplier:          backoffMultiplier,
		MaxInterval:         backoffMaxInterval,
		MaxElapsedTime:      backoffMaxElapsedTime,
		Clock:               backoff.SystemClock,
	}
)

// AccountWarehouse is used to create AWS IAM Users and temporary credentials
type AccountWarehouse struct {
	svcUserArn *string
	store      storage.Store
	tmp        map[string]iam.AccessKey
	keyGC      *processaws.KeyGc
}

func (wh *AccountWarehouse) GetServiceAccounts(ctx context.Context, project string) (<-chan *clouds.Account, error) {
	panic("implement me getserviceaccounts")
}

func (wh *AccountWarehouse) RemoveServiceAccount(ctx context.Context, project, accountID string) error {
	panic("implement me removeserviceaccount")
}

func (wh *AccountWarehouse) ManageAccountKeys(ctx context.Context, project, accountID string, ttl, maxKeyTTL time.Duration, now time.Time, keysPerAccount int64) (int, int, error) {
	panic("implement me manageaccountkeys")
}

type ResourceParams struct {
	UserId                string
	Ttl                   time.Duration
	MaxKeyTtl             time.Duration
	ManagedKeysPerAccount int
	Vars                  map[string]string
	TargetRoles           []string
	TargetScopes          []string
	TokenFormat           string
	DamResourceId         string
	DamViewId             string
	DamRoleId             string
	View                  *v1.View
	ServiceTemplate       *v1.ServiceTemplate
}

type resourceSpec struct {
	rType resourceType
	arn   string
	id    string
}

type principalSpec struct {
	pType principalType
	// Used for roles that must be assumed
	damPrincipalArn string
	params          *ResourceParams
}

func (spec *principalSpec) getId() string {
	switch spec.pType {
	case userType:
		return convertToAwsSafeIdentifier(spec.params.UserId)
	case roleType:
		return spec.params.DamResourceId + "," + spec.params.DamViewId + "," + spec.params.DamRoleId
	default:
		panic(fmt.Sprintf("cannot get ID for princpal type [%v]", spec.pType))
	}
}

func (spec *principalSpec) getArn() string {
	switch spec.pType {
	case userType:
		return fmt.Sprintf("arn:aws:iam::%s:user/%s", extractAccount(spec.damPrincipalArn), spec.getId())
	case roleType:
		return fmt.Sprintf("arn:aws:iam::%s:role/%s", extractAccount(spec.damPrincipalArn), spec.getId())
	default:
		panic(fmt.Sprintf("cannot get ID for princpal type [%v]", spec.pType))
	}
}

func calculateUserArn(clusterArn string, userName string) string {
	parts := strings.Split(clusterArn, ":")

	return fmt.Sprintf( "%s:%s:%s:%s:%s:dbuser:%s/%s", parts[0], parts[1], parts[2], parts[3], parts[4], parts[6], userName)
}

func extractAccount(arn string) string {
	parts := strings.Split(arn, ":")
	return parts[4]
}

func extractClusterName(arn string) string {
	parts := strings.Split(arn, ":")
	return parts[6]
}

func extractDBGroupName(arn string) string {
	arnParts := strings.Split(arn, ":")
	pathParts := strings.Split(arnParts[6], "/")

	return pathParts[len(pathParts)-1]
}

type policySpec struct {
	principal *principalSpec
	rSpecs    []*resourceSpec
	params    *ResourceParams
}

// NewAccountWarehouse creates a new AccountWarehouse using the provided client
// and options.
func NewWarehouse(store storage.Store, ctx context.Context) (*AccountWarehouse, error) {
	wh := &AccountWarehouse{
		store: store,
		tmp: make(map[string]iam.AccessKey),
		keyGC: nil,
	}
	wh.keyGC = processaws.NewKeyGC("aws_key_gc", wh, store, defaultGcFrequency, defaultKeysPerAccount)

	go wh.Run(ctx)
	return wh, nil
}

func RegisterAccountGC(store storage.Store, wh *AccountWarehouse) (error) {
	tx, err := store.Tx(true)
	if err !=nil {
		return err
	}

	return wh.RegisterAccountProject("test-project", tx)
}

// MintTokenWithTTL returns an AccountKey or an AccessToken depending on the TTL requested.
func (wh *AccountWarehouse) MintTokenWithTTL(ctx context.Context, params *ResourceParams) (*clouds.AwsResourceTokenResult, error) {
	sess, err := createSession()
	if err != nil {
		return nil, err
	}

	if params.Ttl > params.MaxKeyTtl {
		return nil, fmt.Errorf("given ttl [%s] is greater than max ttl [%s]", params.Ttl, params.MaxKeyTtl)
	}

	// FIXME load in constructor function?
	svcUserArn, err := wh.loadSvcUserArn(sess)
	if err != nil {
		return nil, err
	}
	princSpec := &principalSpec{
		damPrincipalArn: svcUserArn,
		params:          params,
	}

	if params.Ttl > TemporaryCredMaxTtl {
		princSpec.pType = userType
	} else {
		princSpec.pType = roleType
	}

	var polSpec *policySpec
	switch params.ServiceTemplate.ServiceName {
	case S3ItemFormat:
		bucket, ok := params.Vars["bucket"]
		if !ok {
			return nil, fmt.Errorf("no bucket specified")
		}
		rSpec := &resourceSpec{
			id:    bucket,
			arn:   fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			rType: bucketType,
		}
		polSpec = &policySpec{
			principal: princSpec,
			rSpecs:    []*resourceSpec{rSpec},
			params:    params,
		}
	case RedshiftItemFormat:
		clusterArn, ok := params.Vars["cluster"]
		if !ok {
			return nil, fmt.Errorf("no cluster specified")
		}
		clusterSpec := &resourceSpec{
			rType: otherRType,
			arn:   clusterArn,
			id:    extractClusterName(clusterArn),
		}
		dbuser := convertToAwsSafeIdentifier(params.UserId)
		userSpec := &resourceSpec{
			rType: otherRType,
			arn:   calculateUserArn(clusterArn, dbuser),
			id:    dbuser,
		}
		group, ok := params.Vars["group"]
		var rSpecs []*resourceSpec
		if ok {
			rSpecs = []*resourceSpec{
				clusterSpec,
				userSpec,
				{
					rType: otherRType,
					arn:   group,
					id:    extractDBGroupName(group),
				},
			}
		} else {
			rSpecs = []*resourceSpec{clusterSpec,userSpec}
		}

		polSpec = &policySpec{
			principal: princSpec,
			rSpecs:    rSpecs,
			params:    params,
		}
	default:
		return nil, fmt.Errorf("unrecognized item format [%s] for AWS target adapter", params.ServiceTemplate.ServiceName)
	}

	principalArn, err := ensurePrincipal(sess, princSpec)
	if err != nil {
		return nil, err
	}
	err = ensurePolicy(sess, polSpec)
	if err != nil {
		return nil, err
	}

	return wh.ensureTokenResult(sess, principalArn, princSpec)
}

func (wh *AccountWarehouse) ensureTokenResult(sess *session.Session, principalArn string, princSpec *principalSpec) (*clouds.AwsResourceTokenResult, error) {
	switch princSpec.pType {
	case userType:
		return wh.ensureAccessKeyResult(sess, principalArn, princSpec)
	case roleType:
		return createTempCredentialResult(sess, principalArn, princSpec.params)
	default:
		return nil, fmt.Errorf("cannot generate token for invalid spec with [%v] principal type", princSpec.pType)
	}
}

func createTempCredentialResult(sess *session.Session, principalArn string, params *ResourceParams) (*clouds.AwsResourceTokenResult, error) {
	svc := sts.New(sess)
	userId := convertUserIdToSessionName(params.UserId)
	aro, err := assumeRole(userId, svc, principalArn, params.Ttl)
	if err != nil {
		return nil, err
	}
	return &clouds.AwsResourceTokenResult{
		Account: *aro.AssumedRoleUser.AssumedRoleId,
		AccessKeyId:   *aro.Credentials.AccessKeyId,
		SecretAccessKey:   *aro.Credentials.SecretAccessKey,
		SessionToken:   *aro.Credentials.SessionToken,
		Format:  "aws",
	}, nil
}

func (wh *AccountWarehouse) ensureAccessKeyResult(sess *session.Session, principalArn string, princSpec *principalSpec) (*clouds.AwsResourceTokenResult, error) {
	accessKey, err := wh.ensureAccessKey(sess, princSpec.getId())
	if err != nil {
		return nil, err
	}
	//wh.keyGC.RegisterWork("access_key", nil, nil)
	return &clouds.AwsResourceTokenResult{
		Account: principalArn,
		AccessKeyId: *accessKey.AccessKeyId,
		SecretAccessKey: *accessKey.SecretAccessKey,
		Format:  "aws",
	}, nil
}

func ensurePrincipal(sess *session.Session, princSpec *principalSpec) (string, error) {
	if princSpec.params.Ttl > TemporaryCredMaxTtl {
		return ensureUser(sess, princSpec)
	} else {
		return ensureRole(sess, princSpec)
	}
}

func ensurePolicy(sess *session.Session, spec *policySpec) error {
	if len(spec.rSpecs) == 0 {
		return fmt.Errorf("cannot have policy without any resources")
	} else {
		return ensureIdentityBasedPolicy(sess, spec)
	}
}

func ensureIdentityBasedPolicy(sess *session.Session, spec *policySpec) error {
	switch spec.principal.pType {
	case userType:
		return ensureUserPolicy(sess, spec)
	case roleType:
		return ensureRolePolicy(sess, spec)
	default:
		return fmt.Errorf("cannot generate policy for invalid spec with [%v] principal type", spec.principal.pType)
	}
}

func convertToAwsSafeIdentifier(val string) string {
	return strings.ReplaceAll(val, "|", "@")
}

func convertUserIdToSessionName(userId string) string{
	parts := strings.SplitN(userId, "|", 2)
	sessionName := parts[0] + "@" + stringHash(parts[1])
	maxLen := 64
	if len(sessionName) < 64 {
		maxLen = len(sessionName)
	}
	return sessionName[0:maxLen]
}

// TODO: figure out right place to have this code
//CreateHash method
func createHash(byteStr []byte) []byte {
	var hashVal hash.Hash
	hashVal = sha1.New()
	hashVal.Write(byteStr)

	var bytes []byte

	bytes = hashVal.Sum(nil)
	return bytes
}

func stringHash(val string) string {
	h := createHash([]byte(val))
	return fmt.Sprintf("%x", h)
}

func assumeRole(sessionName string, svcSts *sts.STS, roleArn string, ttl time.Duration) (*sts.AssumeRoleOutput, error) {
	aro, err := svcSts.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: toSeconds(ttl),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to assume role %s: %v", roleArn, err)
	}
	return aro, nil
}

func (wh *AccountWarehouse) ensureAccessKey(sess *session.Session, userId string) (iam.AccessKey, error) {
	svc := iam.New(sess)
	// TODO persist access key, lookup from store
	accessKey, ok := wh.tmp[userId]
	if !ok {
		kres, err := svc.CreateAccessKey(&iam.CreateAccessKeyInput{
			UserName: aws.String(userId),
		})
		if err != nil {
			return iam.AccessKey{}, fmt.Errorf("unable to create access key for user %s: %v", userId, err)
		}
		accessKey = *kres.AccessKey
		wh.tmp[userId] = accessKey
	}
	return accessKey, nil
}

func (wh *AccountWarehouse) loadSvcUserArn(sess *session.Session) (string, error) {
	svc := sts.New(sess)
	if wh.svcUserArn != nil {
		return *wh.svcUserArn, nil
	} else {
		gcio, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			return "", err
		} else {
			wh.svcUserArn = gcio.Arn
			return *wh.svcUserArn, nil
		}
	}
}

func ensureRolePolicy(sess *session.Session, spec *policySpec) error {
	svc := iam.New(sess)
	// FIXME handle versioning
	actions := valuesToJsonStringArray(spec.params.TargetRoles)
	resourceArns := resourceArnsToJsonStringArray(spec.rSpecs)
	// FIXME user serialization library
	policy := fmt.Sprintf(
		`{
								"Version":"2012-10-17",
								"Statement":
								{
									"Effect":"Allow",
									"Action":%s,
									"Resource":%s
								}
							}`, actions, resourceArns)
	_, err := svc.PutRolePolicy(&iam.PutRolePolicyInput{
		PolicyName:     aws.String(spec.principal.getId()),
		RoleName:       aws.String(spec.principal.getId()),
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		return fmt.Errorf("unable to create AWS role policy %s: %v", spec.principal.getId(), err)
	} else {
		return nil
	}
}

func ensureUserPolicy(sess *session.Session, spec *policySpec) error {
	svc := iam.New(sess)
	// FIXME handle versioning
	actions := valuesToJsonStringArray(spec.params.TargetRoles)
	resources := resourceArnsToJsonStringArray(spec.rSpecs)
	// FIXME user serialization library
	policy := fmt.Sprintf(
		`{
								"Version":"2012-10-17",
								"Statement":
								{
									"Effect":"Allow",
									"Action":%s,
									"Resource":%s,
									"Condition": {
										"DateLessThanEquals": {"aws:CurrentTime": "%s"}
									}
								}
							}`, actions, resources, (time.Now().Add(spec.params.Ttl)).Format(time.RFC3339) )
	f := func() error { return putUserPolicy(svc, spec, policy) }
	if err := backoff.Retry(f, exponentialBackoff); err != nil {
		return err
	}
	return nil
}

func putUserPolicy(svc *iam.IAM, spec *policySpec, policy string) error {
	_, err := svc.PutUserPolicy(&iam.PutUserPolicyInput{
		PolicyName:     aws.String(spec.principal.getId()),
		UserName:       aws.String(spec.principal.getId()),
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "MalformedPolicy" && strings.Contains(aerr.Message(), "Invalid principal in policy") {
			return fmt.Errorf("unable to create AWS user policy %s: %v", spec.principal.getId(), err)
		} else {
			return backoff.Permanent(fmt.Errorf("unable to create AWS user policy %s: %v", spec.principal.getId(), err))
		}
	} else {
		return nil
	}
}


// ensures user is created and returns non-empty user ARN if successful
func ensureUser(sess *session.Session, spec *principalSpec) (string, error) {
	svc := iam.New(sess)
	var userArn string
	guo, err := svc.GetUser(&iam.GetUserInput{
		UserName: aws.String(spec.getId()),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			cuo, err := svc.CreateUser(&iam.CreateUserInput{
				UserName: aws.String(spec.getId()),
			})
			if err != nil {
				return "", fmt.Errorf("unable to create IAM user %s: %v", spec.getId(), err)
			} else {
				userArn = *cuo.User.Arn
			}
		} else {
			return "", fmt.Errorf("unable to send AWS IAM request for user %s: %v", spec.getId(), err)
		}
	} else {
		userArn = *guo.User.Arn
	}
	return userArn, nil
}

func ensureRole(sess *session.Session, spec *principalSpec) (string, error) {
	svc := iam.New(sess)
	// FIXME should include a path based on the DAM URL
	gro, err := svc.GetRole(&iam.GetRoleInput{
		RoleName: aws.String(spec.getId()),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			policy := fmt.Sprintf(
				`{
								"Version":"2012-10-17",
								"Statement":
								{
									"Effect":"Allow",
									"Principal": { "AWS": "%s" },
									"Action": "sts:AssumeRole"
								}
							}`, spec.damPrincipalArn)
			cro, err := svc.CreateRole(&iam.CreateRoleInput{
				AssumeRolePolicyDocument: aws.String(policy),
				RoleName:                 aws.String(spec.getId()),
				MaxSessionDuration: toSeconds(TemporaryCredMaxTtl),
				Tags: []*iam.Tag{
					{
						Key:   aws.String("DamResource"),
						Value: aws.String(spec.params.DamResourceId),
					},
					{
						Key:   aws.String("DamView"),
						Value: aws.String(spec.params.DamViewId),
					},
					{
						Key:   aws.String("DamRole"),
						Value: aws.String(spec.params.DamRoleId),
					},
				},
			})
			if err != nil {
				return "", fmt.Errorf("unable to create AWS role %s: %v", spec.getId(), err)
			} else {
				return *cro.Role.Arn, nil
			}
		} else {
			return "", fmt.Errorf("unable to retrieve AWS role %s: %v", spec.getId(), err)
		}
	} else {
		return *gro.Role.Arn, nil
	}
}

func toSeconds(duration time.Duration) *int64 {
	seconds := duration.Nanoseconds() / time.Second.Nanoseconds()
	return &seconds
}

func createSession() (*session.Session, error) {
	rootSess, err := session.NewSession(&aws.Config{
		// FIXME pull from config
		Region: aws.String("ca-central-1"),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create AWS root session: %v", err)
	} else {
		return rootSess, err
	}
}

func resourceArnsToJsonStringArray(rSpecs []*resourceSpec) string {
	arns := make([]string, len(rSpecs))
	for i, rSpec := range rSpecs {
		arns[i] = rSpec.arn
	}

	return valuesToJsonStringArray(arns)
}

func valuesToJsonStringArray(targetRoles []string) string {
	builder := strings.Builder{}
	builder.WriteByte('[')
	for i, role := range targetRoles {
		builder.WriteByte('"')
		builder.WriteString(role)
		builder.WriteByte('"')
		if (i + 1) < len(targetRoles) {
			builder.WriteByte(',')
		}
	}
	builder.WriteByte(']')

	return builder.String()
}

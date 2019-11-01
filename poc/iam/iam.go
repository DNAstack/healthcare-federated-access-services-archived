package iam

import (
	"fmt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/poc/common"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"os"
)

func Main(args []string) {
	sess, err := common.Session()
	if err != nil {
		fmt.Printf("Made an error: %v\n", err)
		os.Exit(1)
	}
	_, err = sess.Config.Credentials.Get()
	if err != nil {
		fmt.Println("Couldn't find credentials")
		os.Exit(1)
	}
	iamSvc := iam.New(sess)
	userName := "my-first-test-user"
	roleName := "my-first-role"
	if len(args) == 1 {
		fmt.Printf("usage: %s {create-user|get-user|delete-user|create-policy|create-token|delete-token}\n", args[0])
		os.Exit(1)
	} else if args[1] == "create-user" {
		output, err := iamSvc.CreateUser(&iam.CreateUserInput{
			UserName: aws.String(userName),
		})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "get-bad-user" {
		output, err := iamSvc.GetUser(&iam.GetUserInput{
			UserName: aws.String("invalid-user"),
		})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "get-user" {
		output, err := iamSvc.GetUser(&iam.GetUserInput{
			UserName: aws.String(userName),
		})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "delete-user" {
		output, err := iamSvc.DeleteUser(&iam.DeleteUserInput{
			UserName: aws.String(userName),
		})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "create-policy" {
		policy := `{
				  "Version":"2012-10-17",
				  "Statement":[
				    {
				      "Sid":"MyFirstPolicy",
				      "Effect":"Allow",
				      "Action":["s3:PutObject","s3:PutObjectAcl","s3:GetObject"],
				      "Resource":["arn:aws:s3:::max-dev-test-bucket/*"]
				    }
				  ]
				}`
		output, err := iamSvc.PutUserPolicy(&iam.PutUserPolicyInput{
			UserName:       aws.String(userName),
			PolicyName:     aws.String("my-first-policy"),
			PolicyDocument: aws.String(policy),
		})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "create-token" {
		output, err := iamSvc.CreateAccessKey(&iam.CreateAccessKeyInput{
			UserName: aws.String(userName),
		})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "create-role" {
		output, err := createRole(iamSvc, roleName, "arn:aws:iam::582623027427:user/my-first-test-user")

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "create-role-policy" {
		output, err := createRolePolicy(iamSvc, roleName, "my-first-role-policy")

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "get-role" {
		output, err := iamSvc.GetRole(&iam.GetRoleInput{
			RoleName: aws.String(roleName),
		})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "delete-role" {
		output, err := iamSvc.DeleteRole(&iam.DeleteRoleInput{
			RoleName: aws.String(roleName),
		})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "get-role-policy" {
		output, err := iamSvc.GetRolePolicy(&iam.GetRolePolicyInput{
			PolicyName: aws.String("my-first-role-policy"),
			RoleName:   aws.String(roleName),
		})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "assume-role" {
		creds := credentials.NewSharedCredentials("/home/max/.aws/credentials", "test-user")
		stsSvc := sts.New(sess, aws.NewConfig().WithCredentials(creds))
		output, err := stsSvc.AssumeRole(&sts.AssumeRoleInput{
			RoleArn:         aws.String("arn:aws:iam::582623027427:role/my-first-role"),
			RoleSessionName: aws.String("my_first_role_session"),
		})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	} else if args[1] == "test-static-creds" {
		creds := credentials.NewStaticCredentials("id", "secret", "")
		stsSvc := sts.New(sess, aws.NewConfig().WithCredentials(creds).WithLogLevel(aws.LogDebugWithHTTPBody))
		output, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})

		if err != nil {
			fmt.Printf("Oh no! %v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("We did it! %v\n", output)
		}
	}
}

func createRolePolicy(iamSvc *iam.IAM, roleName string, policyName string) (*iam.PutRolePolicyOutput, error) {
	policy := `{
								  "Version":"2012-10-17",
								  "Statement":
								    {
								      "Effect":"Allow",
								      "Action":["s3:PutObject","s3:PutObjectAcl","s3:GetObject"],
								      "Resource":["arn:aws:s3:::max-dev-test-bucket/*"]
								    }
								}`
	output, err := iamSvc.PutRolePolicy(&iam.PutRolePolicyInput{
		PolicyDocument: aws.String(policy),
		PolicyName:     aws.String(policyName),
		RoleName:       aws.String(roleName),
	})
	return output, err
}

func createRole(iamSvc *iam.IAM, roleName string, principal string) (*iam.CreateRoleOutput, error) {
	trustPolicy := fmt.Sprintf(`{
						  "Version":"2012-10-17",
						  "Statement":
						    {
						      "Effect":"Allow",
				              "Principal": { "AWS": "%s" },
						      "Action": "sts:AssumeRole"
						    }
						}`, principal)
	output, err := iamSvc.CreateRole(&iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(trustPolicy),
		RoleName:                 aws.String(roleName),
	})
	return output, err
}

type redshiftGroupPolicySpec struct {
	roleName   string
	policyName string
	dbUserArn  string
	dbArn      string
	dbGroupArn string
}

func createRedshiftAccessPolicy(iamSvc *iam.IAM, spec *redshiftGroupPolicySpec) (*iam.PutRolePolicyOutput, error) {
	policy := fmt.Sprintf(`{
								  "Version":"2012-10-17",
								  "Statement": [
								    {
								      "Effect":"Allow",
								      "Action":["redshift:GetClusterCredentials"],
								      "Resource":["%s", "%s", "%s"]
								    },
								    {
								      "Effect":"Allow",
								      "Action":["redshift:CreateClusterUser"],
								      "Resource":["%s"]
								    },
								    {
								      "Effect":"Allow",
								      "Action":["redshift:JoinGroup"],
								      "Resource":["%s"]
								    }
                                  ]
								}`,
		spec.dbUserArn, spec.dbGroupArn, spec.dbArn,
		spec.dbUserArn,
		spec.dbGroupArn)
	output, err := iamSvc.PutRolePolicy(&iam.PutRolePolicyInput{
		PolicyDocument: aws.String(policy),
		PolicyName:     aws.String(spec.policyName),
		RoleName:       aws.String(spec.roleName),
	})

	if err != nil {
		return nil, fmt.Errorf("error creating redshift access policy: %v", err)
	} else {
		return output, nil
	}
}

type DbTokenInput struct {
	ClusterName string
	DbName      string
	TableName   string
	GroupName   string
	UserName    string
	Region      string
}

func GetDbToken(input *DbTokenInput) (*sts.AssumeRoleOutput, error) {
	sess, err := common.Session()
	if err != nil {
		return nil, err
	}
	stsSvc := sts.New(sess)
	iamSvc := iam.New(sess)

	gcio, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}

	var roleArn *string
	cro, err := createRole(iamSvc, input.TableName, *gcio.Arn)
	if err != nil {
		if aerr, ok := err.(awserr.Error); !(ok && aerr.Code() == iam.ErrCodeEntityAlreadyExistsException) {
			return nil, err
		} else {
			gro, err := iamSvc.GetRole(&iam.GetRoleInput{
				RoleName: aws.String(input.TableName),
			})
			if err != nil {
				return nil, err
			} else {
				roleArn = gro.Role.Arn
			}
		}
	} else {
		roleArn = cro.Role.Arn
	}

	_, err = createRedshiftAccessPolicy(iamSvc, &redshiftGroupPolicySpec{
		roleName:   input.TableName,
		policyName: input.TableName,
		dbUserArn:  fmt.Sprintf("arn:aws:redshift:%s:%s:dbuser:%s/%s", input.Region, *gcio.Account, input.ClusterName, input.UserName),
		dbArn:      fmt.Sprintf("arn:aws:redshift:%s:%s:dbname:%s/%s", input.Region, *gcio.Account, input.ClusterName, input.DbName),
		dbGroupArn: fmt.Sprintf("arn:aws:redshift:%s:%s:dbgroup:%s/%s", input.Region, *gcio.Account, input.ClusterName, input.GroupName),
	})
	if err != nil {
		return nil, err
	}

	aro, err := stsSvc.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         roleArn,
		// put user id here
		RoleSessionName: aws.String("my_first_role_session"),
	})

	return aro, err
}

package main

import (
	"fmt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/poc/iam"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/poc/redshift"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"os"
)

func main() {
	switch os.Args[1] {
	case "redshift":
		rsCommand := os.Args[2]
		switch rsCommand {
		case "test":
			val, err := redshift.TestRedshift()
			if err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			} else {
				fmt.Printf("got out this value: %s\n", val)
			}
		case "create-group":
			groupName := os.Args[3]
			err := redshift.CreateGroup(groupName)
			if err != nil {
				fmt.Printf("Error creating group: %v\n", err)
				os.Exit(1)
			}
		case "check-group":
			groupName := os.Args[3]
			found, err := redshift.CheckGroup(groupName)
			if err != nil {
				fmt.Printf("Error creating group: %v\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Does %s exist? %t\n", groupName, found)
				os.Exit(0)
			}
		case "delete-group":
			groupName := os.Args[3]
			err := redshift.DeleteGroup(groupName)
			if err != nil {
				fmt.Printf("Error creating group: %v\n", err)
				os.Exit(1)
			}
		case "grant-group":
			groupName := os.Args[3]
			tableName := os.Args[4]
			err := redshift.GrantGroup(groupName, tableName)
			if err != nil {
				fmt.Printf("Error creating group: %v\n", err)
				os.Exit(1)
			}
		default:
			fmt.Printf("Unknown redshift command: %s\n", rsCommand)
			os.Exit(1)
		}

	case "iam":
		iamCommand := os.Args[2]
		switch iamCommand {
		case "assume-db-role":
			output, err := iam.GetDbToken(&iam.DbTokenInput{
				ClusterName: os.Args[3],
				DbName:      os.Args[4],
				TableName:   os.Args[5],
				GroupName:   os.Args[6],
				UserName:    "test-user",
				Region:      "us-east-1",
			})
			if err != nil {
				fmt.Printf("Error getting db token: %v\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Assumed role info: %v\n", output)
			}
		case "temp-db-credential":
			clusterName := os.Args[3]
			dbName := os.Args[4]
			tableName := os.Args[5]
			groupName := os.Args[6]
			dbUser := "test-user"
			aro, err := iam.GetDbToken(&iam.DbTokenInput{
				ClusterName: clusterName,
				DbName:      dbName,
				TableName:   tableName,
				GroupName:   groupName,
				UserName:    dbUser,
				Region:	     "us-east-1",
			})
			if err != nil {
				fmt.Printf("Error getting db token: %v\n", err)
				os.Exit(1)
			}

			creds := credentials.NewStaticCredentials(*aro.Credentials.AccessKeyId, *aro.Credentials.SecretAccessKey, *aro.Credentials.SessionToken)
			output, err := redshift.GetClusterCredentials(&redshift.GetClusterCredentialsInput{
				Creds:       creds,
				ClusterName: aws.String(clusterName),
				DbGroup:     aws.String(groupName),
				DbName:      aws.String(dbName),
				DbUser:      aws.String(dbUser),
				Region:	     aws.String("us-east-1"),
			})
			if err != nil {
				fmt.Printf("Error getting cluster credential: %v\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Temp DB credential: %v\n", output)
			}
		default:
			iam.Main(os.Args[2:])
		}

	default:
		fmt.Printf("Unknown command group: %s\n", os.Args[1])
		os.Exit(1)
	}
}

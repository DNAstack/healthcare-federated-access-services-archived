package common

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"os"
)

func defaultSession() (*session.Session, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("ca-central-1"),
	})
	return sess, err
}

func debugSession() (*session.Session, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("ca-central-1"),
		LogLevel: aws.LogLevel(aws.LogDebugWithHTTPBody),
	})
	return sess, err
}

func Session() (*session.Session, error) {
	var sess *session.Session
	var err error
	level, _ := os.LookupEnv("LOGGING")
	if level == "DEBUG" {
		sess, err = debugSession()
	} else {
		sess, err = defaultSession()
	}

	return sess, err
}

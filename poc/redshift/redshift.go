package redshift

import (
	"database/sql"
	"fmt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/poc/common"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/redshift"
	_ "github.com/lib/pq"
	"os"
)

type dbConfig struct {
	user     string
	password string
	host     string
	port     string
	dbname   string
}

func TestRedshift() (string, error) {
	dbConfig, e := loadDbConfig()
	if e != nil {
		return "", e
	}
	return test(dbConfig)
}

func loadDbConfig() (*dbConfig, error) {
	var user string
	var password string
	var host string
	var port string
	var dbname string
	var ok bool
	if user, ok = os.LookupEnv("RS_USER"); !ok {
		return nil, fmt.Errorf("missing RS_USER")
	}
	if password, ok = os.LookupEnv("RS_PASSWORD"); !ok {
		return nil, fmt.Errorf("missing RS_PASSWORD")
	}
	if host, ok = os.LookupEnv("RS_HOST"); !ok {
		return nil, fmt.Errorf("missing RS_HOST")
	}
	if port, ok = os.LookupEnv("RS_PORT"); !ok {
		return nil, fmt.Errorf("missing RS_PORT")
	}
	if dbname, ok = os.LookupEnv("RS_DBNAME"); !ok {
		return nil, fmt.Errorf("missing RS_DBNAME")
	}
	dbConfig := &dbConfig{
		user:     user,
		password: password,
		host:     host,
		port:     port,
		dbname:   dbname,
	}
	return dbConfig, nil
}

func CreateGroup(groupName string) error {
	config, err := loadDbConfig()
	if err != nil {
		return fmt.Errorf("unable to load db config: %v", err)
	}

	return createGroup(config, groupName)
}

func DeleteGroup(groupName string) error {
	config, err := loadDbConfig()
	if err != nil {
		return fmt.Errorf("unable to load db config: %v", err)
	}

	return deleteGroup(config, groupName)
}

func CheckGroup(groupName string) (bool, error) {
	config, err := loadDbConfig()
	if err != nil {
		return false, fmt.Errorf("unable to load db config: %v", err)
	}

	return checkGroup(config, groupName)
}

func GrantGroup(groupName string, tableName string) error {
	config, err := loadDbConfig()
	if err != nil {
		return fmt.Errorf("unable to load db config: %v", err)
	}

	return grantGroup(config, groupName, tableName)
}

func checkGroup(config *dbConfig, groupName string) (bool, error) {
	var found bool
	err := performDbAction(config, func(connection *sql.DB) error {
		result, err := connection.Query("SELECT 1 FROM pg_group WHERE groname = $1", groupName)
		found = result.Next()
		result.Close()
		return err
	})
	return found, err
}

func grantGroup(config *dbConfig, groupName string, tableName string) error {
	return performDbAction(config, func(connection *sql.DB) error {
		_, err := connection.Exec(fmt.Sprintf("GRANT SELECT ON TABLE \"%s\" TO GROUP \"%s\"", tableName, groupName))
		return err
	})
}

func createGroup(config *dbConfig, groupName string) error {
	return performDbAction(config, func(connection *sql.DB) error {
		_, err := connection.Exec(fmt.Sprintf("CREATE GROUP \"%s\"", groupName))
		return err
	})
}

func deleteGroup(config *dbConfig, groupName string) error {
	return performDbAction(config, func(connection *sql.DB) error {
		// Won't work if group has privileges.
		_, err := connection.Exec(fmt.Sprintf("DROP GROUP \"%s\"", groupName))
		return err
	})
}

func performDbAction(config *dbConfig, action func(*sql.DB) error) error {
	connection, err := openConnection(config)
	if err != nil {
		return err
	}
	err = action(connection)
	if err != nil {
		connection.Close()
		return err
	} else {
		return connection.Close()
	}
}

func test(config *dbConfig) (string, error) {
	db, err := openConnection(config)
	if err != nil {
		return "", fmt.Errorf("unable to open db connection: %v", err)
	}
	stmt, err := db.Prepare("SELECT * FROM test LIMIT 10")
	if err != nil {
		return "", fmt.Errorf("unable to prepare stmt: %v", err)
	}
	result, err := stmt.Query()
	if err != nil {
		return "", fmt.Errorf("unable to execute stmt: %v", err)
	}
	var text string
	if result.Next() {
		err = result.Scan(&text)
		if err != nil {
			return "", fmt.Errorf("unable to execute stmt: %v", err)
		} else {
			return text, nil
		}
	} else {
		return "", nil
	}
}

func openConnection(config *dbConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s", config.user, config.password, config.host, config.port, config.dbname))
	return db, err
}

type GetClusterCredentialsInput struct {
	Creds       *credentials.Credentials
	ClusterName *string
	DbGroup     *string
	DbName      *string
	DbUser      *string
	Region		*string
}

func GetClusterCredentials(input *GetClusterCredentialsInput) (*redshift.GetClusterCredentialsOutput, error) {

	sess, err := common.Session()
	if err != nil {
		return nil, err
	}
	rsSvc := redshift.New(sess, sess.Config.WithCredentials(input.Creds).WithRegion(*input.Region))
	gcco, err := rsSvc.GetClusterCredentials(&redshift.GetClusterCredentialsInput{
		AutoCreate:        aws.Bool(true),
		ClusterIdentifier: input.ClusterName,
		DbGroups:          []*string{input.DbGroup},
		DbName:            input.DbName,
		DbUser:            input.DbUser,
	})
	if err != nil {
		return nil, err
	}

	return gcco, nil
}

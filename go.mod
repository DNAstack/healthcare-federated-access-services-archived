module github.com/GoogleCloudPlatform/healthcare-federated-access-services

go 1.13

require (
	cloud.google.com/go v0.44.3
	cloud.google.com/go/bigquery v1.0.1 // indirect
	cloud.google.com/go/datastore v1.0.0
	github.com/aws/aws-sdk-go v1.25.24
	github.com/cenkalti/backoff v2.1.1+incompatible
	github.com/coreos/go-oidc v2.0.0+incompatible
	github.com/coreos/go-systemd v0.0.0-20190719114852-fd7a80b32e1f // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-openapi/strfmt v0.19.3
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/mock v1.3.1
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.3.1
	github.com/gorilla/mux v1.7.0
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/jackc/pgx/v4 v4.1.2
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/kr/pty v1.1.8 // indirect
	github.com/lib/pq v1.2.0
	github.com/pborman/uuid v1.2.0
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	go.mongodb.org/mongo-driver v1.1.3 // indirect
	golang.org/x/crypto v0.0.0-20190911031432-227b76d455e7
	golang.org/x/exp v0.0.0-20190731235908-ec7cb31e5a56 // indirect
	golang.org/x/net v0.0.0-20190827160401-ba9fcec4b297 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/tools v0.0.0-20190827205025-b29f5f60c37a // indirect
	google.golang.org/api v0.9.0
	google.golang.org/genproto v0.0.0-20190819201941-24fa4b261c55
	google.golang.org/grpc v1.23.0
	gopkg.in/square/go-jose.v2 v2.3.1
	honnef.co/go/tools v0.0.1-2019.2.2 // indirect
)

replace git.apache.org/thrift.git => github.com/apache/thrift v0.0.0-20180902110319-2566ecd5d999

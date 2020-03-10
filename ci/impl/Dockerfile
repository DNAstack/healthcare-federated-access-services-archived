# This is a two stage build, as described in the Docker docs: https://docs.docker.com/develop/develop-images/multistage-build/

##
## Stage 1: Build and test the Java Sources
##

# This stage depends on a JDK image and uses Maven Wrapper to pull in dependencies and build the project
# from source.
FROM golang:1.12-stretch AS build
ARG APP_NAME
ARG APP_VERSION

WORKDIR /build

# Now add sources, which will bust the cache.
ADD target/ ./
# Build a binaries
RUN CGO_ENABLED=0 GOOS=linux GOPATH=$(pwd)/gcp go build -a -o gcp/dam/main gcp/dam/main.go
RUN CGO_ENABLED=0 GOOS=linux GOPATH=$(pwd)/gcp go build -a -o gcp/ic/main gcp/ic/main.go
RUN CGO_ENABLED=0 GOOS=linux GOPATH=$(pwd)/gcp go build -a -o gcp/personas/main gcp/personas/main.go

##
## Stage 2: Package the runnable image
##

FROM golang:1.12-alpine
ARG APP_NAME
ARG APP_VERSION

COPY --from=0 /build/gcp/dam/main /go/dam-main
COPY --from=0 /build/gcp/ic/main /go/ic-main
COPY --from=0 /build/gcp/personas/main /go/playground-idp-main
# Config must be mounted into these folders at runtime
RUN mkdir -p /go/config/dam /go/config/ic
COPY --from=0 /build/deploy/config/dam-static /go/config/dam-static
COPY --from=0 /build/assets /go/assets/
COPY --from=0 /build/pages /go/pages/
EXPOSE 8080

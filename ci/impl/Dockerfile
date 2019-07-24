# This is a two stage build, as described in the Docker docs: https://docs.docker.com/develop/develop-images/multistage-build/

##
## Stage 1: Build and test the Java Sources
##

# This stage depends on a JDK image and uses Maven Wrapper to pull in dependencies and build the project
# from source.
FROM golang:1.12-alpine AS build
ARG APP_NAME
ARG APP_VERSION

WORKDIR /build

# Now add sources, which will bust the cache.
ADD target/ ./
# Build a binaries
RUN CGO_ENABLED=0 GOOS=linux GOPATH=$(pwd)/gcp go build -a -o gcp/dam/main gcp/dam/main.go
RUN CGO_ENABLED=0 GOOS=linux GOPATH=$(pwd)/gcp go build -a -o gcp/ic/main gcp/ic/main.go

##
## Stage 2: Package the runnable image
##

FROM golang:1.12-alpine
ARG APP_NAME
ARG APP_VERSION

COPY --from=0 /build/gcp/dam/main /dam
COPY --from=0 /build/gcp/ic/main /ic
EXPOSE 8080

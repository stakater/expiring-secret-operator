# Build the manager binary
FROM golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH

ARG GIT_TOKEN
ARG GIT_USER
ENV CGO_ENABLED=0 GO111MODULE=on GOOS=linux TOKEN=$GIT_TOKEN

RUN go env -w GOPRIVATE=github.com/$GIT_USER/*
# Using ssh instead of oauth2/x-oauth-basic locally, so we don't have have to care about token
RUN git config --global url."ssh://git@github.com".insteadOf "https://github.com" && \
    mkdir -p -m 0600 /root/.ssh && \
    ssh-keyscan github.com > /root/.ssh/known_hosts && \
    touch /root/.ssh/config && \
    echo "StrictHostKeyChecking no" >> /root/.ssh/config && \
    chmod 600 /root/.ssh/known_hosts && \
    chmod 644 /root/.ssh/config

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN --mount=type=ssh,id=default go mod download

RUN rm -rf /root/.ssh

# Copy the go source
COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY internal/ internal/

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager cmd/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]

# Build the manager binary
FROM golang:1.16 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY ../../go.mod go.mod
COPY ../../go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN GOPROXY="https://goproxy.cn/,direct" go mod download

# Copy the go source
COPY cmd/addon-agent/main.go main.go
COPY ../../pkg pkg/
COPY ../../controllers controllers/

# Build
RUN GOPROXY="https://goproxy.cn/,direct" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o agent main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM alpine:3.13

WORKDIR /
COPY --from=builder /workspace/agent .
USER 65532:65532

ENTRYPOINT ["/agent"]

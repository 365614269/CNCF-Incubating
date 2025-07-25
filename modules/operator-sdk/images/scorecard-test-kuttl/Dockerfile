# Build the scorecard-test-kuttl binary
FROM --platform=$BUILDPLATFORM golang:1.24 AS builder
ARG TARGETARCH
ARG BUILDPLATFORM

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY . .

# Build
RUN GOOS=linux GOARCH=$TARGETARCH make build/scorecard-test-kuttl

# Final image.
#FROM kudobuilder/kuttl@sha256:8d4dad161521450db95f88fe0e62487cc6587c5818df2a4e750fb9e54c082170
FROM kudobuilder/kuttl:v0.15.0

ENV HOME=/opt/scorecard-test-kuttl \
    USER_NAME=scorecard-test-kuttl \
    USER_UID=1001 \
    KUBECONFIG=

RUN echo "${USER_NAME}:x:${USER_UID}:0:${USER_NAME} user:${HOME}:/sbin/nologin" >> /etc/passwd

WORKDIR ${HOME}
# kuttl writes a kubeconfig file in the current working directory
RUN chmod g+w "${HOME}"

COPY --from=builder /workspace/build/scorecard-test-kuttl /usr/local/bin/scorecard-test-kuttl
COPY --from=builder /workspace/images/scorecard-test-kuttl/entrypoint /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}

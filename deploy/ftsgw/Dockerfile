# syntax=docker/dockerfile:1.7

# Builder stage. We build with -mod=vendor so the image build does not need
# network access; the vendor tree is committed.
FROM golang:1.25-alpine AS builder
ENV CGO_ENABLED=0 GOFLAGS=-mod=vendor
WORKDIR /src
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/ftsgw-server ./ftsgw/cmd/ftsgw-server

# Runtime stage. Distroless static, non-root, all caps dropped.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/ftsgw-server /usr/local/bin/ftsgw-server
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/ftsgw-server"]

FROM golang:1.25-alpine AS build-env

WORKDIR /build

ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux

RUN apk --no-cache add ca-certificates git=~2

COPY main.go go.mod go.sum /build/

RUN go version
RUN go build

FROM alpine:3

COPY --from=build-env /build/traefik-cert-watcher /traefik-cert-watcher

HEALTHCHECK --interval=5s --timeout=3s \
    CMD ps aux | grep 'traefik-cert-watcher' || exit 1

VOLUME /certs

ENTRYPOINT ["/traefik-cert-watcher"]
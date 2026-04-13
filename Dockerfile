# syntax=docker/dockerfile:1.2
FROM alpine:3.24

RUN apk add --no-cache --no-progress ca-certificates tzdata

ARG TARGETPLATFORM
COPY ./dist/$TARGETPLATFORM/traefik /
COPY ./dist/$TARGETPLATFORM/ech /usr/local/bin/ech

EXPOSE 80
VOLUME ["/tmp"]

ENTRYPOINT ["/traefik"]

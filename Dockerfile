FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agent-gateway ./cmd/agent-gateway

FROM alpine:3.23
RUN apk add --no-cache ca-certificates su-exec && addgroup -S gateway && adduser -S -G gateway gateway
WORKDIR /app
COPY --from=build /out/agent-gateway /usr/local/bin/agent-gateway
COPY --chmod=0755 deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN mkdir -p /app/data/spool && chown -R gateway:gateway /app
EXPOSE 11945
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["agent-gateway"]

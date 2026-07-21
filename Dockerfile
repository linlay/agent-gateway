FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agent-gateway ./cmd/agent-gateway

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -S gateway && adduser -S -G gateway gateway
WORKDIR /app
COPY --from=build /out/agent-gateway /usr/local/bin/agent-gateway
RUN mkdir -p /app/data/spool && chown -R gateway:gateway /app
USER gateway
EXPOSE 11945
ENTRYPOINT ["agent-gateway"]

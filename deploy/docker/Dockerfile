FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /waf-api ./cmd/waf-api

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata curl
COPY --from=builder /waf-api /usr/local/bin/waf-api

USER 1000:1000
EXPOSE 9090

ENTRYPOINT ["waf-api"]
CMD ["--config", "/etc/waffynx/waffynx.yaml"]

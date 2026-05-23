# Multi-stage build for the antibot-backend Go service (B2). Drops into the
# B1 substrate topology: same :8080 listen, same /health JSON contract.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' \
    -o /out/antibot-backend ./cmd/antibot-backend

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/antibot-backend /antibot-backend
EXPOSE 8080
ENTRYPOINT ["/antibot-backend"]

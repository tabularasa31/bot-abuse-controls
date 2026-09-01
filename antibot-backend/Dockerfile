# Multi-stage build for the antibot-backend Go service (B2). Drops into the
# B1 substrate topology: same :8080 listen, same /health JSON contract.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' \
    -o /out/antibot-backend ./cmd/antibot-backend

# The B9 log spool — an empty directory is COPYed with chown=nonroot into the final
# image, so that a docker named volume mounted over it inherits the owner
# (nonroot uid 65532). Without that, MkdirAll on a freshly created root-owned 0755
# volume would return nil while the very first spill-file write failed with
# EACCES at runtime (from code review).
RUN mkdir -p /spool

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/antibot-backend /antibot-backend
COPY --from=build --chown=nonroot:nonroot /spool /var/lib/antibot-backend/log-spool
EXPOSE 8080
ENTRYPOINT ["/antibot-backend"]

# Multi-stage build for the antibot-backend Go service (B2). Drops into the
# B1 substrate topology: same :8080 listen, same /health JSON contract.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' \
    -o /out/antibot-backend ./cmd/antibot-backend

# B9 log-spool — пустой каталог COPY'ируется с chown=nonroot в финальный
# образ, чтобы docker named volume, монтируемый поверх, унаследовал владельца
# (nonroot uid 65532). Без этого MkdirAll на свежесозданном root-owned 0755
# volume'е возвращал бы nil, а первая же запись spill-файла падала бы с
# EACCES в рантайме (code-review #56).
RUN mkdir -p /spool

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/antibot-backend /antibot-backend
COPY --from=build --chown=nonroot:nonroot /spool /var/lib/antibot-backend/log-spool
EXPOSE 8080
ENTRYPOINT ["/antibot-backend"]

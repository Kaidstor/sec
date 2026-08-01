FROM golang:1.26-alpine AS build
WORKDIR /src
ARG VERSION=dev
# копируем контекст целиком (см. .dockerignore): перечисление файлов поимённо
# ломало сборку каждый раз, когда появлялся новый go:embed-ресурс
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /sec-share .

# alpine, не scratch: шелл нужен для `docker exec … token add` и отладки
FROM alpine:3.22
RUN adduser -D -H -u 10001 secshare
COPY --from=build /sec-share /usr/local/bin/sec-share
# бинд-маунт ./data должен принадлежать uid 10001 — deploy.sh делает chown
USER secshare
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sec-share"]
CMD ["serve"]

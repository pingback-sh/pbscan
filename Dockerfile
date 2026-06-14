FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/pingback-sh/pbscan/internal/app.Version=${VERSION} -X github.com/pingback-sh/pbscan/internal/app.Commit=${COMMIT} -X github.com/pingback-sh/pbscan/internal/app.Date=${DATE}" \
    -o /out/pbscan ./cmd/pbscan

FROM alpine:3.21
RUN addgroup -S pbscan && adduser -S -G pbscan pbscan \
    && apk add --no-cache ca-certificates
COPY --from=build /out/pbscan /usr/local/bin/pbscan
USER pbscan
WORKDIR /work
ENTRYPOINT ["pbscan"]
CMD ["help"]

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/cassd ./cmd/cassd

FROM alpine:3.22

RUN addgroup -S cass && adduser -S -G cass -u 10001 cass
WORKDIR /app
COPY --from=build /out/cassd /usr/local/bin/cassd
USER cass
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/cassd"]

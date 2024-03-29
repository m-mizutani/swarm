FROM golang:1.22 AS build-go
ENV CGO_ENABLED=0
ARG BUILD_VERSION
COPY . /app
WORKDIR /app
RUN go build -o swarm -ldflags "-X github.com/m-mizutani/swarm/pkg/domain/types.AppVersion=${BUILD_VERSION}" .

FROM gcr.io/distroless/base:nonroot
USER nonroot
COPY --from=build-go /app/swarm /swarm

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD [ "/swarm", "client", "health" ]

ENTRYPOINT ["/swarm"]

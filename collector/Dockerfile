FROM golang:alpine3.23 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY ingest.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ingest .

FROM golang:alpine3.23

RUN apk add --no-cache bash ca-certificates

WORKDIR /app
COPY --from=builder /out/ingest ./ingest
COPY --chown=65532:65532 run.sh ./run.sh
COPY --chown=65532:65532 bin/ ./bin/
COPY --chown=65532:65532 db/ ./db/

USER 65532:65532
EXPOSE 2055/udp
ENTRYPOINT ["./run.sh"]

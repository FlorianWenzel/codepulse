# Build CodePulse binaries. CGo is required for the tree-sitter grammars.
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=1
RUN go build -o /out/codepulse-server ./cmd/codepulse-server \
 && go build -o /out/codepulse-scan ./cmd/codepulse-scan

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/codepulse-server /usr/local/bin/codepulse-server
COPY --from=build /out/codepulse-scan /usr/local/bin/codepulse-scan
EXPOSE 8080
ENTRYPOINT ["codepulse-server"]

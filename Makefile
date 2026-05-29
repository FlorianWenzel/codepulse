.PHONY: build test vet scan clean

# Build the scanner CLI.
build:
	go build -o bin/codepulse-server ./cmd/codepulse-server
	go build -o bin/codepulse-scan ./cmd/codepulse-scan

# Run the full test suite (unit + e2e).
test:
	go test ./...

vet:
	go vet ./...

# Dogfood: scan our own source.
scan: build
	./bin/codepulse-scan ./internal

clean:
	rm -rf bin

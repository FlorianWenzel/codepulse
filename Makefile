.PHONY: build test vet scan rules-catalog clean

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

# Regenerate the rule catalogue reference doc from the built-in rules.
rules-catalog: build
	./bin/codepulse-scan -rules | python3 scripts/gen_rules_catalog.py > docs/RULES_CATALOG.md

clean:
	rm -rf bin

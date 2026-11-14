BIN := prowl
PKGS := ./internal/... ./cmd/...   # explicit: avoids transient corpus_* dirs at module root
FUZZTIME ?= 10s

.PHONY: build test race bench vet fmt-check fuzz install docker clean e2e ci

build:
	go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/prowl

test:
	go test $(PKGS)

race:
	go test -race $(PKGS)

bench:
	go test ./internal/detect/ -bench . -benchmem -run '^$$'

vet:
	go vet $(PKGS)

fmt-check:
	@test -z "$$(gofmt -l internal cmd)" || { gofmt -l internal cmd; exit 1; }

fuzz: ## short fuzz smoke across every target
	@set -eu; \
	packages=$$(go list $(PKGS)); \
	for pkg in $$packages; do \
		listing=$$(go test "$$pkg" -list '^Fuzz'); \
		targets=$$(printf '%s\n' "$$listing" | sed -n '/^Fuzz[A-Za-z0-9_]*$$/p'); \
		for target in $$targets; do \
			go test "$$pkg" -run '^$$' -fuzz "^$$target\$$" -fuzztime $(FUZZTIME); \
		done; \
	done

ci: fmt-check vet build race e2e ## the full local gate

install:
	go install ./cmd/prowl

docker:
	docker build -t prowl .

clean:
	rm -f $(BIN) *.prof *.sarif

e2e: ## run end-to-end scenario tests
	bash test/e2e.sh

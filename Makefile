SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

default: build

build: checks
	cd v5 && go install .

generate:
	cd v5 && ../script/generate

regenerate:
	cd v5 && ../script/generate -n

checks: fmt-check

fmt-check:
	@test -z "$(shell gofmt -l $(SRC) | tee /dev/stderr)" || echo "[WARN] Fix formatting issues in with 'make fmt'"

.PHONY: build checks fmt-check generate

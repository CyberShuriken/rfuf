build: preflight
	set -e
	GOTOOLCHAIN=local go build -o bin/rfuf ./cmd/rfuf
	GOTOOLCHAIN=local go build -o bin/findings-runner ./cmd/findings-runner
	GOTOOLCHAIN=local go build -o bin/filter-testable ./cmd/filter-testable

install: preflight
	GOTOOLCHAIN=local go install ./cmd/rfuf

fmt:
	find . -type f -name '*.go' -not -path './.git/*' -print0 | xargs -0 gofmt -w

fmtcheck:
	@test -z "$$(gofmt -l $$(find . -type f -name '*.go' -not -path './.git/*'))" || { gofmt -l $$(find . -type f -name '*.go' -not -path './.git/*'); exit 1; }

preflight:
	@test -d .git -a -f go.mod -a -f cmd/rfuf/main.go -a -f cmd/findings-runner/main.go -a -f cmd/filter-testable/main.go -a -d nuclei-templates-rfuf || { echo 'incomplete RFUF checkout: require .git, go.mod, command wrappers, and nuclei templates' >&2; exit 1; }
	@test -w . || { echo 'repository directory is not writable' >&2; exit 1; }

test:
	GOTOOLCHAIN=local go test ./...

vet:
	GOTOOLCHAIN=local go vet ./...

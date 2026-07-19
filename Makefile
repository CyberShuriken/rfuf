build:
	go build -o bin/rfuf ./cmd/rfuf

install:
	go install ./cmd/rfuf

fmt:
	gofmt -w .

test:
	go test ./...

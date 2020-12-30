.PHONY: default test test-cover dev


# for test
test:
	go test -race -cover ./...

test-cover:
	go test -race -coverprofile=test.out ./... && go tool cover --html=test.out
lint:
	golangci-lint run

hooks:
	cp hooks/* .git/hooks/
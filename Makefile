progs= nestedaes

all: $(progs)

$(progs):
	go build ./cmd/$@

fmt:
	go fmt ./...

vet:
	go vet ./...

# -count=1 forces tests to always run, even if no code has changed
test:
	go test -v -vet=all -count=1 ./...

clean:
	rm -f $(progs)

.PHONY: $(progs) all fmt vet test clean

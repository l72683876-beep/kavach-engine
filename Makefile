.PHONY: build vet test full demo clean

build:
	cd engine && go build -o kavach .

vet:
	cd engine && go vet ./...

test: build
	bash scripts/test.sh

full: build
	bash scripts/test.sh --full

demo: build
	bash scripts/demo.sh

clean:
	rm -f engine/kavach

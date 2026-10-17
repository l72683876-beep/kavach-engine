.PHONY: build vet test full demo demo-stop clean

build:
	cd engine && go build -o kavach .

vet:
	cd engine && go vet ./...

test: build
	bash scripts/test.sh

full: build
	bash scripts/test.sh --full

# One command, any machine: builds the engine, boots it (20k seats),
# boots the demo app sized to this machine's cores, and opens the app.
demo: build
	bash scripts/demo.sh

demo-stop:
	pkill -f "kavach -seats" 2>/dev/null; pkill -f gunicorn 2>/dev/null; true

clean:
	rm -f engine/kavach

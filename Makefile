.PHONY: all build-agent run-backend test-integrity docker-up clean

all: build-agent docker-up

build-agent:
	@chmod +x scripts/build.sh
	@./scripts/build.sh

docker-up:
	docker compose up -d --build

test-integrity:
	./dist/aegis-agent-linux-x64 --verify

clean:
	rm -rf dist/
	docker compose down

.PHONY: build test-launch test-audit test-discovery test-file-access test-workspace test-network

build:
	cargo run -- build-image

test-launch:
	./scripts/test-launch.sh

test-audit:
	./scripts/test-audit.sh

test-discovery:
	./scripts/test-discovery.sh

test-file-access:
	./scripts/test-file-access.sh

test-workspace:
	./scripts/test-workspace.sh

test-network:
	./scripts/test-network.sh

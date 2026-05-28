.PHONY: install build test type-check lint verify-bundle clean

## install: install web dependencies
install:
	bun install

## build: build the SPA for production (no source maps)
build:
	bun run build
	@$(MAKE) verify-bundle

## test: run vitest unit tests
test:
	bun run test

## type-check: TypeScript type check
type-check:
	bun run type-check

## verify-bundle: check that dist exists and has no .map files
verify-bundle:
	@bash scripts/verify-bundle.sh

## clean: remove dist directory
clean:
	rm -rf dist

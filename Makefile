include .env
export

.PHONY: help
help: ## display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: aqua
aqua: ## Put the path in your environment variables. ex) export PATH="${AQUA_ROOT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/aquaproj-aqua}/bin:$PATH"
	@go run github.com/aquaproj/aqua-installer@latest --aqua-version v2.0.0

.PHONY: tool
tool: ## Install tool.
	@aqua i

.PHONY: gen
gen: ## Generate code.
	@oapi-codegen -generate types -package api ./api/openapi.yaml > ./internal/api/types.gen.go
	@oapi-codegen -generate server -package api ./api/openapi.yaml > ./internal/api/server.gen.go
	@oapi-codegen -generate client -package api ./api/openapi.yaml > ./internal/api/client.gen.go
	@go mod tidy

.PHONY: dev
dev: ## Make development.
	@docker compose --project-name ${APP_NAME} --file ./.docker/docker-compose.yaml up -d

.PHONY: redev
redev: ## Restart dev container
	@touch cmd/app/main.go

.PHONY: down
down: ## Down development. (retain containers and delete volumes.)
	@docker compose --project-name ${APP_NAME} down --volumes

.PHONY: balus
balus: ## Destroy everything about docker. (containers, images, volumes, networks.)
	@docker compose --project-name ${APP_NAME} down --rmi all --volumes

.PHONY: test
test: ## Run test.
	@go test -v ./test/...

# Ryzan Makefile for Docker operations

.PHONY: help build run start stop restart logs shell clean dev

# Default target
help: ## Show this help message
	@echo "Ryzan Docker Management"
	@echo ""
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the Docker image
	docker build -t ryzan:latest .

run: ## Run ryzan interactively
	docker run -it --rm -v ryzan_config:/home/ryzan/.config/ryzan ryzan:latest

start: ## Start with docker-compose
	docker compose up -d

stop: ## Stop docker-compose
	docker compose down

restart: ## Restart docker-compose
	docker compose down && docker compose up -d

logs: ## Show docker-compose logs
	docker compose logs -f

shell: ## Access container shell
	docker compose exec ryzan bash

clean: ## Clean up Docker resources
	docker compose down -v
	docker rmi ryzan:latest 2>/dev/null || true
	docker system prune -f

dev: ## Start development environment
	docker compose -f docker-compose.dev.yml up --build

# Quick commands
create: ## Create a new wallet (interactive)
	docker compose exec ryzan ryzan create --name $(or $(name),mywallet)

balance: ## Check wallet balance
	docker compose exec ryzan ryzan balance --name $(or $(name),mywallet) --totp $(totp)

send: ## Send SOL (requires name, address, amount, totp)
	docker compose exec ryzan ryzan send $(address) $(amount) --totp $(totp)

# Example usage:
# make create name=mywallet
# make balance name=mywallet totp=123456
# make send address=ABC123 amount=0.1 totp=123456 
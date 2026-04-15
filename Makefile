# FlexEdgeAdmin — Convenience Makefile
#
# Usage: make <target>

COMPOSE_BASE = docker compose -f docker/docker-compose.yml
COMPOSE_PROD = $(COMPOSE_BASE) -f docker/docker-compose.prod.yml

.PHONY: dev prod dev-raw prod-raw stop logs restart build cli setup update

# Development: guided bootstrap (Docker check, .env setup, Azure AD prompt),
#              then build + run foreground on port 5000 with live logs.
dev:
	@./deploy.sh --dev

# Production: guided bootstrap, then build + run detached with nginx + TLS.
prod:
	@./deploy.sh

# Raw docker compose start (skips bootstrap — requires .env already present)
dev-raw:
	$(COMPOSE_BASE) up --build

prod-raw:
	$(COMPOSE_PROD) up -d --build

# Stop all services
stop:
	$(COMPOSE_BASE) down 2>/dev/null; $(COMPOSE_PROD) down 2>/dev/null; true

# Follow logs
logs:
	$(COMPOSE_BASE) logs -f

# Restart services
restart:
	$(COMPOSE_BASE) restart

# Rebuild without starting
build:
	$(COMPOSE_BASE) build

# Run CLI command inside the container
# Usage: make cli CMD="--tenant prod connect"
cli:
	$(COMPOSE_BASE) exec flexedge-web python /app/cli/connect.py $(CMD)

# First-time setup: create config files from templates
setup:
	@./deploy.sh --no-tls

# Update: pull latest and rebuild
update:
	@./deploy.sh --update

# =============================================================================
# Azure API Platform — Makefile
# =============================================================================
# Usage:
#   make help          Show all available targets
#   make setup         Install dependencies and set up local environment
#   make test          Run all unit tests
#   make lint          Run linter and formatter checks
#   make validate      Validate Terraform configuration
#   make plan          Run Terraform plan for an environment
#   make apply         Apply Terraform changes for an environment
#   make all           Run full CI pipeline (lint + test + validate)
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# --- Configuration -----------------------------------------------------------
PYTHON         := python3
PIP            := pip3
VENV_DIR       := .venv
FUNC_DIR       := src/functions
TERRAFORM_DIR  := terraform
ENV            ?= dev

# Activate venv for recipe commands
VENV_ACTIVATE  := source $(VENV_DIR)/bin/activate &&

# --- Colors ------------------------------------------------------------------
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
NC     := \033[0m  # No Color

# =============================================================================
# Help
# =============================================================================
.PHONY: help
help: ## Show this help message
	@echo ""
	@echo "Azure API Platform — Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "Environment variable overrides:"
	@echo "  ENV=dev|stage|prod   Target environment (default: dev)"
	@echo ""

# =============================================================================
# Setup & Dependencies
# =============================================================================
.PHONY: setup
setup: venv install ## Set up local dev environment (venv + dependencies)
	@echo "$(GREEN)✅ Setup complete. Activate venv: source $(VENV_DIR)/bin/activate$(NC)"

.PHONY: venv
venv: ## Create Python virtual environment
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "$(YELLOW)Creating virtual environment...$(NC)"; \
		$(PYTHON) -m venv $(VENV_DIR); \
	else \
		echo "Virtual environment already exists."; \
	fi

.PHONY: install
install: venv ## Install Python dependencies (prod + dev)
	@echo "$(YELLOW)Installing dependencies...$(NC)"
	$(VENV_ACTIVATE) $(PIP) install --upgrade pip
	$(VENV_ACTIVATE) $(PIP) install -r $(FUNC_DIR)/requirements-dev.txt

# =============================================================================
# Testing
# =============================================================================
.PHONY: test
test: ## Run all unit tests
	@echo "$(YELLOW)Running unit tests...$(NC)"
	$(VENV_ACTIVATE) cd $(FUNC_DIR) && $(PYTHON) -m pytest -m unit --tb=short -v

.PHONY: test-cov
test-cov: ## Run unit tests with coverage report
	@echo "$(YELLOW)Running tests with coverage...$(NC)"
	$(VENV_ACTIVATE) cd $(FUNC_DIR) && $(PYTHON) -m pytest -m unit \
		--cov=blueprints --cov=shared \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--tb=short -v
	@echo "$(GREEN)Coverage report: $(FUNC_DIR)/htmlcov/index.html$(NC)"

.PHONY: test-all
test-all: ## Run all tests (unit + integration)
	@echo "$(YELLOW)Running all tests...$(NC)"
	$(VENV_ACTIVATE) cd $(FUNC_DIR) && $(PYTHON) -m pytest --tb=short -v

.PHONY: test-integration
test-integration: ## Run integration tests only (requires Azure resources)
	@echo "$(YELLOW)Running integration tests...$(NC)"
	$(VENV_ACTIVATE) cd $(FUNC_DIR) && $(PYTHON) -m pytest -m integration --tb=short -v

# =============================================================================
# Linting & Formatting
# =============================================================================
.PHONY: lint
lint: ## Run ruff linter checks
	@echo "$(YELLOW)Running linter...$(NC)"
	$(VENV_ACTIVATE) ruff check $(FUNC_DIR)
	@echo "$(GREEN)✅ Lint passed$(NC)"

.PHONY: lint-fix
lint-fix: ## Auto-fix linting issues
	@echo "$(YELLOW)Auto-fixing lint issues...$(NC)"
	$(VENV_ACTIVATE) ruff check --fix $(FUNC_DIR)
	$(VENV_ACTIVATE) ruff format $(FUNC_DIR)

.PHONY: format
format: ## Format Python code with ruff
	@echo "$(YELLOW)Formatting code...$(NC)"
	$(VENV_ACTIVATE) ruff format $(FUNC_DIR)

.PHONY: format-check
format-check: ## Check formatting without modifying files
	$(VENV_ACTIVATE) ruff format --check $(FUNC_DIR)

.PHONY: typecheck
typecheck: ## Run mypy type checking
	@echo "$(YELLOW)Running type checker...$(NC)"
	$(VENV_ACTIVATE) mypy $(FUNC_DIR) --ignore-missing-imports
	@echo "$(GREEN)✅ Type check passed$(NC)"

# =============================================================================
# Terraform
# =============================================================================
.PHONY: tf-init
tf-init: ## Initialize Terraform (downloads providers, configures backend)
	@echo "$(YELLOW)Initializing Terraform...$(NC)"
	cd $(TERRAFORM_DIR) && terraform init

.PHONY: tf-validate
tf-validate: tf-init ## Validate Terraform configuration
	@echo "$(YELLOW)Validating Terraform...$(NC)"
	cd $(TERRAFORM_DIR) && terraform validate
	@echo "$(GREEN)✅ Terraform validation passed$(NC)"

.PHONY: tf-fmt
tf-fmt: ## Check Terraform formatting
	@echo "$(YELLOW)Checking Terraform formatting...$(NC)"
	cd $(TERRAFORM_DIR) && terraform fmt -check -recursive
	@echo "$(GREEN)✅ Terraform format check passed$(NC)"

.PHONY: tf-fmt-fix
tf-fmt-fix: ## Auto-format Terraform files
	cd $(TERRAFORM_DIR) && terraform fmt -recursive

.PHONY: plan
plan: tf-init ## Run Terraform plan (ENV=dev|stage|prod)
	@echo "$(YELLOW)Planning for environment: $(ENV)$(NC)"
	cd $(TERRAFORM_DIR) && terraform plan \
		-var-file=environments/$(ENV).tfvars \
		-out=tfplan-$(ENV)
	@echo "$(GREEN)✅ Plan saved to $(TERRAFORM_DIR)/tfplan-$(ENV)$(NC)"

.PHONY: apply
apply: ## Apply Terraform plan (ENV=dev|stage|prod)
	@echo "$(RED)⚠️  Applying changes to: $(ENV)$(NC)"
	@read -p "Are you sure? (y/N): " confirm && [ "$$confirm" = "y" ] || exit 1
	cd $(TERRAFORM_DIR) && terraform apply tfplan-$(ENV)

.PHONY: destroy
destroy: ## Destroy Terraform resources (ENV=dev|stage|prod) — USE WITH CAUTION
	@echo "$(RED)⚠️  DESTROYING all resources in: $(ENV)$(NC)"
	@read -p "Type the environment name to confirm: " confirm && [ "$$confirm" = "$(ENV)" ] || exit 1
	cd $(TERRAFORM_DIR) && terraform destroy \
		-var-file=environments/$(ENV).tfvars

.PHONY: tf-output
tf-output: ## Show Terraform outputs
	cd $(TERRAFORM_DIR) && terraform output

# =============================================================================
# Azure Functions (Local Dev)
# =============================================================================
.PHONY: func-start
func-start: ## Start Azure Functions locally
	@echo "$(YELLOW)Starting Azure Functions locally...$(NC)"
	cd $(FUNC_DIR) && func start

.PHONY: func-deploy
func-deploy: ## Deploy Function App to Azure (requires FUNC_APP_NAME)
	@if [ -z "$(FUNC_APP_NAME)" ]; then \
		echo "$(RED)Error: FUNC_APP_NAME is required. Usage: make func-deploy FUNC_APP_NAME=func-apiplatform-dev$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Deploying to $(FUNC_APP_NAME)...$(NC)"
	cd $(FUNC_DIR) && func azure functionapp publish $(FUNC_APP_NAME)

# =============================================================================
# Bootstrap & Setup Scripts
# =============================================================================
.PHONY: bootstrap
bootstrap: ## Bootstrap Terraform remote backend (run once)
	@echo "$(YELLOW)Bootstrapping Terraform backend...$(NC)"
	chmod +x scripts/bootstrap_backend.sh
	./scripts/bootstrap_backend.sh

.PHONY: create-sp
create-sp: ## Create Service Principal and App Registration
	@echo "$(YELLOW)Creating Service Principal...$(NC)"
	chmod +x scripts/create_service_principal.sh
	./scripts/create_service_principal.sh

# =============================================================================
# CI Pipeline Targets
# =============================================================================
.PHONY: ci
ci: lint format-check test tf-validate ## Run full CI checks (lint + format + test + terraform validate)
	@echo "$(GREEN)✅ All CI checks passed$(NC)"

.PHONY: all
all: ci ## Alias for ci

.PHONY: presubmit
presubmit: lint-fix format test-cov tf-validate tf-fmt ## Full presubmit: fix lint, format, test with coverage, validate TF
	@echo "$(GREEN)✅ Presubmit complete$(NC)"

# =============================================================================
# Cleanup
# =============================================================================
.PHONY: clean
clean: ## Remove generated files and caches
	@echo "$(YELLOW)Cleaning up...$(NC)"
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name htmlcov -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -f $(TERRAFORM_DIR)/tfplan-*
	@echo "$(GREEN)✅ Clean$(NC)"

.PHONY: clean-all
clean-all: clean ## Remove everything including venv
	rm -rf $(VENV_DIR)
	rm -rf $(TERRAFORM_DIR)/.terraform
	@echo "$(GREEN)✅ Full clean$(NC)"

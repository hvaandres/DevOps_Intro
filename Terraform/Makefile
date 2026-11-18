SHELL := /bin/bash
.DEFAULT_GOAL := help
BASE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

RESOURCE_GROUP ?= rg-terraform-state-test
LOCATION ?= eastus2
CONTAINER_NAME ?= tfstate
STATE_KEY ?= test/terraform.tfstate
BACKEND_CONFIG ?= $(BASE_DIR)backend.hcl
PRINCIPAL_TYPE ?= User

export SUBSCRIPTION_ID RESOURCE_GROUP LOCATION STORAGE_ACCOUNT CONTAINER_NAME
export STATE_KEY BACKEND_CONFIG PRINCIPAL_ID PRINCIPAL_TYPE CONFIRM_SUBSCRIPTION

.PHONY: help azure-login azure-subscription azure-permissions backend-create backend-test test
help:
	@printf '%s\n' \
	  'Azure Terraform setup (requires Azure CLI, Bash, Python 3):' \
	  '  azure-login          Log in and select a subscription' \
	  '  azure-subscription   List and select a subscription' \
	  '  azure-permissions    Confirm and grant subscription-wide admin roles' \
	  '  backend-create       Confirm and create/reuse a test state backend' \
	  '  backend-test         Test backend access using a temporary blob' \
	  '  test                 Run offline mocked-CLI regression tests' \
	  '' \
	  'Cloud commands require SUBSCRIPTION_ID; backend commands also need STORAGE_ACCOUNT.' \
	  'Defaults: RESOURCE_GROUP=rg-terraform-state-test LOCATION=eastus2 CONTAINER_NAME=tfstate' \
	  'Optional: PRINCIPAL_ID, PRINCIPAL_TYPE=User|Group|ServicePrincipal' \
	  'For noninteractive confirmation: CONFIRM_SUBSCRIPTION=<exact subscription UUID>'

azure-login azure-subscription azure-permissions backend-create backend-test:
	@bash "$(BASE_DIR)scripts/azure-bootstrap.sh" "$@"

test:
	@python3 -m unittest discover -s "$(BASE_DIR)tests" -v

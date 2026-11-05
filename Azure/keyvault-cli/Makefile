.DEFAULT_GOAL := help
TOOL_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
export TOOL_DIR
export VAULT SECRET SUBSCRIPTION RESOURCE_GROUP INPUT_FILE OUTPUT_FILE REPORT_FILE ONLINE
export AZURE_TENANT_ID AZURE_CLIENT_ID

.PHONY: help setup auth login vaults check secrets get create import update session report doctor Doctor test lint

# Selectors travel through the environment, never through shell interpolation.
# Never pass credential or secret values as Make variables.
help setup auth login vaults check secrets get create import update session report doctor Doctor test lint:
	@if command -v python3 >/dev/null 2>&1; then \
		python3 "$$TOOL_DIR/commands.py" "$@"; \
	else \
		printf '%s\n' 'Python 3 is missing. Install Python 3.10+ (macOS: brew install python), then run make setup.' >&2; \
		exit 1; \
	fi

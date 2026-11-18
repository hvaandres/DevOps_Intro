# Share all Azure setup targets without changing the caller's working directory.
include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))Terraform/Makefile

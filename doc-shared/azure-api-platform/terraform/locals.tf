locals {
  # Naming convention: {resource_prefix}-{project}-{environment}
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = merge(var.tags, {
    project     = var.project_name
    environment = var.environment
    managed_by  = "terraform"
  })
}

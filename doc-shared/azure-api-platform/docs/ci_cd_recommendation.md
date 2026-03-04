# CI/CD Recommendation

## Overview

Two separate pipelines are recommended:
1. **Infrastructure Pipeline** — Terraform plan/apply for Azure resources
2. **Application Pipeline** — Build and deploy Azure Functions code

Both can run on **GitHub Actions** or **Azure DevOps Pipelines**.

## Infrastructure Pipeline (Terraform)

### Stages

1. **Lint & Validate**
   - `terraform fmt -check`
   - `terraform validate`
   - `tflint` (optional)

2. **Plan**
   - `terraform plan -var-file=environments/<env>.tfvars -out=tfplan`
   - Post plan output as a PR comment (for review)

3. **Approval Gate**
   - Manual approval required for `stage` and `prod`
   - Auto-approve for `dev` (optional)

4. **Apply**
   - `terraform apply tfplan`

### Branching Strategy

- `feature/*` branches → PR triggers plan against `dev`
- Merge to `main` → auto-deploy to `dev`
- Tag `v*-stage` → deploy to `stage` (with approval)
- Tag `v*-prod` → deploy to `prod` (with approval)

### GitHub Actions Example

```yaml
name: Terraform
on:
  push:
    branches: [main]
    paths: ['terraform/**']
  pull_request:
    paths: ['terraform/**']

env:
  ARM_CLIENT_ID: ${{ secrets.ARM_CLIENT_ID }}
  ARM_CLIENT_SECRET: ${{ secrets.ARM_CLIENT_SECRET }}
  ARM_SUBSCRIPTION_ID: ${{ secrets.ARM_SUBSCRIPTION_ID }}
  ARM_TENANT_ID: ${{ secrets.ARM_TENANT_ID }}

jobs:
  plan:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: terraform
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init
      - run: terraform plan -var-file=environments/dev.tfvars -out=tfplan
      - uses: actions/upload-artifact@v4
        with:
          name: tfplan
          path: terraform/tfplan

  apply:
    needs: plan
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: dev
    defaults:
      run:
        working-directory: terraform
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - uses: actions/download-artifact@v4
        with:
          name: tfplan
          path: terraform/
      - run: terraform init
      - run: terraform apply tfplan
```

## Application Pipeline (Azure Functions)

### Stages

1. **Test**
   - `pip install -r requirements.txt`
   - `pytest tests/`

2. **Build**
   - Package the function app

3. **Deploy**
   - `func azure functionapp publish <app-name>`
   - Or use the `Azure/functions-action` GitHub Action

### GitHub Actions Example

```yaml
name: Deploy Functions
on:
  push:
    branches: [main]
    paths: ['src/functions/**']

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r src/functions/requirements.txt
      - uses: Azure/functions-action@v1
        with:
          app-name: ${{ secrets.FUNCTION_APP_NAME }}
          package: src/functions
          publish-profile: ${{ secrets.AZURE_FUNCTIONAPP_PUBLISH_PROFILE }}
```

## Secrets Management

Store the following in GitHub Actions secrets (or Azure DevOps variable groups):

- `ARM_CLIENT_ID` — Service Principal client ID
- `ARM_CLIENT_SECRET` — Service Principal secret
- `ARM_SUBSCRIPTION_ID` — Azure subscription ID
- `ARM_TENANT_ID` — Entra ID tenant ID
- `FUNCTION_APP_NAME` — Target function app name
- `AZURE_FUNCTIONAPP_PUBLISH_PROFILE` — Function app publish profile

## Recommendations

- Use **OIDC federation** instead of client secrets for GitHub Actions → Azure auth (more secure, no secret rotation needed)
- Enable **Terraform state locking** via Azure Storage blob lease
- Use **Checkov** or **tfsec** for security scanning in the plan stage
- Consider **Terragrunt** if managing many environments with similar configurations

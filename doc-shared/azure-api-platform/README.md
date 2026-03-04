# Azure API Platform — Multi-Cloud Read-Only Data Sharing

Production-ready Azure-based API platform for secure, scalable, read-only data sharing across multi-cloud environments (AWS, GCP, On-Prem).

## Architecture

- **API Gateway**: Azure API Management (APIM) — rate limiting, JWT validation, subscription keys, request/response policies
- **API Backend**: Azure Functions (Python) — stateless, read-only endpoints with pagination and streaming
- **Identity**: Entra ID (Azure AD) OAuth 2.0 client_credentials flow, Service Principal with least-privilege RBAC
- **Data Layer**: Azure Blob Storage, Data Lake Gen2, Azure SQL, Cosmos DB — all behind private endpoints
- **Networking**: VNet integration, private endpoints, NSGs, no public exposure on data layer
- **Monitoring**: Azure Monitor, Log Analytics, Application Insights

## Folder Structure

```
azure-api-platform/
├── terraform/          # Infrastructure as Code (Terraform)
│   ├── modules/        # Reusable Terraform modules
│   ├── environments/   # Per-environment variable files
│   └── *.tf            # Root module
├── src/functions/      # Azure Functions (Python v2 programming model)
├── policies/apim/      # APIM policy XML files
├── scripts/            # Bootstrap and setup scripts
└── docs/               # Architecture and CI/CD documentation
```

## Prerequisites

- Azure CLI (`az`) authenticated
- Terraform >= 1.5
- Python >= 3.10
- An Azure subscription with Contributor access

## Quick Start

### 1. Bootstrap the Terraform remote backend

```bash
chmod +x scripts/bootstrap_backend.sh
./scripts/bootstrap_backend.sh
```

### 2. Create the Service Principal

```bash
chmod +x scripts/create_service_principal.sh
./scripts/create_service_principal.sh
```

### 3. Deploy infrastructure

```bash
cd terraform
terraform init
terraform plan -var-file=environments/dev.tfvars -out=tfplan
terraform apply tfplan
```

### 4. Deploy the Function App

```bash
cd src/functions
func azure functionapp publish <function-app-name>
```

## Environment Promotion

Use the corresponding `.tfvars` file for each environment:

```bash
terraform plan -var-file=environments/stage.tfvars
terraform plan -var-file=environments/prod.tfvars
```

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Gateway | APIM subscription keys + JWT validation |
| Auth | Entra ID OAuth 2.0 client_credentials |
| Network | VNet, private endpoints, NSGs |
| Data | Read-only RBAC (Storage Blob Data Reader, Cosmos DB Account Reader, SQL DB Reader) |
| API | APIM policy rejects non-GET/HEAD methods |

## Documentation

- [Architecture](docs/architecture.md)
- [CI/CD Recommendation](docs/ci_cd_recommendation.md)

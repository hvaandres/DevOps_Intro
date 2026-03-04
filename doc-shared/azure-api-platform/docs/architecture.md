# Architecture — Azure API Platform

## Overview

This platform provides a centralized, secure API layer hosted in Azure that enables external consumers (across AWS, GCP, On-Prem, and other cloud providers) to pull large volumes of data in a read-only fashion.

## Component Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                    External Consumers                            │
│           (AWS / GCP / On-Prem / Other Clouds)                  │
└──────────────────────┬───────────────────────────────────────────┘
                       │ HTTPS (TLS 1.2+)
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│              Azure API Management (APIM)                         │
│  ┌─────────────┐ ┌──────────────┐ ┌───────────────────────────┐ │
│  │ JWT Validate │ │ Rate Limit   │ │ Subscription Key Check    │ │
│  └─────────────┘ └──────────────┘ └───────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Request/Response Policies (read-only enforcement, CORS)     │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────┬───────────────────────────────────────────┘
                       │ Internal VNet
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│              Azure Function App (Python)                         │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────┐ │
│  │ /health    │ │ /blob-data │ │ /sql-data  │ │ /cosmos-data │ │
│  └────────────┘ └────────────┘ └────────────┘ └──────────────┘ │
│  • Managed Identity    • VNet Integrated    • Stateless         │
│  • Pagination          • Streaming          • Read-only         │
└──────────────────────┬───────────────────────────────────────────┘
                       │ Private Endpoints
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Data Sources                                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │
│  │ Blob Storage │ │ Azure SQL    │ │ Cosmos DB                │ │
│  │ / Data Lake  │ │ Database     │ │                          │ │
│  └──────────────┘ └──────────────┘ └──────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Azure Monitor / Log Analytics / Application Insights            │
└──────────────────────────────────────────────────────────────────┘
```

## Authentication Flow

1. External consumer registers an App Registration in their Entra ID tenant (or is provisioned one in the platform tenant).
2. Consumer requests an OAuth 2.0 token via `client_credentials` grant against the platform's Entra ID tenant.
3. Consumer sends requests to APIM with `Authorization: Bearer <token>` and `Ocp-Apim-Subscription-Key` headers.
4. APIM validates the JWT (issuer, audience, expiry, roles/scopes).
5. APIM forwards valid requests to the Function App over the internal VNet.
6. Function App uses its Managed Identity to access data sources — no secrets stored in code.

## Networking

- **VNet**: Single VNet with three subnets:
  - `snet-functions` — delegated to `Microsoft.Web/serverFarms` for Function App VNet integration
  - `snet-apim` — for APIM VNet injection (internal or external mode)
  - `snet-private-endpoints` — for private endpoints to storage, SQL, Cosmos DB
- **NSGs**: Applied to each subnet with least-privilege rules
- **Private DNS Zones**: For private endpoint resolution (blob, sql, cosmos)
- **No public IP** on data resources — all access via private endpoints

## Read-Only Enforcement (Defense in Depth)

1. **APIM Policy Layer**: Global policy rejects all HTTP methods except GET and HEAD
2. **Function App Code**: Only read operations implemented; no write endpoints exist
3. **RBAC**: Managed Identity assigned only Reader roles (Storage Blob Data Reader, SQL DB Reader, Cosmos DB Account Reader Role)
4. **Network**: Data sources only accessible via private endpoints from the Function App subnet

## Large Data Transfer Strategy

- **Pagination**: Cursor-based pagination with `continuation_token` for SQL and Cosmos DB queries
- **Streaming**: Chunked HTTP responses for large blob data
- **SAS Tokens**: For very large files (>100MB), the API returns a time-limited, read-only SAS URL for direct download
- **Compression**: gzip response encoding enabled at APIM and Function App level

## Multi-Region Scalability (Optional)

- **APIM Premium**: Deploy gateway units in multiple Azure regions
- **Azure Front Door**: Global load balancing and WAF
- **Cosmos DB**: Multi-region read replicas with automatic failover
- **Geo-Redundant Storage (GRS)**: For blob/data lake
- **Traffic Manager / Front Door**: Route to nearest region

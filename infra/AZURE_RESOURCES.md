# Azure Resources - DevSecOps Guardian

## Resumen de Recursos (6 total)

```
rg-devsecops-guardian                    (Resource Group)
├── acrdevsecopsguardian                 (Container Registry - Basic)
├── log-devsecops-guardian               (Log Analytics Workspace)
├── cae-devsecops-guardian               (Container Apps Environment)
│   ├── ca-api-gateway                   (Container App - API + 5 agents)
│   └── ca-dashboard                     (Container App - Next.js frontend)
│
└── [YA EXISTENTE] Azure OpenAI Foundry  (devsecops-guardian-hackaton-etec)
```

---

## Recurso 1: Resource Group

| Campo | Valor |
|-------|-------|
| **Nombre** | `rg-devsecops-guardian` |
| **Tipo** | `Microsoft.Resources/resourceGroups` |
| **Region** | `East US` |
| **Proposito** | Contenedor logico de todos los recursos |

**Portal**: Home > Resource groups > Create
```
Name:     rg-devsecops-guardian
Region:   East US
Tags:     project=devsecops-guardian, environment=hackathon
```

---

## Recurso 2: Azure Container Registry (ACR)

| Campo | Valor |
|-------|-------|
| **Nombre** | `acrdevsecopsguardian` |
| **Tipo** | `Microsoft.ContainerRegistry/registries` |
| **SKU** | `Basic` (~$5/mes) |
| **Region** | `East US` |
| **Resource Group** | `rg-devsecops-guardian` |
| **Admin user** | **Enabled** (requerido para Container Apps con secret-based auth) |
| **Login Server** | `acrdevsecopsguardian.azurecr.io` |
| **Proposito** | Almacenar imagenes Docker de api-gateway y dashboard |

**Portal**: Home > Container registries > Create
```
Registry name:  acrdevsecopsguardian
Resource group: rg-devsecops-guardian
Location:       East US
SKU:            Basic
```
Despues de crear: Settings > Access keys > Admin user: **Enable**

**Imagenes que se suben:**
| Imagen | Tag | Tamano aprox |
|--------|-----|-------------|
| `acrdevsecopsguardian.azurecr.io/api-gateway` | `v1`, `latest` | ~400MB |
| `acrdevsecopsguardian.azurecr.io/dashboard` | `v1`, `latest` | ~150MB |

---

## Recurso 3: Log Analytics Workspace

| Campo | Valor |
|-------|-------|
| **Nombre** | `log-devsecops-guardian` |
| **Tipo** | `Microsoft.OperationalInsights/workspaces` |
| **Region** | `East US` |
| **Resource Group** | `rg-devsecops-guardian` |
| **Retention** | 30 dias (default) |
| **Proposito** | Logs de Container Apps (stdout, stderr, system) |

**Nota**: Se crea automaticamente al crear el Container Apps Environment desde CLI.
Si lo creas desde el portal, el Environment te pide uno o crea uno nuevo.

---

## Recurso 4: Container Apps Environment

| Campo | Valor |
|-------|-------|
| **Nombre** | `cae-devsecops-guardian` |
| **Tipo** | `Microsoft.App/managedEnvironments` |
| **Region** | `East US` |
| **Resource Group** | `rg-devsecops-guardian` |
| **Log Analytics** | `log-devsecops-guardian` |
| **Proposito** | Red compartida entre api-gateway y dashboard |

**Portal**: Home > Container Apps Environments > Create
```
Environment name:    cae-devsecops-guardian
Resource group:      rg-devsecops-guardian
Region:              East US
Environment type:    Consumption only (mas barato)
Logs:                Azure Log Analytics (create new o seleccionar existente)
```

---

## Recurso 5: Container App - API Gateway

| Campo | Valor |
|-------|-------|
| **Nombre** | `ca-api-gateway` |
| **Tipo** | `Microsoft.App/containerApps` |
| **Region** | `East US` |
| **Resource Group** | `rg-devsecops-guardian` |
| **Environment** | `cae-devsecops-guardian` |
| **Image** | `acrdevsecopsguardian.azurecr.io/api-gateway:v1` |
| **Registry** | `acrdevsecopsguardian.azurecr.io` (secret-based auth) |
| **Target port** | `8000` |
| **Ingress** | **External** (accepting traffic from anywhere) |
| **Transport** | HTTP/1 (Auto) |
| **CPU** | `1.0 vCPU` |
| **Memory** | `2.0 Gi` |
| **Min replicas** | `0` (scale to zero) |
| **Max replicas** | `1` |
| **Proposito** | FastAPI backend + orquestador de 5 agentes AI |

### Environment Variables

| Variable | Tipo | Valor |
|----------|------|-------|
| `API_HOST` | Manual entry | `0.0.0.0` |
| `API_PORT` | Manual entry | `8000` |
| `CORS_ORIGINS` | Manual entry | `*` (actualizar despues con FQDN del dashboard) |
| `DEFAULT_SCAN_PATH` | Manual entry | `demo-app` |
| `PIPELINE_TIMEOUT` | Manual entry | `600` |
| `AZURE_OPENAI_DEPLOYMENT` | Manual entry | `gpt-4.1-mini` |
| `AZURE_OPENAI_API_VERSION` | Manual entry | `2024-12-01-preview` |
| `GITHUB_OWNER` | Manual entry | `freddan58` |
| `GITHUB_REPO` | Manual entry | `devsecops-guardian` |

### Secrets (configurar en Secrets tab ANTES de las env vars)

| Secret name | Valor |
|-------------|-------|
| `azure-openai-endpoint` | `https://devsecops-guardian-hackaton-etec.services.ai.azure.com/` |
| `azure-openai-api-key` | (tu API key de Azure OpenAI) |
| `github-token` | (tu GitHub PAT) |

### Environment Variables que referencian Secrets

| Variable | Source | Secret name |
|----------|--------|-------------|
| `AZURE_OPENAI_ENDPOINT` | Reference a secret | `azure-openai-endpoint` |
| `AZURE_OPENAI_API_KEY` | Reference a secret | `azure-openai-api-key` |
| `GITHUB_TOKEN` | Reference a secret | `github-token` |

**Portal path para crear**:
```
Home > Container Apps > Create

  Basics:
    Container app name:  ca-api-gateway
    Resource group:      rg-devsecops-guardian
    Container Apps Environment: cae-devsecops-guardian

  Container:
    Image source:        Azure Container Registry
    Registry:            acrdevsecopsguardian.azurecr.io
    Image:               api-gateway
    Image tag:           v1
    CPU and Memory:      1 vCPU, 2 Gi memory

    Environment variables:
      (agregar todas las de la tabla arriba)

  Ingress:
    Ingress:             Enabled
    Ingress traffic:     Accepting traffic from anywhere
    Ingress type:        HTTP
    Target port:         8000

  Scale:
    Min replicas: 0
    Max replicas: 1
```

---

## Recurso 6: Container App - Dashboard

| Campo | Valor |
|-------|-------|
| **Nombre** | `ca-dashboard` |
| **Tipo** | `Microsoft.App/containerApps` |
| **Region** | `East US` |
| **Resource Group** | `rg-devsecops-guardian` |
| **Environment** | `cae-devsecops-guardian` |
| **Image** | `acrdevsecopsguardian.azurecr.io/dashboard:v1` |
| **Registry** | `acrdevsecopsguardian.azurecr.io` (secret-based auth) |
| **Target port** | `3000` |
| **Ingress** | **External** (accepting traffic from anywhere) |
| **CPU** | `0.5 vCPU` |
| **Memory** | `1.0 Gi` |
| **Min replicas** | `0` (scale to zero) |
| **Max replicas** | `1` |
| **Proposito** | Next.js frontend del dashboard |

### Environment Variables

| Variable | Tipo | Valor |
|----------|------|-------|
| `NEXT_PUBLIC_API_URL` | Manual entry | `https://ca-api-gateway.<FQDN>.azurecontainerapps.io` * |
| `NODE_ENV` | Manual entry | `production` |
| `HOSTNAME` | Manual entry | `0.0.0.0` |

> *NOTA: `NEXT_PUBLIC_API_URL` se bake en el JS bundle en build-time. La env var en runtime
> es un fallback pero NO funciona para Next.js client-side code. Por eso la imagen del dashboard
> se debe rebuilder despues de conocer la URL del API (Paso 7 del deploy.ps1).

**Portal path para crear**:
```
Home > Container Apps > Create

  Basics:
    Container app name:  ca-dashboard
    Resource group:      rg-devsecops-guardian
    Container Apps Environment: cae-devsecops-guardian

  Container:
    Image source:        Azure Container Registry
    Registry:            acrdevsecopsguardian.azurecr.io
    Image:               dashboard
    Image tag:           v1
    CPU and Memory:      0.5 vCPU, 1 Gi memory

    Environment variables:
      NEXT_PUBLIC_API_URL = (URL del API gateway, ver nota)
      NODE_ENV = production
      HOSTNAME = 0.0.0.0

  Ingress:
    Ingress:             Enabled
    Ingress traffic:     Accepting traffic from anywhere
    Ingress type:        HTTP
    Target port:         3000

  Scale:
    Min replicas: 0
    Max replicas: 1
```

---

## Orden de Creacion (IMPORTANTE)

```
1. Resource Group              (contenedor de todo)
2. Container Registry          (donde van las imagenes)
3. [BUILD + PUSH imagenes]     (desde tu maquina local)
4. Log Analytics Workspace     (para logs)
5. Container Apps Environment  (red compartida)
6. Container App: API Gateway  (primero el API para obtener su URL)
7. [REBUILD dashboard]         (con la URL real del API)
8. Container App: Dashboard    (apuntando al API)
9. [ACTUALIZAR CORS del API]   (con la URL real del dashboard)
```

---

## Post-Deployment: Datos a Recopilar

Despues del deploy, compartir estos datos para actualizar configs:

| Dato | Donde encontrarlo | Ejemplo |
|------|--------------------|---------|
| API FQDN | Portal > ca-api-gateway > Overview > Application Url | `ca-api-gateway.delightfulforest-xxx.eastus.azurecontainerapps.io` |
| Dashboard FQDN | Portal > ca-dashboard > Overview > Application Url | `ca-dashboard.delightfulforest-xxx.eastus.azurecontainerapps.io` |
| ACR Login Server | Portal > acrdevsecopsguardian > Overview > Login server | `acrdevsecopsguardian.azurecr.io` |

---

## Costos Estimados (Hackathon)

| Recurso | Costo Estimado |
|---------|---------------|
| ACR Basic | ~$5/mes |
| Container Apps (scale-to-zero) | ~$0 cuando idle, ~$2-5/mes con uso |
| Log Analytics | ~$0-2/mes (30 day retention) |
| Azure OpenAI | Ya existente (pay-per-use) |
| **Total** | **~$10-15/mes** |

---

## Troubleshooting

### Imagen no encontrada en ACR
```powershell
az acr repository list --name acrdevsecopsguardian --output table
az acr repository show-tags --name acrdevsecopsguardian --repository api-gateway --output table
```

### Container App no inicia
```powershell
az containerapp logs show -n ca-api-gateway -g rg-devsecops-guardian --type system
az containerapp logs show -n ca-api-gateway -g rg-devsecops-guardian --type console
```

### API health check
```powershell
curl https://ca-api-gateway.<FQDN>.azurecontainerapps.io/api/health
```

### Dashboard no conecta al API (CORS)
Verificar que CORS_ORIGINS incluya la URL del dashboard:
```powershell
az containerapp show -n ca-api-gateway -g rg-devsecops-guardian --query "properties.template.containers[0].env"
```

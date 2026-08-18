# Infrastructure as Code (Bicep)

Clean, reusable Bicep templates that deploy the Azure resources for the
**Memory-Based Detection of Golden Ticket & SIDHistory Abuse** framework.

All templates are **sanitized**: no subscription IDs, tenant IDs, resource IDs,
IP addresses, or environment-specific names are embedded. Everything is driven by
parameters, and globally-unique names are derived at deploy time from a
`namePrefix` plus a `uniqueString()` suffix. Secrets (SSH key, connection strings)
are `@secure()` parameters or resolved at deploy time via `listKeys()` — never
committed.

## Structure
```
iac/
├── main.bicep                 # Subscription-scope orchestrator (creates RG + modules)
├── main.parameters.json       # Placeholder parameter values (edit before deploy)
├── .gitignore                 # Ignores local *.secret.* and compiled *.json
└── modules/
    ├── loganalytics.bicep     # Log Analytics workspace + Microsoft Sentinel
    ├── storage.bicep          # Storage: memory dumps, SIDHistory logs, Functions store
    ├── servicebus.bicep       # Service Bus namespace + memory-dump-queue + analysis-queue
    ├── functionapp.bicep      # Linux Python Function App + App Insights (system MSI)
    ├── dcr.bicep              # Data Collection Rule for Kerberos security events
    └── analysis-vm.bicep      # Ubuntu memory-analysis VM + network (dynamic public IP)
```

## What it deploys
| Module | Resources |
|--------|-----------|
| loganalytics | Log Analytics workspace, Sentinel onboarding |
| storage | 3 storage accounts + containers (`artifacts`, `kerberos-logs`, `sidhistory-logs`) |
| servicebus | Namespace + `memory-dump-queue`, `analysis-queue` |
| functionapp | Consumption plan, App Insights, Function App (system-assigned identity) |
| dcr | Data Collection Rule (events 4768/4769/4672/4624/4625/4662/5136) |
| analysis-vm | VNet, subnet, NSG, NIC, dynamic public IP, Ubuntu 22.04 VM |

## Prerequisites
- Azure CLI (`az`) with the Bicep extension, logged in to the target tenant
- An SSH key pair (`ssh-keygen -t rsa -b 4096`)

## Deploy
```bash
# validate
az deployment sub validate \
  --location <region> \
  --template-file main.bicep \
  --parameters main.parameters.json \
  --parameters sshPublicKey="$(cat ~/.ssh/id_rsa.pub)"

# what-if (preview changes)
az deployment sub what-if \
  --location <region> \
  --template-file main.bicep \
  --parameters main.parameters.json \
  --parameters sshPublicKey="$(cat ~/.ssh/id_rsa.pub)"

# deploy
az deployment sub create \
  --location <region> \
  --template-file main.bicep \
  --parameters main.parameters.json \
  --parameters sshPublicKey="$(cat ~/.ssh/id_rsa.pub)"
```

## Post-deployment (environment-specific — intentionally NOT in the templates)
These steps bind to resources whose identifiers are unique to *your* environment,
so they are documented rather than hardcoded:

1. **Arc-enable the Domain Controller** and install the Azure Monitor Agent.
2. **Associate the DCR** to the Arc machine:
   ```bash
   az monitor data-collection rule association create \
     --name dcr-association \
     --rule-id <DCR_RESOURCE_ID> \
     --resource <ARC_MACHINE_RESOURCE_ID>
   ```
3. **Grant the Function App's managed identity** access to Storage/Service Bus
   (Storage Blob Data Contributor, Azure Service Bus Data Owner).
4. **Deploy the Function code** (`function-app/`) and the **worker** (`azure/volatility-worker/`).
5. **Import the analytics rules** from [`../kql/`](../kql/) and the workbooks from
   [`../azure/workbooks/`](../azure/workbooks/).

## Security notes
- **Never commit private keys or connection strings.** `sshPublicKey` is the public
  key only; connection strings are resolved at deploy time.
- **Restrict SSH.** `sshSourceAddressPrefix` defaults to `*` for lab convenience —
  set it to your IP/CIDR for anything beyond a throwaway lab.
- Storage accounts are created with `allowBlobPublicAccess: false` and TLS 1.2.

> These templates provision infrastructure only. Detection content (KQL rules,
> workbooks, Function code, worker) lives elsewhere in the repository and is applied
> in the post-deployment steps above.

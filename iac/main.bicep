// =============================================================================
//  Memory-Based Detection of Golden Ticket & SIDHistory Abuse
//  Infrastructure as Code - main orchestrator (subscription scope)
//
//  Deploys the full hybrid detection framework. All environment-specific values
//  are parameters - no subscription IDs, tenant IDs, resource IDs, IPs, or
//  hardcoded names are embedded. Globally-unique names are derived at deploy
//  time from a namePrefix + a uniqueString() suffix.
//
//  Deploy:
//    az deployment sub create \
//      --location <region> \
//      --template-file main.bicep \
//      --parameters main.parameters.json \
//      --parameters sshPublicKey="$(cat ~/.ssh/id_rsa.pub)"
// =============================================================================

targetScope = 'subscription'

@description('Azure region for all resources.')
param location string = deployment().location

@description('Short prefix used to name resources (3-10 lowercase alphanumerics).')
@minLength(3)
@maxLength(10)
param namePrefix string = 'addetect'

@description('Name of the resource group to create/use.')
param resourceGroupName string = '${namePrefix}-rg'

@description('Admin username for the Linux analysis VM.')
param vmAdminUsername string = 'azureuser'

@description('SSH public key for the analysis VM (never commit the private key).')
@secure()
param sshPublicKey string

@description('Size of the Linux memory-analysis VM.')
param vmSize string = 'Standard_D2s_v3'

@description('Tags applied to all resources.')
param tags object = {
  project: 'ad-golden-ticket-detection'
  environment: 'lab'
  managedBy: 'bicep'
}

// A short, deterministic suffix for globally-unique names (storage, etc.)
var uniqueSuffix = substring(uniqueString(subscription().subscriptionId, resourceGroupName), 0, 6)

resource rg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module logAnalytics 'modules/loganalytics.bicep' = {
  scope: rg
  name: 'deploy-loganalytics'
  params: {
    location: location
    workspaceName: '${namePrefix}-ws'
    tags: tags
  }
}

module storage 'modules/storage.bicep' = {
  scope: rg
  name: 'deploy-storage'
  params: {
    location: location
    namePrefix: namePrefix
    uniqueSuffix: uniqueSuffix
    tags: tags
  }
}

module serviceBus 'modules/servicebus.bicep' = {
  scope: rg
  name: 'deploy-servicebus'
  params: {
    location: location
    namespaceName: '${namePrefix}-sb-${uniqueSuffix}'
    tags: tags
  }
}

module functionApp 'modules/functionapp.bicep' = {
  scope: rg
  name: 'deploy-functionapp'
  params: {
    location: location
    namePrefix: namePrefix
    uniqueSuffix: uniqueSuffix
    functionStorageName: storage.outputs.functionStorageName
    serviceBusNamespaceName: serviceBus.outputs.namespaceName
    tags: tags
  }
}

module dcr 'modules/dcr.bicep' = {
  scope: rg
  name: 'deploy-dcr'
  params: {
    location: location
    dcrName: '${namePrefix}-dcr-kerberos'
    workspaceResourceId: logAnalytics.outputs.workspaceResourceId
    tags: tags
  }
}

module analysisVm 'modules/analysis-vm.bicep' = {
  scope: rg
  name: 'deploy-analysis-vm'
  params: {
    location: location
    namePrefix: namePrefix
    vmSize: vmSize
    adminUsername: vmAdminUsername
    sshPublicKey: sshPublicKey
    tags: tags
  }
}

output resourceGroup string = rg.name
output workspaceName string = logAnalytics.outputs.workspaceName
output serviceBusNamespace string = serviceBus.outputs.namespaceName
output functionAppName string = functionApp.outputs.functionAppName
output analysisVmName string = analysisVm.outputs.vmName

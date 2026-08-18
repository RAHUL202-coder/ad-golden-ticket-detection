// Linux Consumption Function App (Python) + App Insights.
// Connection strings are resolved at deploy time via listKeys() - never hardcoded.
@description('Azure region.')
param location string

@description('Resource name prefix.')
param namePrefix string

@description('Deterministic unique suffix.')
param uniqueSuffix string

@description('Name of the Functions backing storage account (in the same RG).')
param functionStorageName string

@description('Name of the Service Bus namespace (in the same RG).')
param serviceBusNamespaceName string

@description('Python version for the Functions runtime.')
param pythonVersion string = '3.11'

@description('Resource tags.')
param tags object = {}

var functionAppName = '${namePrefix}proc${uniqueSuffix}'
var planName = '${namePrefix}-plan'
var appInsightsName = '${namePrefix}-ai'

resource functionStorage 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: functionStorageName
}

resource serviceBus 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' existing = {
  name: serviceBusNamespaceName
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: planName
  location: location
  tags: tags
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  kind: 'functionapp,linux'
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|${pythonVersion}'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${functionStorage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${functionStorage.listKeys().keys[0].value}'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          // Service Bus connection for triggers - resolved at deploy time
          name: 'SERVICEBUS_CONNECTION'
          value: listKeys('${serviceBus.id}/AuthorizationRules/RootManageSharedAccessKey', '2022-10-01-preview').primaryConnectionString
        }
        {
          // Blob storage that receives LSASS dumps (set to your memory-dump storage connection)
          name: 'MEMDUMP_STORAGE_CONN'
          value: '<SET_VIA_DEPLOYMENT_OR_KEYVAULT>'
        }
      ]
    }
  }
}

output functionAppName string = functionApp.name
output functionAppPrincipalId string = functionApp.identity.principalId

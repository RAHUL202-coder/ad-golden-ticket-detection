// Service Bus namespace + the two pipeline queues.
@description('Azure region.')
param location string

@description('Service Bus namespace name (globally unique).')
param namespaceName string

@description('Resource tags.')
param tags object = {}

resource namespace 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: namespaceName
  location: location
  tags: tags
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
  properties: {
    minimumTlsVersion: '1.2'
  }
}

resource memoryDumpQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: namespace
  name: 'memory-dump-queue'
  properties: {
    lockDuration: 'PT5M'
    maxDeliveryCount: 10
    defaultMessageTimeToLive: 'P1D'
  }
}

resource analysisQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: namespace
  name: 'analysis-queue'
  properties: {
    lockDuration: 'PT5M'
    maxDeliveryCount: 10
    defaultMessageTimeToLive: 'P1D'
  }
}

output namespaceName string = namespace.name
output namespaceResourceId string = namespace.id

// Storage accounts: memory dumps, SIDHistory logs, and the Functions backing store.
// Global-unique names are derived from namePrefix + uniqueSuffix.
@description('Azure region.')
param location string

@description('Resource name prefix.')
param namePrefix string

@description('Deterministic suffix for globally-unique names.')
param uniqueSuffix string

@description('Resource tags.')
param tags object = {}

// --- Memory-dump storage (LSASS dumps + kerberos logs) ---
resource memoryStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mem${uniqueSuffix}${substring(namePrefix, 0, min(length(namePrefix), 8))}'
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource memoryBlob 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: memoryStorage
  name: 'default'
}

resource artifactsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: memoryBlob
  name: 'artifacts'
  properties: {
    publicAccess: 'None'
  }
}

resource kerberosLogsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: memoryBlob
  name: 'kerberos-logs'
  properties: {
    publicAccess: 'None'
  }
}

// --- SIDHistory storage ---
resource sidHistoryStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'sid${uniqueSuffix}${substring(namePrefix, 0, min(length(namePrefix), 8))}'
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource sidBlob 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: sidHistoryStorage
  name: 'default'
}

resource sidLogsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: sidBlob
  name: 'sidhistory-logs'
  properties: {
    publicAccess: 'None'
  }
}

// --- Functions backing storage ---
resource functionStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'func${uniqueSuffix}${substring(namePrefix, 0, min(length(namePrefix), 7))}'
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

output memoryStorageName string = memoryStorage.name
output sidHistoryStorageName string = sidHistoryStorage.name
output functionStorageName string = functionStorage.name

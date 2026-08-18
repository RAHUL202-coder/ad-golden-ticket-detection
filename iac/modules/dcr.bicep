// Data Collection Rule (AMA) for Kerberos / account-logon security events.
// Bind the association to your Arc-enabled DC separately (see iac/README.md),
// because the machine resource id is environment-specific.
@description('Azure region.')
param location string

@description('Data Collection Rule name.')
param dcrName string

@description('Resource id of the target Log Analytics workspace.')
param workspaceResourceId string

@description('Resource tags.')
param tags object = {}

var destinationName = 'laDestination'

resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: dcrName
  location: location
  tags: tags
  kind: 'Windows'
  properties: {
    dataSources: {
      windowsEventLogs: [
        {
          name: 'securityEvents'
          streams: [
            'Microsoft-SecurityEvent'
          ]
          // Kerberos + account-logon + directory events used by the detections.
          xPathQueries: [
            'Security!*[System[(EventID=4768 or EventID=4769 or EventID=4672 or EventID=4624 or EventID=4625 or EventID=4662 or EventID=5136)]]'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: destinationName
          workspaceResourceId: workspaceResourceId
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-SecurityEvent'
        ]
        destinations: [
          destinationName
        ]
      }
    ]
  }
}

output dcrResourceId string = dcr.id
output dcrName string = dcr.name

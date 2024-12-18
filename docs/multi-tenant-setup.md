# Multi-Tenant Setup for MSPs

This guide explains how to configure CISA MCP servers for managing multiple Microsoft 365 tenants, ideal for Managed Service Providers (MSPs).

## Overview

The multi-tenant configuration allows MSPs to:
- Manage multiple client tenants from a single deployment
- Apply consistent security policies across all tenants
- Generate consolidated reports and alerts
- Customize settings per tenant while maintaining global standards

## Configuration Structure

The multi-tenant setup uses an extended configuration format that supports multiple tenant credentials and settings:

```json
{
  "mcpServer": {
    "command": "node",
    "args": ["./build/index.js"],
    "tenants": [
      {
        "name": "Tenant1",
        "env": {
          "MS_TENANT_ID": "tenant1-id",
          "MS_CLIENT_ID": "tenant1-client-id",
          "MS_CLIENT_SECRET": "tenant1-client-secret"
        },
        "policies": {
          "securityDefaults": true,
          "conditionalAccess": true,
          "mfaEnforcement": true
        }
      }
    ],
    "globalSettings": {
      "parallelExecution": true,
      "reportingInterval": "daily",
      "alertThresholds": {
        "securityScore": 70,
        "complianceScore": 80
      },
      "notifications": {
        "email": "admin@msp.com",
        "teams": "webhook-url",
        "slack": "webhook-url"
      }
    }
  }
}
```

## Setup Instructions

1. Create App Registrations
   - Create an app registration in each tenant's Azure AD
   - Grant necessary permissions for Microsoft Graph API
   - Generate client secrets

2. Configure Tenant Settings
   - Copy the example configuration
   - Add each tenant's credentials and settings
   - Customize policies per tenant if needed

3. Global Settings
   - Configure reporting and notification preferences
   - Set alert thresholds
   - Enable parallel execution if desired

## Features

### Per-Tenant Configuration
- Individual credentials
- Custom security policies
- Tenant-specific thresholds

### Global Management
- Centralized reporting
- Consolidated alerts
- Unified policy enforcement

### Automation
- Parallel execution across tenants
- Scheduled compliance checks
- Automated remediation

## Best Practices

1. Security
   - Use separate service principals per tenant
   - Implement least-privilege access
   - Rotate secrets regularly

2. Performance
   - Enable parallel execution for faster processing
   - Set appropriate reporting intervals
   - Monitor resource usage

3. Compliance
   - Maintain tenant isolation
   - Track per-tenant compliance scores
   - Document policy exceptions

## Example Use Cases

1. Security Baseline Deployment
```json
{
  "policies": {
    "securityDefaults": true,
    "conditionalAccess": {
      "mfaPolicy": true,
      "locationPolicy": true
    }
  }
}
```

2. Compliance Monitoring
```json
{
  "monitoring": {
    "complianceChecks": ["NIST", "HIPAA", "PCI"],
    "reportingFrequency": "daily"
  }
}
```

## Troubleshooting

Common issues and solutions:

1. Authentication Failures
   - Verify tenant credentials
   - Check permission grants
   - Confirm secret expiration

2. Performance Issues
   - Adjust parallel execution settings
   - Optimize reporting intervals
   - Monitor resource utilization

## Additional Resources

- [Microsoft Graph API Documentation](https://docs.microsoft.com/graph)
- [Azure AD Best Practices](https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-introduction)
- [CISA Security Guidelines](https://www.cisa.gov/cybersecurity)

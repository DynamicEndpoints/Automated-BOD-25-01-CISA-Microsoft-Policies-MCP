# CISA Power Platform MCP Server

This Model Context Protocol (MCP) server implements security controls for Microsoft Power Platform according to CISA Binding Operational Directive 25-01.

## Overview

The CISA Power Platform MCP server provides tools for configuring and managing Power Platform security settings in accordance with BOD 25-01 requirements. It helps organizations:

- Restrict environment creation capabilities to administrators only
- Implement Data Loss Prevention (DLP) policies in the default environment
- Enable tenant isolation for enhanced security
- Monitor and report on security control compliance

## Security Controls Implementation

### MS.POWERPLATFORM.1.1v1 & MS.POWERPLATFORM.1.2v1
**Due Date: 06/20/2025**
- Restricts the ability to create production and sandbox environments to admins
- Restricts the ability to create trial environments to admins
- Prevents non-admin users from creating any type of environment
- Ensures centralized control over environment provisioning

### MS.POWERPLATFORM.2.1v1
**Due Date: 06/20/2025**
- Creates and enforces DLP policy in the default Power Platform environment
- Restricts connector access based on data sensitivity
- Prevents unauthorized data sharing and exfiltration
- Enables granular control over which connectors can be used

### MS.POWERPLATFORM.3.1v1
**Due Date: 06/20/2025**
- Enables Power Platform tenant isolation
- Prevents cross-tenant data sharing and access
- Enhances security boundaries between tenants
- Reduces risk of unauthorized data access

## Available Tools

### restrict_environment_creation
Restricts environment creation capabilities to specified admin groups.

```json
{
  "adminGroupId": "group-id"
}
```

### configure_dlp_policy
Creates and configures DLP policies to restrict connector access.

```json
{
  "allowedConnectors": ["connector-id-1", "connector-id-2"]
}
```

### enable_tenant_isolation
Enables Power Platform tenant isolation settings.

```json
{}
```

### get_policy_status
Retrieves current status of all CISA Power Platform security policies.

```json
{}
```

## Installation

1. Clone this repository
2. Install dependencies:
```bash
npm install
```
3. Build the server:
```bash
npm run build
```
4. Configure environment variables by copying `.env.example` to `.env` and setting required values:
```
TENANT_ID=your-tenant-id
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
```

## Usage

Configure the server in your MCP client settings (e.g., Claude desktop app):

```json
{
  "mcpServers": {
    "cisa-powerplatform": {
      "command": "node",
      "args": ["path/to/cisa-powerplatform/build/index.js"],
      "env": {
        "TENANT_ID": "your-tenant-id",
        "CLIENT_ID": "your-client-id",
        "CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

## Compliance Reporting

The server provides comprehensive reporting capabilities to help track compliance with BOD 25-01 requirements:

- Current status of all security controls
- Detailed policy configurations
- Non-compliant settings detection
- Recommendations for remediation

## Security Considerations

- All credentials and tokens are handled securely through environment variables
- API calls use Microsoft Graph API with appropriate authentication
- Changes are logged for audit purposes
- Tenant isolation is enforced when enabled
- DLP policies are strictly enforced

## Contributing

Contributions are welcome! Please ensure any pull requests or changes:

1. Include clear documentation
2. Follow existing code style
3. Include tests where appropriate
4. Update security control implementations as BOD requirements evolve

## License

MIT

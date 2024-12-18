# CISA SharePoint & OneDrive MCP Server

This Model Context Protocol (MCP) server implements security controls for Microsoft SharePoint Online and OneDrive according to CISA Binding Operational Directive 25-01.

## Overview

The CISA SharePoint & OneDrive MCP server provides tools for configuring and managing SharePoint Online and OneDrive security settings in accordance with BOD 25-01 requirements. It helps organizations:

- Restrict external sharing capabilities
- Configure secure default sharing settings
- Prevent custom script execution
- Monitor and report on security control compliance

## Security Controls Implementation

### MS.SHAREPOINT.1.1v1
**Due Date: 06/20/2025**
- Restricts external sharing in SharePoint to:
  - Existing Guests only, or
  - Only People in your Organization
- Prevents unrestricted external sharing
- Ensures controlled access to SharePoint content

### MS.SHAREPOINT.1.2v1
**Due Date: 06/20/2025**
- Restricts external sharing in OneDrive to:
  - Existing Guests only, or
  - Only People in your Organization
- Prevents unrestricted external sharing
- Ensures controlled access to OneDrive content

### MS.SHAREPOINT.2.1v1
**Due Date: 06/20/2025**
- Sets file and folder default sharing scope to "Specific People"
- Requires explicit selection of recipients
- Prevents accidental oversharing
- Enhances sharing control granularity

### MS.SHAREPOINT.2.2v1
**Due Date: 06/20/2025**
- Sets file and folder default sharing permissions to "View only"
- Restricts default access level
- Requires explicit permission elevation when needed
- Implements principle of least privilege

### MS.SHAREPOINT.4.2v1
**Due Date: 06/20/2025**
- Prevents users from running custom scripts on self-service created sites
- Reduces risk of malicious script execution
- Enhances security of user-created sites
- Maintains controlled development environment

## Available Tools

### configure_sharepoint_sharing
Configure SharePoint external sharing settings.

```json
{
  "sharingLevel": "ExistingGuests"
}
```

### configure_onedrive_sharing
Configure OneDrive external sharing settings.

```json
{
  "sharingLevel": "OnlyOrganization"
}
```

### configure_default_sharing_scope
Configure default sharing scope for files and folders.

```json
{}
```

### configure_default_sharing_permissions
Configure default sharing permissions for files and folders.

```json
{}
```

### disable_custom_scripts
Prevent users from running custom scripts on self-service created sites.

```json
{}
```

### get_policy_status
Get current status of all CISA SharePoint and OneDrive security policies.

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
    "cisa-sharepoint": {
      "command": "node",
      "args": ["path/to/cisa-sharepoint/build/index.js"],
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
- Detailed sharing settings configuration
- Non-compliant settings detection
- Recommendations for remediation

## Security Considerations

- All credentials and tokens are handled securely through environment variables
- API calls use Microsoft Graph API with appropriate authentication
- Changes are logged for audit purposes
- Sharing restrictions are strictly enforced
- Custom script execution is controlled

## Contributing

Contributions are welcome! Please ensure any pull requests or changes:

1. Include clear documentation
2. Follow existing code style
3. Include tests where appropriate
4. Update security control implementations as BOD requirements evolve

## License

MIT

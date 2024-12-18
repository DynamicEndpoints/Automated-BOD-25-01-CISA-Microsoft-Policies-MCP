# CISA Power Platform MCP Server

This MCP server implements security controls for Microsoft Power Platform according to CISA BOD 25-01 requirements.

## Security Controls

### MS.POWERPLATFORM.1.1v1 & MS.POWERPLATFORM.1.2v1
- Restricts the ability to create production, sandbox, and trial environments to admins only
- Due Date: 06/20/2025

### MS.POWERPLATFORM.2.1v1
- Creates DLP policy to restrict connector access in the default Power Platform environment
- Due Date: 06/20/2025

### MS.POWERPLATFORM.3.1v1
- Enables Power Platform tenant isolation
- Due Date: 06/20/2025

## Available Tools

### restrict_environment_creation
Restricts production, sandbox, and trial environment creation to admins.

```json
{
  "adminGroupId": "group-id"
}
```

### configure_dlp_policy
Creates DLP policy to restrict connector access in default environment.

```json
{
  "allowedConnectors": ["connector-id-1", "connector-id-2"]
}
```

### enable_tenant_isolation
Enables Power Platform tenant isolation.

```json
{}
```

### get_policy_status
Gets current status of all CISA Power Platform security policies.

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

## License

MIT

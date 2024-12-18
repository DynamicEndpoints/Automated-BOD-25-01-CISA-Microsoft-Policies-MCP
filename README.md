# CISA Microsoft Defender Compliance Server

This MCP server implements Microsoft Defender policies according to [CISA BOD 25-01](https://www.cisa.gov/resources-tools/services/bod-25-01-implementing-secure-practices-cloud-services-required-configurations) requirements for Microsoft 365 cloud services.

<a href="https://glama.ai/mcp/servers/rml141i0fk"><img width="380" height="200" src="https://glama.ai/mcp/servers/rml141i0fk/badge" alt="BOD-25-01-CSA-Microsoft-Policy-MCP MCP server" /></a>

## CISA Policy Implementation

### Policy Reference

This server implements the following CISA BOD 25-01 Microsoft Defender policies:

| Policy ID | Requirement | Due Date | Implementation |
|-----------|-------------|----------|----------------|
| MS.DEFENDER.1.1v1 | Standard and strict preset security policies SHALL be enabled | 06/20/2025 | `configure_security_policies` tool |
| MS.DEFENDER.1.2v1 | All users SHALL be added to Exchange Online Protection in standard/strict policy | 06/20/2025 | `configure_security_policies` tool |
| MS.DEFENDER.1.3v1 | All users SHALL be added to Defender for Office 365 Protection | 06/20/2025 | `configure_security_policies` tool |
| MS.DEFENDER.1.4v1 | Sensitive accounts SHALL be added to Exchange Online Protection strict policy | 06/20/2025 | `configure_security_policies` tool |
| MS.DEFENDER.1.5v1 | Sensitive accounts SHALL be added to Defender for Office 365 strict policy | 06/20/2025 | `configure_security_policies` tool |
| MS.DEFENDER.4.1v1 | Custom policy SHALL be configured to protect PII and sensitive information | 06/20/2025 | `configure_pii_protection` tool |
| MS.DEFENDER.5.1v1 | Required alerts SHALL be enabled | 06/20/2025 | `configure_alerts` tool |
| MS.DEFENDER.6.1v1 | Microsoft Purview Audit (Standard) logging SHALL be enabled | 06/20/2025 | `configure_audit_logging` tool |
| MS.DEFENDER.6.2v1 | Microsoft Purview Audit (Premium) logging SHALL be enabled for ALL users | 06/20/2025 | `configure_audit_logging` tool |

## Installation

```bash
# Clone the repository
git clone [repository-url]

# Install dependencies
npm install

# Copy environment example
cp .env.example .env

# Edit .env with your credentials
# Build the server
npm run build
```

## Security Setup

### Environment Variables

Create a `.env` file with your Microsoft 365 credentials:

```env
TENANT_ID=your-tenant-id
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
```

⚠️ **SECURITY NOTICE**: Never commit credentials to source control. The `.gitignore` file is configured to prevent this.

## Usage Examples

### 1. Get Current Policy Status

Check compliance status of all Microsoft Defender policies:

```typescript
const result = await use_mcp_tool({
  server_name: "cisa-defender",
  tool_name: "get_policy_status",
  arguments: {}
});
```

### 2. Configure Security Policies

Enable standard and strict security policies with sensitive accounts:

```typescript
const result = await use_mcp_tool({
  server_name: "cisa-defender",
  tool_name: "configure_security_policies",
  arguments: {
    standardPolicy: true,
    strictPolicy: true,
    sensitiveAccounts: [
      "admin@domain.com",
      "security@domain.com"
    ]
  }
});
```

### 3. Configure PII Protection

Set up PII protection according to MS.DEFENDER.4.1v1:

```typescript
const result = await use_mcp_tool({
  server_name: "cisa-defender",
  tool_name: "configure_pii_protection",
  arguments: {
    blockCreditCards: true,
    blockTIN: true,
    blockSSN: true,
    customPatterns: [
      // Add custom patterns if needed
    ]
  }
});
```

### 4. Configure Audit Logging

Enable both standard and premium audit logging:

```typescript
const result = await use_mcp_tool({
  server_name: "cisa-defender",
  tool_name: "configure_audit_logging",
  arguments: {
    enableStandard: true,
    enablePremium: true,
    userScope: "all"
  }
});
```

## Compliance Verification

After applying configurations, use the `get_policy_status` tool to verify compliance:

```typescript
const status = await use_mcp_tool({
  server_name: "cisa-defender",
  tool_name: "get_policy_status",
  arguments: {}
});

// Status includes:
// - Current configuration
// - Compliance status for each policy
// - Implementation dates
// - Due dates
// - Recommendations for non-compliant items
```

## Additional Resources

- [CISA BOD 25-01 Documentation](https://www.cisa.gov/resources-tools/services/bod-25-01-implementing-secure-practices-cloud-services-required-configurations)
- [Microsoft Defender Security Documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender/)
- [Microsoft Graph API Reference](https://learn.microsoft.com/en-us/graph/api/overview)

## Security Best Practices

1. **Credential Management**
   - Store credentials securely in environment variables
   - Rotate secrets regularly
   - Use least-privilege access principles

2. **Audit Logging**
   - Monitor policy changes
   - Review audit logs regularly
   - Maintain compliance documentation

3. **Policy Updates**
   - Subscribe to CISA updates
   - Review policy changes regularly
   - Update configurations as needed

## Troubleshooting

Common issues and solutions:

1. **Authentication Errors**
   - Verify credentials in .env file
   - Check Azure AD permissions
   - Ensure service principal has required roles

2. **Policy Application Failures**
   - Check for conflicting policies
   - Verify account permissions
   - Review error messages in logs

## Support

For issues related to:
- CISA BOD 25-01: Contact CISA
- Microsoft Defender: Contact Microsoft Support
- This MCP Server: Open an issue in the repository

Remember to never share credentials or sensitive information when seeking support.

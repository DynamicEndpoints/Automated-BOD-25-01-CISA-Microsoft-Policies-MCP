# CISA Exchange Online Compliance Server

This MCP server implements Exchange Online policies according to [CISA BOD 25-01](https://www.cisa.gov/resources-tools/services/bod-25-01-implementing-secure-practices-cloud-services-required-configurations) requirements for Microsoft 365 cloud services.

## CISA Policy Implementation

### Policy Reference

This server implements the following CISA BOD 25-01 Exchange Online policies:

| Policy ID | Requirement | Due Date | Implementation |
|-----------|-------------|----------|----------------|
| MS.EXO.1.1v1 | Automatic forwarding to external domains SHALL be disabled | 06/20/2025 | `disable_external_forwarding` tool |
| MS.EXO.2.2v2 | SPF policy SHALL be published for each domain | 06/20/2025 | `configure_spf_policy` tool |
| MS.EXO.4.1v1 | DMARC policy SHALL be published for every second-level domain | 06/20/2025 | `configure_dmarc_policy` tool |
| MS.EXO.4.2v1 | DMARC message rejection option SHALL be p=reject | 06/20/2025 | `configure_dmarc_policy` tool |
| MS.EXO.4.3v1 | DMARC reports SHALL include reports@dmarc.cyber.dhs.gov | 06/20/2025 | `configure_dmarc_policy` tool |
| MS.EXO.5.1v1 | SMTP AUTH SHALL be disabled | 06/20/2025 | `disable_smtp_auth` tool |
| MS.EXO.6.1v1 | Contact folders SHALL NOT be shared with all domains | 06/20/2025 | `configure_sharing_policies` tool |
| MS.EXO.6.2v1 | Calendar details SHALL NOT be shared with all domains | 06/20/2025 | `configure_sharing_policies` tool |
| MS.EXO.7.1v1 | External sender warnings SHALL be implemented | 06/20/2025 | `enable_external_sender_warning` tool |
| MS.EXO.13.1v1 | Mailbox auditing SHALL be enabled | 06/20/2025 | `enable_mailbox_audit` tool |

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

Check compliance status of all Exchange Online policies:

```typescript
const result = await use_mcp_tool({
  server_name: "cisa-exchange",
  tool_name: "get_policy_status",
  arguments: {}
});
```

### 2. Configure External Forwarding

Disable automatic forwarding to external domains:

```typescript
const result = await use_mcp_tool({
  server_name: "cisa-exchange",
  tool_name: "disable_external_forwarding",
  arguments: {}
});
```

### 3. Configure SPF and DMARC

Set up SPF and DMARC policies for a domain:

```typescript
// Configure SPF
const spfResult = await use_mcp_tool({
  server_name: "cisa-exchange",
  tool_name: "configure_spf_policy",
  arguments: {
    domain: "yourdomain.com"
  }
});

// Configure DMARC
const dmarcResult = await use_mcp_tool({
  server_name: "cisa-exchange",
  tool_name: "configure_dmarc_policy",
  arguments: {
    domain: "yourdomain.com",
    rejectPolicy: true,
    includeReports: true  // Adds reports@dmarc.cyber.dhs.gov
  }
});
```

### 4. Configure Sharing Policies

Disable contact and calendar sharing with all domains:

```typescript
const result = await use_mcp_tool({
  server_name: "cisa-exchange",
  tool_name: "configure_sharing_policies",
  arguments: {
    disableContactSharing: true,
    disableCalendarSharing: true
  }
});
```

### 5. Enable Security Features

Enable external sender warnings and mailbox auditing:

```typescript
// Enable external sender warnings
const warningResult = await use_mcp_tool({
  server_name: "cisa-exchange",
  tool_name: "enable_external_sender_warning",
  arguments: {}
});

// Enable mailbox auditing
const auditResult = await use_mcp_tool({
  server_name: "cisa-exchange",
  tool_name: "enable_mailbox_audit",
  arguments: {}
});
```

## Compliance Verification

After applying configurations, use the `get_policy_status` tool to verify compliance:

```typescript
const status = await use_mcp_tool({
  server_name: "cisa-exchange",
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
- [Exchange Online Documentation](https://learn.microsoft.com/en-us/exchange/exchange-online)
- [Microsoft Graph API Reference](https://learn.microsoft.com/en-us/graph/api/overview)
- [DMARC Implementation Guide](https://www.cisa.gov/sites/default/files/publications/dmarc-guide.pdf)

## Security Best Practices

1. **Email Security**
   - Monitor forwarding rules regularly
   - Review DMARC reports
   - Maintain SPF records

2. **Access Control**
   - Review sharing policies regularly
   - Monitor external access
   - Audit mailbox permissions

3. **Compliance Monitoring**
   - Review audit logs
   - Track policy changes
   - Document compliance status

## Troubleshooting

Common issues and solutions:

1. **DMARC/SPF Issues**
   - Verify DNS records
   - Check domain ownership
   - Review email authentication reports

2. **Sharing Policy Problems**
   - Check existing sharing relationships
   - Verify policy application
   - Review override settings

3. **Audit Configuration**
   - Verify mailbox audit settings
   - Check retention policies
   - Review audit log search capabilities

## Support

For issues related to:
- CISA BOD 25-01: Contact CISA
- Exchange Online: Contact Microsoft Support
- This MCP Server: Open an issue in the repository

Remember to never share credentials or sensitive information when seeking support.

## Policy Updates

Stay informed about CISA policy updates:
- Subscribe to [CISA Alerts](https://www.cisa.gov/news-events/cybersecurity-advisories)
- Monitor BOD 25-01 updates
- Review Exchange Online security advisories

## Contributing

1. Follow security guidelines
2. Test thoroughly
3. Document changes
4. Submit pull requests

Remember to never include sensitive data in contributions.

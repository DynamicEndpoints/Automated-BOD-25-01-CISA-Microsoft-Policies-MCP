#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { Client } from '@microsoft/microsoft-graph-client';
import { ClientSecretCredential } from '@azure/identity';

// CISA BOD 25-01 Exchange Online Policy IDs and Requirements
const EXO_POLICIES = {
  EXTERNAL_FORWARDING: {
    id: 'MS.EXO.1.1v1',
    title: 'Disable External Forwarding',
    requirement: 'Automatic forwarding to external domains SHALL be disabled.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  SPF_POLICY: {
    id: 'MS.EXO.2.2v2',
    title: 'SPF Policy',
    requirement: 'An SPF policy SHALL be published for each domain that fails all non-approved senders.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  DMARC_POLICY: {
    id: 'MS.EXO.4.1v1',
    title: 'DMARC Policy',
    requirement: 'A DMARC policy SHALL be published for every second-level domain.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  DMARC_REJECT: {
    id: 'MS.EXO.4.2v1',
    title: 'DMARC Reject',
    requirement: 'The DMARC message rejection option SHALL be p=reject.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  DMARC_REPORTS: {
    id: 'MS.EXO.4.3v1',
    title: 'DMARC Reports',
    requirement: 'The DMARC point of contact for aggregate reports SHALL include reports@dmarc.cyber.dhs.gov.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  SMTP_AUTH: {
    id: 'MS.EXO.5.1v1',
    title: 'SMTP AUTH',
    requirement: 'SMTP AUTH SHALL be disabled.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  CONTACT_SHARING: {
    id: 'MS.EXO.6.1v1',
    title: 'Contact Sharing',
    requirement: 'Contact folders SHALL NOT be shared with all domains.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  CALENDAR_SHARING: {
    id: 'MS.EXO.6.2v1',
    title: 'Calendar Sharing',
    requirement: 'Calendar details SHALL NOT be shared with all domains.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  EXTERNAL_SENDER: {
    id: 'MS.EXO.7.1v1',
    title: 'External Sender Warnings',
    requirement: 'External sender warnings SHALL be implemented.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  MAILBOX_AUDIT: {
    id: 'MS.EXO.13.1v1',
    title: 'Mailbox Auditing',
    requirement: 'Mailbox auditing SHALL be enabled.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  }
};

interface DmarcPolicyArgs {
  domain: string;
  rejectPolicy: boolean;
  includeReports: boolean;
}

interface SharingPolicyArgs {
  disableContactSharing: boolean;
  disableCalendarSharing: boolean;
}

class CisaExchangeServer {
  private server: Server;
  private graphClient: Client | null = null;

  constructor() {
    this.server = new Server(
      {
        name: 'cisa-exchange',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    const tenantId = process.env.TENANT_ID;
    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;

    if (tenantId && clientId && clientSecret) {
      const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
      this.graphClient = Client.initWithMiddleware({
        authProvider: {
          getAccessToken: async () => {
            const token = await credential.getToken('https://graph.microsoft.com/.default');
            return token.token;
          }
        }
      });
    }

    this.setupToolHandlers();
    
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'get_policy_status',
          description: 'Get current status of all CISA Exchange Online policies',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'disable_external_forwarding',
          description: 'Disable automatic forwarding to external domains',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'configure_spf_policy',
          description: 'Configure SPF policy for domains',
          inputSchema: {
            type: 'object',
            properties: {
              domain: {
                type: 'string',
                description: 'Domain to configure SPF for'
              }
            },
            required: ['domain']
          }
        },
        {
          name: 'configure_dmarc_policy',
          description: 'Configure DMARC policy settings',
          inputSchema: {
            type: 'object',
            properties: {
              domain: {
                type: 'string',
                description: 'Domain to configure DMARC for'
              },
              rejectPolicy: {
                type: 'boolean',
                description: 'Enable p=reject policy'
              },
              includeReports: {
                type: 'boolean',
                description: 'Include CISA DMARC reporting address'
              }
            },
            required: ['domain', 'rejectPolicy', 'includeReports']
          }
        },
        {
          name: 'disable_smtp_auth',
          description: 'Disable SMTP AUTH',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'configure_sharing_policies',
          description: 'Configure contact and calendar sharing policies',
          inputSchema: {
            type: 'object',
            properties: {
              disableContactSharing: {
                type: 'boolean',
                description: 'Disable contact folder sharing'
              },
              disableCalendarSharing: {
                type: 'boolean',
                description: 'Disable calendar detail sharing'
              }
            },
            required: ['disableContactSharing', 'disableCalendarSharing']
          }
        },
        {
          name: 'enable_external_sender_warning',
          description: 'Enable external sender warnings',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'enable_mailbox_audit',
          description: 'Enable mailbox auditing',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        }
      ]
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      if (!this.graphClient) {
        throw new McpError(
          ErrorCode.InvalidRequest,
          'Microsoft Graph client not configured. Please provide TENANT_ID, CLIENT_ID, and CLIENT_SECRET.'
        );
      }

      switch (request.params.name) {
        case 'get_policy_status':
          return await this.getPolicyStatus();
        case 'disable_external_forwarding':
          return await this.disableExternalForwarding();
        case 'configure_spf_policy':
          return await this.configureSpfPolicy(request.params.arguments.domain);
        case 'configure_dmarc_policy':
          return await this.configureDmarcPolicy(request.params.arguments as DmarcPolicyArgs);
        case 'disable_smtp_auth':
          return await this.disableSmtpAuth();
        case 'configure_sharing_policies':
          return await this.configureSharingPolicies(request.params.arguments as SharingPolicyArgs);
        case 'enable_external_sender_warning':
          return await this.enableExternalSenderWarning();
        case 'enable_mailbox_audit':
          return await this.enableMailboxAudit();
        default:
          throw new McpError(
            ErrorCode.MethodNotFound,
            `Unknown tool: ${request.params.name}`
          );
      }
    });
  }

  private async getPolicyStatus() {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const results = {
        policies: EXO_POLICIES,
        currentStatus: {
          externalForwarding: await this.graphClient.api('/admin/exchangeSettings/externalForwarding').get(),
          spfPolicies: await this.graphClient.api('/admin/domains/spfRecords').get(),
          dmarcPolicies: await this.graphClient.api('/admin/domains/dmarcRecords').get(),
          smtpAuth: await this.graphClient.api('/admin/exchangeSettings/smtpAuth').get(),
          sharingPolicies: await this.graphClient.api('/admin/exchangeSettings/sharingPolicies').get(),
          externalSenderWarning: await this.graphClient.api('/admin/exchangeSettings/externalSenderWarning').get(),
          mailboxAudit: await this.graphClient.api('/admin/exchangeSettings/mailboxAudit').get()
        }
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(results, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to get policy status: ${errorMessage}`
      );
    }
  }

  private async disableExternalForwarding() {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const result = await this.graphClient.api('/admin/exchangeSettings/externalForwarding')
        .patch({
          enabled: false
        });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              result,
              appliedPolicy: EXO_POLICIES.EXTERNAL_FORWARDING
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to disable external forwarding: ${errorMessage}`
      );
    }
  }

  private async configureSpfPolicy(domain: string) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const result = await this.graphClient.api(`/admin/domains/${domain}/spfRecord`)
        .patch({
          record: 'v=spf1 include:spf.protection.outlook.com -all'
        });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              result,
              appliedPolicy: EXO_POLICIES.SPF_POLICY
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure SPF policy: ${errorMessage}`
      );
    }
  }

  private async configureDmarcPolicy(args: DmarcPolicyArgs) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const dmarcRecord = {
        version: 'DMARC1',
        policy: args.rejectPolicy ? 'reject' : 'quarantine',
        rua: args.includeReports ? 'mailto:reports@dmarc.cyber.dhs.gov' : undefined
      };

      const result = await this.graphClient.api(`/admin/domains/${args.domain}/dmarcRecord`)
        .patch({
          record: `v=${dmarcRecord.version}; p=${dmarcRecord.policy}${dmarcRecord.rua ? `; rua=${dmarcRecord.rua}` : ''}`
        });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              result,
              appliedPolicies: [
                EXO_POLICIES.DMARC_POLICY,
                args.rejectPolicy && EXO_POLICIES.DMARC_REJECT,
                args.includeReports && EXO_POLICIES.DMARC_REPORTS
              ].filter(Boolean)
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure DMARC policy: ${errorMessage}`
      );
    }
  }

  private async disableSmtpAuth() {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const result = await this.graphClient.api('/admin/exchangeSettings/smtpAuth')
        .patch({
          enabled: false
        });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              result,
              appliedPolicy: EXO_POLICIES.SMTP_AUTH
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to disable SMTP AUTH: ${errorMessage}`
      );
    }
  }

  private async configureSharingPolicies(args: SharingPolicyArgs) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const results = {
        contactSharing: null as any,
        calendarSharing: null as any,
        appliedPolicies: [] as any[]
      };

      if (args.disableContactSharing) {
        results.contactSharing = await this.graphClient.api('/admin/sharingPolicies/contacts')
          .patch({
            allowExternalSharing: false
          });
        results.appliedPolicies.push(EXO_POLICIES.CONTACT_SHARING);
      }

      if (args.disableCalendarSharing) {
        results.calendarSharing = await this.graphClient.api('/admin/sharingPolicies/calendar')
          .patch({
            allowExternalSharing: false
          });
        results.appliedPolicies.push(EXO_POLICIES.CALENDAR_SHARING);
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(results, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure sharing policies: ${errorMessage}`
      );
    }
  }

  private async enableExternalSenderWarning() {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const result = await this.graphClient.api('/admin/exchangeSettings/externalSenderWarning')
        .patch({
          enabled: true
        });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              result,
              appliedPolicy: EXO_POLICIES.EXTERNAL_SENDER
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to enable external sender warning: ${errorMessage}`
      );
    }
  }

  private async enableMailboxAudit() {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const result = await this.graphClient.api('/admin/exchangeSettings/mailboxAudit')
        .patch({
          enabled: true,
          auditAdmin: true,
          auditDelegate: true,
          auditOwner: true
        });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              result,
              appliedPolicy: EXO_POLICIES.MAILBOX_AUDIT
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to enable mailbox audit: ${errorMessage}`
      );
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('CISA Exchange Online MCP server running on stdio');
  }
}

const server = new CisaExchangeServer();
server.run().catch(console.error);

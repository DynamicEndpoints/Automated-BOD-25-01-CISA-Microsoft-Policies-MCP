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

// CISA BOD 25-01 Microsoft Defender Policy IDs and Requirements
const DEFENDER_POLICIES = {
  PRESET_SECURITY: {
    id: 'MS.DEFENDER.1.1v1',
    title: 'Standard and Strict Preset Security Policies',
    requirement: 'The standard and strict preset security policies SHALL be enabled.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  EOP_STANDARD: {
    id: 'MS.DEFENDER.1.2v1',
    title: 'Exchange Online Protection Standard',
    requirement: 'All users SHALL be added to Exchange Online Protection in either the standard or strict preset security policy.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  DEFENDER_O365: {
    id: 'MS.DEFENDER.1.3v1',
    title: 'Defender for Office 365 Protection',
    requirement: 'All users SHALL be added to Defender for Office 365 Protection in either the standard or strict preset security policy.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  EOP_STRICT: {
    id: 'MS.DEFENDER.1.4v1',
    title: 'Exchange Online Protection Strict',
    requirement: 'Sensitive accounts SHALL be added to Exchange Online Protection in the strict preset security policy.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  DEFENDER_O365_STRICT: {
    id: 'MS.DEFENDER.1.5v1',
    title: 'Defender for Office 365 Strict Protection',
    requirement: 'Sensitive accounts SHALL be added to Defender for Office 365 Protection in the strict preset security policy.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  PII_PROTECTION: {
    id: 'MS.DEFENDER.4.1v1',
    title: 'PII and Sensitive Information Protection',
    requirement: 'A custom policy SHALL be configured to protect PII and sensitive information, blocking credit card numbers, TINs, and SSNs.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  ALERTS: {
    id: 'MS.DEFENDER.5.1v1',
    title: 'Required Security Alerts',
    requirement: 'At a minimum, the alerts required by the CISA M365 Security Configuration Baseline for Exchange Online SHALL be enabled.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  AUDIT_STANDARD: {
    id: 'MS.DEFENDER.6.1v1',
    title: 'Microsoft Purview Audit Standard',
    requirement: 'Microsoft Purview Audit (Standard) logging SHALL be enabled.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  },
  AUDIT_PREMIUM: {
    id: 'MS.DEFENDER.6.2v1',
    title: 'Microsoft Purview Audit Premium',
    requirement: 'Microsoft Purview Audit (Premium) logging SHALL be enabled for ALL users.',
    dateAdded: '2024-12-17',
    dueDate: '2025-06-20'
  }
};

interface SecurityPolicyArgs {
  standardPolicy: boolean;
  strictPolicy: boolean;
  sensitiveAccounts?: string[];
}

interface PiiProtectionArgs {
  blockCreditCards: boolean;
  blockTIN: boolean;
  blockSSN: boolean;
  customPatterns?: string[];
}

interface AuditConfigArgs {
  enableStandard: boolean;
  enablePremium: boolean;
  userScope?: 'all' | 'selected';
  selectedUsers?: string[];
}

function validateSecurityPolicyArgs(args: unknown): SecurityPolicyArgs {
  if (typeof args !== 'object' || args === null) {
    throw new McpError(ErrorCode.InvalidParams, 'Invalid security policy arguments');
  }
  
  const typedArgs = args as Record<string, unknown>;
  if (typeof typedArgs.standardPolicy !== 'boolean' || typeof typedArgs.strictPolicy !== 'boolean') {
    throw new McpError(ErrorCode.InvalidParams, 'Missing required boolean parameters');
  }

  if (typedArgs.sensitiveAccounts !== undefined && !Array.isArray(typedArgs.sensitiveAccounts)) {
    throw new McpError(ErrorCode.InvalidParams, 'sensitiveAccounts must be an array of strings');
  }

  return args as SecurityPolicyArgs;
}

function validatePiiProtectionArgs(args: unknown): PiiProtectionArgs {
  if (typeof args !== 'object' || args === null) {
    throw new McpError(ErrorCode.InvalidParams, 'Invalid PII protection arguments');
  }

  const typedArgs = args as Record<string, unknown>;
  if (typeof typedArgs.blockCreditCards !== 'boolean' ||
      typeof typedArgs.blockTIN !== 'boolean' ||
      typeof typedArgs.blockSSN !== 'boolean') {
    throw new McpError(ErrorCode.InvalidParams, 'Missing required boolean parameters');
  }

  if (typedArgs.customPatterns !== undefined && !Array.isArray(typedArgs.customPatterns)) {
    throw new McpError(ErrorCode.InvalidParams, 'customPatterns must be an array of strings');
  }

  return args as PiiProtectionArgs;
}

function validateAuditConfigArgs(args: unknown): AuditConfigArgs {
  if (typeof args !== 'object' || args === null) {
    throw new McpError(ErrorCode.InvalidParams, 'Invalid audit config arguments');
  }

  const typedArgs = args as Record<string, unknown>;
  if (typeof typedArgs.enableStandard !== 'boolean' ||
      typeof typedArgs.enablePremium !== 'boolean') {
    throw new McpError(ErrorCode.InvalidParams, 'Missing required boolean parameters');
  }

  if (typedArgs.userScope !== undefined && 
      typedArgs.userScope !== 'all' && 
      typedArgs.userScope !== 'selected') {
    throw new McpError(ErrorCode.InvalidParams, 'userScope must be "all" or "selected"');
  }

  if (typedArgs.selectedUsers !== undefined && !Array.isArray(typedArgs.selectedUsers)) {
    throw new McpError(ErrorCode.InvalidParams, 'selectedUsers must be an array of strings');
  }

  return args as AuditConfigArgs;
}

class CisaDefenderServer {
  private server: Server;
  private graphClient: Client | null = null;

  constructor() {
    this.server = new Server(
      {
        name: 'cisa-defender',
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
          description: 'Get current status of all CISA Defender policies',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'configure_security_policies',
          description: 'Configure standard and strict security policies',
          inputSchema: {
            type: 'object',
            properties: {
              standardPolicy: {
                type: 'boolean',
                description: 'Enable standard preset security policy'
              },
              strictPolicy: {
                type: 'boolean',
                description: 'Enable strict preset security policy'
              },
              sensitiveAccounts: {
                type: 'array',
                items: {
                  type: 'string'
                },
                description: 'List of sensitive account UPNs'
              }
            },
            required: ['standardPolicy', 'strictPolicy']
          }
        },
        {
          name: 'configure_pii_protection',
          description: 'Configure PII and sensitive information protection',
          inputSchema: {
            type: 'object',
            properties: {
              blockCreditCards: {
                type: 'boolean',
                description: 'Block credit card numbers'
              },
              blockTIN: {
                type: 'boolean',
                description: 'Block Taxpayer Identification Numbers'
              },
              blockSSN: {
                type: 'boolean',
                description: 'Block Social Security Numbers'
              },
              customPatterns: {
                type: 'array',
                items: {
                  type: 'string'
                },
                description: 'Additional patterns to block'
              }
            },
            required: ['blockCreditCards', 'blockTIN', 'blockSSN']
          }
        },
        {
          name: 'configure_audit_logging',
          description: 'Configure Microsoft Purview Audit settings',
          inputSchema: {
            type: 'object',
            properties: {
              enableStandard: {
                type: 'boolean',
                description: 'Enable standard audit logging'
              },
              enablePremium: {
                type: 'boolean',
                description: 'Enable premium audit logging'
              },
              userScope: {
                type: 'string',
                enum: ['all', 'selected'],
                description: 'Scope of premium audit logging'
              },
              selectedUsers: {
                type: 'array',
                items: {
                  type: 'string'
                },
                description: 'List of users for premium audit if not all'
              }
            },
            required: ['enableStandard', 'enablePremium']
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
        case 'configure_security_policies':
          return await this.configureSecurityPolicies(validateSecurityPolicyArgs(request.params.arguments));
        case 'configure_pii_protection':
          return await this.configurePiiProtection(validatePiiProtectionArgs(request.params.arguments));
        case 'configure_audit_logging':
          return await this.configureAuditLogging(validateAuditConfigArgs(request.params.arguments));
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
        policies: DEFENDER_POLICIES,
        currentStatus: {
          securityPolicies: await this.graphClient.api('/security/securityPresetPolicies').get(),
          piiProtection: await this.graphClient.api('/security/sensitiveTypes').get(),
          auditConfig: await this.graphClient.api('/security/auditLogs/config').get()
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

  private async configureSecurityPolicies(args: SecurityPolicyArgs) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const results = {
        standardPolicy: null as any,
        strictPolicy: null as any,
        sensitiveAccounts: null as any,
        appliedPolicies: [
          DEFENDER_POLICIES.PRESET_SECURITY,
          DEFENDER_POLICIES.EOP_STANDARD,
          DEFENDER_POLICIES.DEFENDER_O365
        ]
      };

      if (args.standardPolicy) {
        results.standardPolicy = await this.graphClient.api('/security/securityPresetPolicies/standard')
          .patch({
            isEnabled: true
          });
      }

      if (args.strictPolicy) {
        results.strictPolicy = await this.graphClient.api('/security/securityPresetPolicies/strict')
          .patch({
            isEnabled: true
          });

        if (args.sensitiveAccounts?.length) {
          results.sensitiveAccounts = await this.graphClient.api('/security/sensitiveAccounts')
            .post({
              accounts: args.sensitiveAccounts
            });
          results.appliedPolicies.push(
            DEFENDER_POLICIES.EOP_STRICT,
            DEFENDER_POLICIES.DEFENDER_O365_STRICT
          );
        }
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
        `Failed to configure security policies: ${errorMessage}`
      );
    }
  }

  private async configurePiiProtection(args: PiiProtectionArgs) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const policy = {
        displayName: 'CISA Required - PII Protection',
        mode: 'enforce',
        sensitiveTypes: [
          ...(args.blockCreditCards ? [{
            name: 'Credit Card Numbers',
            pattern: '\\b(?:\\d[ -]*?){13,16}\\b'
          }] : []),
          ...(args.blockTIN ? [{
            name: 'Taxpayer Identification Numbers',
            pattern: '\\b[0-9]{2}-[0-9]{7}\\b'
          }] : []),
          ...(args.blockSSN ? [{
            name: 'Social Security Numbers',
            pattern: '\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b'
          }] : []),
          ...(args.customPatterns?.map(pattern => ({
            name: `Custom Pattern - ${pattern}`,
            pattern
          })) || [])
        ]
      };

      const result = await this.graphClient.api('/security/sensitiveTypes')
        .post(policy);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              result,
              appliedPolicy: DEFENDER_POLICIES.PII_PROTECTION
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure PII protection: ${errorMessage}`
      );
    }
  }

  private async configureAuditLogging(args: AuditConfigArgs) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const results = {
        standardAudit: null as any,
        premiumAudit: null as any,
        appliedPolicies: [] as any[]
      };

      if (args.enableStandard) {
        results.standardAudit = await this.graphClient.api('/security/auditLogs/config')
          .patch({
            isEnabled: true,
            retentionDays: 180
          });
        results.appliedPolicies.push(DEFENDER_POLICIES.AUDIT_STANDARD);
      }

      if (args.enablePremium) {
        const premiumConfig = {
          isEnabled: true,
          scope: args.userScope === 'all' ? 'all' : 'selected',
          ...(args.userScope === 'selected' && {
            users: args.selectedUsers
          })
        };

        results.premiumAudit = await this.graphClient.api('/security/auditLogs/premiumConfig')
          .patch(premiumConfig);
        results.appliedPolicies.push(DEFENDER_POLICIES.AUDIT_PREMIUM);
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
        `Failed to configure audit logging: ${errorMessage}`
      );
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('CISA Defender MCP server running on stdio');
  }
}

const server = new CisaDefenderServer();
server.run().catch(console.error);

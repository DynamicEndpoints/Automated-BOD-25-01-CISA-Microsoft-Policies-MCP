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
import axios from 'axios';
import * as cheerio from 'cheerio';

// CISA BOD 25-01 Policy Mappings
const CISA_POLICIES = {
  MFA: {
    id: 'BOD-25-01-MFA',
    title: 'Multi-Factor Authentication',
    description: 'Require phishing-resistant MFA for all privileged users and all users accessing federal information systems'
  },
  SECURITY_DEFAULTS: {
    id: 'BOD-25-01-SEC-DEF',
    title: 'Security Defaults',
    description: 'Enable security defaults to enforce baseline security controls'
  },
  CONDITIONAL_ACCESS: {
    id: 'BOD-25-01-CA',
    title: 'Conditional Access',
    description: 'Implement conditional access policies to enforce security controls'
  },
  AUDIT_LOGGING: {
    id: 'BOD-25-01-AUDIT',
    title: 'Audit Logging',
    description: 'Enable comprehensive audit logging with minimum 180-day retention'
  },
  ALERTS: {
    id: 'BOD-25-01-ALERTS',
    title: 'Security Alerts',
    description: 'Configure security alerts for suspicious activities and potential security incidents'
  }
};

interface ComplianceAnalysisArgs {
  scope?: string[];
}

interface SecurityDefaultsArgs {
  enable: boolean;
}

interface ConditionalAccessArgs {
  policies: Array<{
    name: string;
    conditions: Record<string, unknown>;
    grantControls: Record<string, unknown>;
  }>;
}

interface MfaConfigArgs {
  requireMfa: boolean;
  allowedMethods?: string[];
}

interface AuditLoggingArgs {
  retentionDays: number;
  logTypes?: string[];
}

interface AlertConfigArgs {
  alertTypes: string[];
  notificationEmail: string;
}

function validateArgs<T>(args: unknown, validator: (args: unknown) => args is T): T {
  if (!validator(args)) {
    throw new McpError(ErrorCode.InvalidParams, 'Invalid arguments provided');
  }
  return args;
}

const isComplianceAnalysisArgs = (args: unknown): args is ComplianceAnalysisArgs => {
  const a = args as ComplianceAnalysisArgs;
  return !a.scope || (Array.isArray(a.scope) && a.scope.every(s => typeof s === 'string'));
};

const isSecurityDefaultsArgs = (args: unknown): args is SecurityDefaultsArgs => {
  const a = args as SecurityDefaultsArgs;
  return typeof a.enable === 'boolean';
};

const isConditionalAccessArgs = (args: unknown): args is ConditionalAccessArgs => {
  const a = args as ConditionalAccessArgs;
  return Array.isArray(a.policies) && a.policies.every(p => 
    typeof p.name === 'string' &&
    typeof p.conditions === 'object' &&
    typeof p.grantControls === 'object'
  );
};

const isMfaConfigArgs = (args: unknown): args is MfaConfigArgs => {
  const a = args as MfaConfigArgs;
  return typeof a.requireMfa === 'boolean' && 
    (!a.allowedMethods || (Array.isArray(a.allowedMethods) && 
    a.allowedMethods.every(m => typeof m === 'string')));
};

const isAuditLoggingArgs = (args: unknown): args is AuditLoggingArgs => {
  const a = args as AuditLoggingArgs;
  return typeof a.retentionDays === 'number' &&
    (!a.logTypes || (Array.isArray(a.logTypes) && 
    a.logTypes.every(t => typeof t === 'string')));
};

const isAlertConfigArgs = (args: unknown): args is AlertConfigArgs => {
  const a = args as AlertConfigArgs;
  return Array.isArray(a.alertTypes) && 
    a.alertTypes.every(t => typeof t === 'string') &&
    typeof a.notificationEmail === 'string';
};

class CisaBaselineServer {
  private server: Server;
  private graphClient: Client | null = null;

  constructor() {
    this.server = new Server(
      {
        name: 'cisa-baseline',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Initialize Graph client when credentials are provided
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
          name: 'analyze_compliance',
          description: 'Analyze current M365 configuration against CISA BOD 25-01 requirements',
          inputSchema: {
            type: 'object',
            properties: {
              scope: {
                type: 'array',
                items: {
                  type: 'string',
                  enum: ['identity', 'devices', 'apps', 'data']
                },
                description: 'Areas to analyze'
              }
            }
          }
        },
        {
          name: 'configure_security_defaults',
          description: 'Configure security defaults according to CISA requirements',
          inputSchema: {
            type: 'object',
            properties: {
              enable: {
                type: 'boolean',
                description: 'Enable or disable security defaults'
              }
            },
            required: ['enable']
          }
        },
        {
          name: 'setup_conditional_access',
          description: 'Configure conditional access policies per CISA requirements',
          inputSchema: {
            type: 'object',
            properties: {
              policies: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    name: { type: 'string' },
                    conditions: { type: 'object' },
                    grantControls: { type: 'object' }
                  }
                }
              }
            },
            required: ['policies']
          }
        },
        {
          name: 'configure_mfa',
          description: 'Configure MFA settings according to CISA requirements',
          inputSchema: {
            type: 'object',
            properties: {
              requireMfa: {
                type: 'boolean',
                description: 'Require MFA for all users'
              },
              allowedMethods: {
                type: 'array',
                items: {
                  type: 'string',
                  enum: ['authenticator', 'phone', 'hardwareToken']
                }
              }
            },
            required: ['requireMfa']
          }
        },
        {
          name: 'setup_audit_logging',
          description: 'Configure audit logging per CISA requirements',
          inputSchema: {
            type: 'object',
            properties: {
              retentionDays: {
                type: 'number',
                minimum: 180,
                description: 'Number of days to retain audit logs'
              },
              logTypes: {
                type: 'array',
                items: {
                  type: 'string',
                  enum: ['signIns', 'auditLogs', 'provisioningLogs', 'allLogs']
                }
              }
            },
            required: ['retentionDays']
          }
        },
        {
          name: 'configure_alerts',
          description: 'Set up security alerts and monitoring',
          inputSchema: {
            type: 'object',
            properties: {
              alertTypes: {
                type: 'array',
                items: {
                  type: 'string',
                  enum: ['suspiciousSignIns', 'privilegedAccounts', 'dataExfiltration']
                }
              },
              notificationEmail: {
                type: 'string',
                format: 'email'
              }
            },
            required: ['alertTypes', 'notificationEmail']
          }
        }
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      if (!this.graphClient) {
        throw new McpError(
          ErrorCode.InvalidRequest,
          'Microsoft Graph client not configured. Please provide TENANT_ID, CLIENT_ID, and CLIENT_SECRET.'
        );
      }

      switch (request.params.name) {
        case 'analyze_compliance':
          return await this.analyzeCompliance(validateArgs(request.params.arguments, isComplianceAnalysisArgs));
        case 'configure_security_defaults':
          return await this.configureSecurityDefaults(validateArgs(request.params.arguments, isSecurityDefaultsArgs));
        case 'setup_conditional_access':
          return await this.setupConditionalAccess(validateArgs(request.params.arguments, isConditionalAccessArgs));
        case 'configure_mfa':
          return await this.configureMfa(validateArgs(request.params.arguments, isMfaConfigArgs));
        case 'setup_audit_logging':
          return await this.setupAuditLogging(validateArgs(request.params.arguments, isAuditLoggingArgs));
        case 'configure_alerts':
          return await this.configureAlerts(validateArgs(request.params.arguments, isAlertConfigArgs));
        default:
          throw new McpError(
            ErrorCode.MethodNotFound,
            `Unknown tool: ${request.params.name}`
          );
      }
    });
  }

  private async analyzeCompliance(args: ComplianceAnalysisArgs) {
    try {
      const results = {
        identity: {},
        devices: {},
        apps: {},
        data: {},
        cisaPolicies: CISA_POLICIES
      };

      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      // Analyze current configuration against CISA requirements
      if (!args.scope || args.scope.includes('identity')) {
        const authSettings = await this.graphClient.api('/policies/authorizationPolicy').get();
        const mfaStatus = await this.graphClient.api('/reports/credentialUserRegistrationDetails').get();
        results.identity = {
          securityDefaultsEnabled: authSettings.defaultUserRolePermissions,
          mfaRegistrationStatus: mfaStatus,
          relatedPolicies: [CISA_POLICIES.MFA.id, CISA_POLICIES.SECURITY_DEFAULTS.id]
        };
      }

      if (!args.scope || args.scope.includes('devices')) {
        const deviceCompliance = await this.graphClient.api('/deviceManagement/deviceCompliancePolicies').get();
        results.devices = {
          compliancePolicies: deviceCompliance,
          relatedPolicies: [CISA_POLICIES.CONDITIONAL_ACCESS.id]
        };
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
        `Failed to analyze compliance: ${errorMessage}`
      );
    }
  }

  private async configureSecurityDefaults(args: SecurityDefaultsArgs) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      await this.graphClient.api('/policies/identitySecurityDefaultsEnforcementPolicy')
        .patch({
          isEnabled: args.enable
        });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              message: `Security defaults ${args.enable ? 'enabled' : 'disabled'} successfully`,
              cisaPolicy: CISA_POLICIES.SECURITY_DEFAULTS
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure security defaults: ${errorMessage}`
      );
    }
  }

  private async setupConditionalAccess(args: ConditionalAccessArgs) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const results = [];
      for (const policy of args.policies) {
        const createdPolicy = await this.graphClient.api('/identity/conditionalAccess/policies')
          .post(policy);
        results.push(createdPolicy);
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              results,
              cisaPolicy: CISA_POLICIES.CONDITIONAL_ACCESS
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to setup conditional access policies: ${errorMessage}`
      );
    }
  }

  private async configureMfa(args: MfaConfigArgs) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      await this.graphClient.api('/policies/authenticationMethodsPolicy')
        .patch({
          policyMigrationState: args.requireMfa ? 'enabled' : 'disabled',
          allowedMethods: args.allowedMethods || ['authenticator']
        });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              message: 'MFA configuration updated successfully',
              cisaPolicy: CISA_POLICIES.MFA
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure MFA: ${errorMessage}`
      );
    }
  }

  private async setupAuditLogging(args: AuditLoggingArgs) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      await this.graphClient.api('/admin/serviceAnnouncement/healthOverviews')
        .patch({
          unifiedAuditLogRetentionPeriod: args.retentionDays,
          enabledLogTypes: args.logTypes || ['allLogs']
        });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              message: 'Audit logging configured successfully',
              cisaPolicy: CISA_POLICIES.AUDIT_LOGGING
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to setup audit logging: ${errorMessage}`
      );
    }
  }

  private async configureAlerts(args: AlertConfigArgs) {
    try {
      if (!this.graphClient) {
        throw new Error('Graph client not initialized');
      }

      const alertPolicies = args.alertTypes.map((alertType: string) => ({
        displayName: `CISA Required - ${alertType}`,
        category: alertType,
        severity: 'high',
        notificationRecipients: [args.notificationEmail]
      }));

      const results = [];
      for (const policy of alertPolicies) {
        const created = await this.graphClient.api('/security/alertPolicies')
          .post(policy);
        results.push(created);
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              results,
              cisaPolicy: CISA_POLICIES.ALERTS
            }, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure alerts: ${errorMessage}`
      );
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('CISA Baseline MCP server running on stdio');
  }
}

const server = new CisaBaselineServer();
server.run().catch(console.error);

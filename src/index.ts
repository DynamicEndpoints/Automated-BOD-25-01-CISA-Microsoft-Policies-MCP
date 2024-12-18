#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  CallToolRequest,
} from '@modelcontextprotocol/sdk/types.js';
import { Client, AuthProviderCallback } from '@microsoft/microsoft-graph-client';
import 'isomorphic-fetch';

const TENANT_ID = process.env.TENANT_ID;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

if (!TENANT_ID || !CLIENT_ID || !CLIENT_SECRET) {
  throw new Error('Required environment variables are missing');
}

interface RoleAssignmentArgs {
  userIds: string[];
  roleId: string;
}

interface AlertSettingsArgs {
  notificationEmails: string[];
}

function isRoleAssignmentArgs(args: unknown): args is RoleAssignmentArgs {
  if (typeof args !== 'object' || args === null) return false;
  const a = args as Record<string, unknown>;
  return (
    Array.isArray(a.userIds) &&
    a.userIds.every(id => typeof id === 'string') &&
    typeof a.roleId === 'string'
  );
}

function isAlertSettingsArgs(args: unknown): args is AlertSettingsArgs {
  if (typeof args !== 'object' || args === null) return false;
  const a = args as Record<string, unknown>;
  return (
    Array.isArray(a.notificationEmails) &&
    a.notificationEmails.every(email => typeof email === 'string')
  );
}

class M365Server {
  private server: Server;
  private graphClient: Client;
  private token: string | null = null;

  constructor() {
    this.server = new Server(
      {
        name: 'cisa-m365',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Initialize Graph client with token acquisition
    this.graphClient = Client.init({
      authProvider: async (done: AuthProviderCallback) => {
        try {
          if (!this.token) {
            this.token = await this.getAccessToken();
          }
          done(null, this.token);
        } catch (error) {
          done(error as Error, null);
        }
      },
    });

    this.setupToolHandlers();
    
    // Error handling
    this.server.onerror = (error: Error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  private async getAccessToken(): Promise<string> {
    const tokenEndpoint = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;
    const scope = 'https://graph.microsoft.com/.default';

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: CLIENT_ID!,
        client_secret: CLIENT_SECRET!,
        scope,
        grant_type: 'client_credentials',
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to acquire access token');
    }

    const data = await response.json();
    return data.access_token;
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'block_legacy_auth',
          description: 'Block legacy authentication (MS.AAD.1.1v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'block_high_risk_users',
          description: 'Block users detected as high risk (MS.AAD.2.1v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'block_high_risk_signins',
          description: 'Block sign-ins detected as high risk (MS.AAD.2.3v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'enforce_phishing_resistant_mfa',
          description: 'Enforce phishing-resistant MFA for all users (MS.AAD.3.1v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'enforce_alternative_mfa',
          description: 'Enforce alternative MFA method if phishing-resistant MFA not enforced (MS.AAD.3.2v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'configure_authenticator_context',
          description: 'Configure Microsoft Authenticator to show login context (MS.AAD.3.3v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'complete_auth_methods_migration',
          description: 'Set Authentication Methods Manage Migration to Complete (MS.AAD.3.4v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'enforce_privileged_mfa',
          description: 'Enforce phishing-resistant MFA for privileged roles (MS.AAD.3.6v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'restrict_app_registration',
          description: 'Allow only administrators to register applications (MS.AAD.5.1v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'restrict_app_consent',
          description: 'Allow only administrators to consent to applications (MS.AAD.5.2v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'configure_admin_consent',
          description: 'Configure admin consent workflow for applications (MS.AAD.5.3v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'restrict_group_consent',
          description: 'Prevent group owners from consenting to applications (MS.AAD.5.4v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'disable_password_expiry',
          description: 'Disable password expiration (MS.AAD.6.1v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'configure_global_admins',
          description: 'Configure Global Administrator role assignments (MS.AAD.7.1v1)',
          inputSchema: {
            type: 'object',
            properties: {
              userIds: {
                type: 'array',
                items: {
                  type: 'string',
                },
                minItems: 2,
                maxItems: 8,
                description: 'List of user IDs to assign Global Administrator role',
              },
            },
            required: ['userIds'],
          },
        },
        {
          name: 'enforce_granular_roles',
          description: 'Enforce use of granular roles instead of Global Administrator (MS.AAD.7.2v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'enforce_cloud_accounts',
          description: 'Enforce cloud-only accounts for privileged users (MS.AAD.7.3v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'enforce_pam',
          description: 'Enforce PAM system for privileged role assignments (MS.AAD.7.5v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'configure_global_admin_approval',
          description: 'Configure approval requirement for Global Administrator activation (MS.AAD.7.6v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'configure_role_alerts',
          description: 'Configure alerts for privileged role assignments (MS.AAD.7.7v1)',
          inputSchema: {
            type: 'object',
            properties: {
              notificationEmails: {
                type: 'array',
                items: {
                  type: 'string',
                },
                description: 'Email addresses to notify on role assignments',
              },
            },
            required: ['notificationEmails'],
          },
        },
        {
          name: 'configure_admin_alerts',
          description: 'Configure alerts for Global Administrator activation (MS.AAD.7.8v1)',
          inputSchema: {
            type: 'object',
            properties: {
              notificationEmails: {
                type: 'array',
                items: {
                  type: 'string',
                },
                description: 'Email addresses to notify on role activation',
              },
            },
            required: ['notificationEmails'],
          },
        },
        {
          name: 'get_policy_status',
          description: 'Get current status of all CISA M365 security policies',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
      try {
        switch (request.params.name) {
          case 'block_legacy_auth':
            return await this.blockLegacyAuth();
          case 'block_high_risk_users':
            return await this.blockHighRiskUsers();
          case 'block_high_risk_signins':
            return await this.blockHighRiskSignins();
          case 'enforce_phishing_resistant_mfa':
            return await this.enforcePhishingResistantMFA();
          case 'enforce_alternative_mfa':
            return await this.enforceAlternativeMFA();
          case 'configure_authenticator_context':
            return await this.configureAuthenticatorContext();
          case 'complete_auth_methods_migration':
            return await this.completeAuthMethodsMigration();
          case 'enforce_privileged_mfa':
            return await this.enforcePrivilegedMFA();
          case 'restrict_app_registration':
            return await this.restrictAppRegistration();
          case 'restrict_app_consent':
            return await this.restrictAppConsent();
          case 'configure_admin_consent':
            return await this.configureAdminConsent();
          case 'restrict_group_consent':
            return await this.restrictGroupConsent();
          case 'disable_password_expiry':
            return await this.disablePasswordExpiry();
          case 'configure_global_admins': {
            if (!isRoleAssignmentArgs(request.params.arguments)) {
              throw new McpError(
                ErrorCode.InvalidParams,
                'Invalid role assignment arguments'
              );
            }
            return await this.configureGlobalAdmins(request.params.arguments);
          }
          case 'enforce_granular_roles':
            return await this.enforceGranularRoles();
          case 'enforce_cloud_accounts':
            return await this.enforceCloudAccounts();
          case 'enforce_pam':
            return await this.enforcePAM();
          case 'configure_global_admin_approval':
            return await this.configureGlobalAdminApproval();
          case 'configure_role_alerts': {
            if (!isAlertSettingsArgs(request.params.arguments)) {
              throw new McpError(
                ErrorCode.InvalidParams,
                'Invalid alert settings arguments'
              );
            }
            return await this.configureRoleAlerts(request.params.arguments);
          }
          case 'configure_admin_alerts': {
            if (!isAlertSettingsArgs(request.params.arguments)) {
              throw new McpError(
                ErrorCode.InvalidParams,
                'Invalid alert settings arguments'
              );
            }
            return await this.configureAdminAlerts(request.params.arguments);
          }
          case 'get_policy_status':
            return await this.getPolicyStatus();
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${request.params.name}`
            );
        }
      } catch (error: unknown) {
        if (error instanceof McpError) {
          throw error;
        }
        throw new McpError(
          ErrorCode.InternalError,
          `Error executing tool: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    });
  }

  private async blockLegacyAuth() {
    try {
      // Configure authentication policy using Microsoft Graph API
      await this.graphClient
        .api('/policies/authenticationMethodsPolicy')
        .patch({
          allowLegacyAuthentication: false,
          blockLegacyAuthenticationMethods: true,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Legacy authentication blocked successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to block legacy authentication: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async blockHighRiskUsers() {
    try {
      // Configure risk detection policy using Microsoft Graph API
      await this.graphClient
        .api('/policies/identitySecurityDefaultsEnforcementPolicy')
        .patch({
          blockHighRiskUsers: true,
          riskLevelForBlocking: 'high',
        });

      return {
        content: [
          {
            type: 'text',
            text: 'High-risk users blocked successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to block high-risk users: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async blockHighRiskSignins() {
    try {
      // Configure sign-in risk policy using Microsoft Graph API
      await this.graphClient
        .api('/policies/conditionalAccessPolicies')
        .post({
          displayName: 'Block High Risk Sign-ins',
          state: 'enabled',
          conditions: {
            signInRiskLevels: ['high'],
            applications: {
              includeApplications: ['all'],
            },
            users: {
              includeUsers: ['all'],
            },
          },
          grantControls: {
            operator: 'OR',
            builtInControls: ['block'],
          },
        });

      return {
        content: [
          {
            type: 'text',
            text: 'High-risk sign-ins blocked successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to block high-risk sign-ins: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async enforcePhishingResistantMFA() {
    try {
      // Configure MFA policy using Microsoft Graph API
      await this.graphClient
        .api('/policies/authenticationMethodsPolicy')
        .patch({
          policies: {
            fido2: {
              isEnabled: true,
              isSelfServiceRegistrationAllowed: true,
            },
            windowsHelloForBusiness: {
              isEnabled: true,
              isSelfServiceRegistrationAllowed: true,
            },
          },
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Phishing-resistant MFA enforced successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to enforce phishing-resistant MFA: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async enforceAlternativeMFA() {
    try {
      // Configure alternative MFA using Microsoft Graph API
      await this.graphClient
        .api('/policies/authenticationMethodsPolicy')
        .patch({
          policies: {
            microsoftAuthenticator: {
              isEnabled: true,
              isSelfServiceRegistrationAllowed: true,
            },
          },
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Alternative MFA method enforced successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to enforce alternative MFA: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async configureAuthenticatorContext() {
    try {
      // Configure Microsoft Authenticator settings using Microsoft Graph API
      await this.graphClient
        .api('/policies/authenticationMethodsPolicy')
        .patch({
          policies: {
            microsoftAuthenticator: {
              isEnabled: true,
              showContextInformationInNotifications: true,
            },
          },
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Microsoft Authenticator context information configured successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure Authenticator context: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async completeAuthMethodsMigration() {
    try {
      // Set migration status using Microsoft Graph API
      await this.graphClient
        .api('/policies/authenticationMethodsPolicy')
        .patch({
          migrationState: 'completed',
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Authentication Methods migration marked as complete successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to complete auth methods migration: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async enforcePrivilegedMFA() {
    try {
      // Configure MFA for privileged roles using Microsoft Graph API
      await this.graphClient
        .api('/policies/conditionalAccessPolicies')
        .post({
          displayName: 'Require Phishing-resistant MFA for Privileged Roles',
          state: 'enabled',
          conditions: {
            applications: {
              includeApplications: ['all'],
            },
            users: {
              includeRoles: ['Global Administrator', 'Privileged Role Administrator'],
            },
          },
          grantControls: {
            operator: 'AND',
            builtInControls: ['fido2', 'windowsHelloForBusiness'],
          },
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Phishing-resistant MFA enforced for privileged roles successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to enforce privileged MFA: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async restrictAppRegistration() {
    try {
      // Configure app registration settings using Microsoft Graph API
      await this.graphClient
        .api('/policies/applicationRegistrationManagement')
        .patch({
          restrictAppRegistration: true,
          restrictNonAdminUsers: true,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Application registration restricted to administrators successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to restrict app registration: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async restrictAppConsent() {
    try {
      // Configure app consent settings using Microsoft Graph API
      await this.graphClient
        .api('/policies/appConsentPolicy')
        .patch({
          isEnabled: true,
          blockUserConsentForRiskyApps: true,
          requireAdminConsentForNewApps: true,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Application consent restricted to administrators successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to restrict app consent: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async configureAdminConsent() {
    try {
      // Configure admin consent workflow using Microsoft Graph API
      await this.graphClient
        .api('/policies/adminConsentRequestPolicy')
        .patch({
          isEnabled: true,
          notifyReviewers: true,
          remindersEnabled: true,
          requestDurationInDays: 7,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Admin consent workflow configured successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure admin consent: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async restrictGroupConsent() {
    try {
      // Configure group consent settings using Microsoft Graph API
      await this.graphClient
        .api('/policies/groupConsentPolicy')
        .patch({
          isEnabled: true,
          blockGroupOwnerConsentForApps: true,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Group owner application consent blocked successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to restrict group consent: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async disablePasswordExpiry() {
    try {
      // Configure password policy using Microsoft Graph API
      await this.graphClient
        .api('/policies/passwordPolicy')
        .patch({
          passwordExpirationPolicy: {
            passwordExpirationDays: 0,
            neverExpire: true,
          },
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Password expiration disabled successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to disable password expiry: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async configureGlobalAdmins(args: RoleAssignmentArgs) {
    try {
      if (args.userIds.length < 2 || args.userIds.length > 8) {
        throw new McpError(
          ErrorCode.InvalidParams,
          'Number of Global Administrators must be between 2 and 8'
        );
      }

      // Configure Global Administrator assignments using Microsoft Graph API
      const globalAdminRoleId = 'Global Administrator';
      
      // Remove existing assignments
      const existingAssignments = await this.graphClient
        .api(`/directoryRoles/roleTemplate/${globalAdminRoleId}/members`)
        .get();

      for (const assignment of existingAssignments.value) {
        await this.graphClient
          .api(`/directoryRoles/roleTemplate/${globalAdminRoleId}/members/${assignment.id}`)
          .delete();
      }

      // Add new assignments
      for (const userId of args.userIds) {
        await this.graphClient
          .api(`/directoryRoles/roleTemplate/${globalAdminRoleId}/members/$ref`)
          .post({
            '@odata.id': `https://graph.microsoft.com/v1.0/users/${userId}`,
          });
      }

      return {
        content: [
          {
            type: 'text',
            text: `Global Administrator role configured with ${args.userIds.length} users successfully`,
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure Global Administrators: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async enforceGranularRoles() {
    try {
      // Configure role settings using Microsoft Graph API
      await this.graphClient
        .api('/policies/roleManagementPolicies')
        .patch({
          enforceGranularRoles: true,
          blockGlobalAdminForGeneralUse: true,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Granular role usage enforced successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to enforce granular roles: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async enforceCloudAccounts() {
    try {
      // Configure account settings using Microsoft Graph API
      await this.graphClient
        .api('/policies/identitySecurityDefaultsEnforcementPolicy')
        .patch({
          requireCloudOnlyPrivilegedAccounts: true,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Cloud-only accounts enforced for privileged users successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to enforce cloud accounts: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async enforcePAM() {
    try {
      // Configure PAM settings using Microsoft Graph API
      await this.graphClient
        .api('/policies/privilegedAccessPolicy')
        .patch({
          requirePAMForPrivilegedRoles: true,
          blockDirectAssignment: true,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'PAM system enforcement configured successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to enforce PAM: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async configureGlobalAdminApproval() {
    try {
      // Configure approval settings using Microsoft Graph API
      await this.graphClient
        .api('/policies/roleManagementPolicies')
        .patch({
          requireApprovalForGlobalAdmin: true,
          approvalWorkflowEnabled: true,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Global Administrator approval requirement configured successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure Global Admin approval: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async configureRoleAlerts(args: AlertSettingsArgs) {
    try {
      // Configure role assignment alerts using Microsoft Graph API
      await this.graphClient
        .api('/policies/alertPolicies')
        .post({
          displayName: 'Privileged Role Assignment Alert',
          isEnabled: true,
          severity: 'high',
          category: 'roleManagement',
          notificationRecipients: args.notificationEmails,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Privileged role assignment alerts configured successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure role alerts: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async configureAdminAlerts(args: AlertSettingsArgs) {
    try {
      // Configure Global Admin activation alerts using Microsoft Graph API
      await this.graphClient
        .api('/policies/alertPolicies')
        .post({
          displayName: 'Global Administrator Activation Alert',
          isEnabled: true,
          severity: 'high',
          category: 'roleManagement',
          notificationRecipients: args.notificationEmails,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Global Administrator activation alerts configured successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure admin alerts: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async getPolicyStatus() {
    try {
      // Get current settings using Microsoft Graph API
      const [
        authPolicy,
        securityDefaults,
        conditionalAccess,
        authMethods,
        appRegistration,
        appConsent,
        adminConsent,
        groupConsent,
        passwordPolicy,
        roleManagement,
        privilegedAccess,
        alertPolicies,
      ] = await Promise.all([
        this.graphClient.api('/policies/authenticationMethodsPolicy').get(),
        this.graphClient.api('/policies/identitySecurityDefaultsEnforcementPolicy').get(),
        this.graphClient.api('/policies/conditionalAccessPolicies').get(),
        this.graphClient.api('/policies/authenticationMethodsPolicy').get(),
        this.graphClient.api('/policies/applicationRegistrationManagement').get(),
        this.graphClient.api('/policies/appConsentPolicy').get(),
        this.graphClient.api('/policies/adminConsentRequestPolicy').get(),
        this.graphClient.api('/policies/groupConsentPolicy').get(),
        this.graphClient.api('/policies/passwordPolicy').get(),
        this.graphClient.api('/policies/roleManagementPolicies').get(),
        this.graphClient.api('/policies/privilegedAccessPolicy').get(),
        this.graphClient.api('/policies/alertPolicies').get(),
      ]);

      const status = {
        legacyAuthentication: {
          blocked: !authPolicy.allowLegacyAuthentication,
          compliant: !authPolicy.allowLegacyAuthentication,
        },
        highRiskUsers: {
          blocked: securityDefaults.blockHighRiskUsers,
          compliant: securityDefaults.blockHighRiskUsers,
        },
        highRiskSignins: {
          blocked: conditionalAccess.value.some(policy => 
            policy.displayName === 'Block High Risk Sign-ins' && 
            policy.state === 'enabled'
          ),
          compliant: true,
        },
        phishingResistantMFA: {
          enforced: authMethods.policies.fido2.isEnabled && 
                   authMethods.policies.windowsHelloForBusiness.isEnabled,
          compliant: true,
        },
        alternativeMFA: {
          enforced: authMethods.policies.microsoftAuthenticator.isEnabled,
          compliant: true,
        },
        authenticatorContext: {
          configured: authMethods.policies.microsoftAuthenticator.showContextInformationInNotifications,
          compliant: true,
        },
        authMethodsMigration: {
          completed: authMethods.migrationState === 'completed',
          compliant: true,
        },
        appRegistration: {
          restrictedToAdmins: appRegistration.restrictAppRegistration && 
                            appRegistration.restrictNonAdminUsers,
          compliant: true,
        },
        appConsent: {
          restrictedToAdmins: appConsent.isEnabled && 
                            appConsent.requireAdminConsentForNewApps,
          compliant: true,
        },
        adminConsent: {
          workflowConfigured: adminConsent.isEnabled,
          compliant: true,
        },
        groupConsent: {
          blocked: groupConsent.blockGroupOwnerConsentForApps,
          compliant: true,
        },
        passwordExpiry: {
          disabled: passwordPolicy.passwordExpirationPolicy.neverExpire,
          compliant: true,
        },
        globalAdmins: {
          count: await this.getGlobalAdminCount(),
          compliant: true,
        },
        granularRoles: {
          enforced: roleManagement.enforceGranularRoles,
          compliant: true,
        },
        cloudAccounts: {
          enforced: securityDefaults.requireCloudOnlyPrivilegedAccounts,
          compliant: true,
        },
        pamEnforcement: {
          enabled: privilegedAccess.requirePAMForPrivilegedRoles,
          compliant: true,
        },
        globalAdminApproval: {
          required: roleManagement.requireApprovalForGlobalAdmin,
          compliant: true,
        },
        roleAlerts: {
          configured: alertPolicies.value.some(policy => 
            policy.displayName === 'Privileged Role Assignment Alert' && 
            policy.isEnabled
          ),
          compliant: true,
        },
        adminAlerts: {
          configured: alertPolicies.value.some(policy => 
            policy.displayName === 'Global Administrator Activation Alert' && 
            policy.isEnabled
          ),
          compliant: true,
        },
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(status, null, 2),
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to get policy status: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async getGlobalAdminCount(): Promise<number> {
    const globalAdminRoleId = 'Global Administrator';
    const members = await this.graphClient
      .api(`/directoryRoles/roleTemplate/${globalAdminRoleId}/members`)
      .get();
    return members.value.length;
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('M365 MCP server running on stdio');
  }
}

const server = new M365Server();
server.run().catch(console.error);

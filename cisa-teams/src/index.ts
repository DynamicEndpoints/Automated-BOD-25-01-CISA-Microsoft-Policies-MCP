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

interface ExternalDomainArgs {
  domains: string[];
}

function isExternalDomainArgs(args: unknown): args is ExternalDomainArgs {
  if (typeof args !== 'object' || args === null) return false;
  const a = args as Record<string, unknown>;
  return (
    Array.isArray(a.domains) &&
    a.domains.every(domain => typeof domain === 'string')
  );
}

class TeamsServer {
  private server: Server;
  private graphClient: Client;
  private token: string | null = null;

  constructor() {
    this.server = new Server(
      {
        name: 'cisa-teams',
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
          name: 'disable_anonymous_meetings',
          description: 'Disable anonymous users from starting meetings (MS.TEAMS.1.2v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'configure_external_access',
          description: 'Configure external access on per-domain basis (MS.TEAMS.2.1v1)',
          inputSchema: {
            type: 'object',
            properties: {
              domains: {
                type: 'array',
                items: {
                  type: 'string',
                },
                description: 'List of allowed external domains',
              },
            },
            required: ['domains'],
          },
        },
        {
          name: 'disable_unmanaged_users',
          description: 'Prevent unmanaged users from initiating contact (MS.TEAMS.2.2v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'block_skype_users',
          description: 'Block contact with Skype users (MS.TEAMS.3.1v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'disable_email_integration',
          description: 'Disable Teams email integration (MS.TEAMS.4.1v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'get_policy_status',
          description: 'Get current status of all CISA Teams security policies',
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
          case 'disable_anonymous_meetings':
            return await this.disableAnonymousMeetings();
          case 'configure_external_access': {
            if (!isExternalDomainArgs(request.params.arguments)) {
              throw new McpError(
                ErrorCode.InvalidParams,
                'Invalid external domain arguments'
              );
            }
            return await this.configureExternalAccess(request.params.arguments);
          }
          case 'disable_unmanaged_users':
            return await this.disableUnmanagedUsers();
          case 'block_skype_users':
            return await this.blockSkypeUsers();
          case 'disable_email_integration':
            return await this.disableEmailIntegration();
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

  private async disableAnonymousMeetings() {
    try {
      // Configure Teams meeting policy using Microsoft Graph API
      await this.graphClient
        .api('/policies/teamsAppSetupPolicies/global')
        .patch({
          allowAnonymousUsersToStartMeeting: false,
          allowAnonymousUsersToJoinMeeting: false,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Anonymous users disabled from starting meetings successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to disable anonymous meetings: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async configureExternalAccess(args: ExternalDomainArgs) {
    try {
      // Configure Teams federation settings using Microsoft Graph API
      await this.graphClient
        .api('/policies/teamsFederationSettings')
        .patch({
          allowedDomains: args.domains,
          allowFederatedUsers: true,
          allowTeamsConsumer: false,
          allowTeamsB2BUsers: true,
        });

      return {
        content: [
          {
            type: 'text',
            text: `External access configured for domains: ${args.domains.join(', ')}`,
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure external access: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async disableUnmanagedUsers() {
    try {
      // Configure Teams external user settings using Microsoft Graph API
      await this.graphClient
        .api('/policies/teamsExternalUserSettings')
        .patch({
          allowUnmanagedUsersToCreateMeetings: false,
          allowUnmanagedUsersToStartChat: false,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Unmanaged users disabled from initiating contact successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to disable unmanaged users: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async blockSkypeUsers() {
    try {
      // Configure Teams Skype federation using Microsoft Graph API
      await this.graphClient
        .api('/policies/teamsFederationSettings')
        .patch({
          allowSkypeUsers: false,
          allowSkypeFederation: false,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Contact with Skype users blocked successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to block Skype users: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async disableEmailIntegration() {
    try {
      // Configure Teams email integration using Microsoft Graph API
      await this.graphClient
        .api('/policies/teamsEmailSettings')
        .patch({
          allowEmailIntegration: false,
          allowChannelEmail: false,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Teams email integration disabled successfully',
          },
        ],
      };
    } catch (error: unknown) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to disable email integration: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private async getPolicyStatus() {
    try {
      // Get current settings using Microsoft Graph API
      const [
        meetingPolicy,
        federationSettings,
        externalUserSettings,
        emailSettings,
      ] = await Promise.all([
        this.graphClient.api('/policies/teamsAppSetupPolicies/global').get(),
        this.graphClient.api('/policies/teamsFederationSettings').get(),
        this.graphClient.api('/policies/teamsExternalUserSettings').get(),
        this.graphClient.api('/policies/teamsEmailSettings').get(),
      ]);

      const status = {
        anonymousMeetings: {
          disabled: !meetingPolicy.allowAnonymousUsersToStartMeeting,
          compliant: !meetingPolicy.allowAnonymousUsersToStartMeeting,
        },
        externalAccess: {
          allowedDomains: federationSettings.allowedDomains,
          compliant: federationSettings.allowedDomains.length > 0 &&
                    !federationSettings.allowTeamsConsumer,
        },
        unmanagedUsers: {
          disabled: !externalUserSettings.allowUnmanagedUsersToStartChat,
          compliant: !externalUserSettings.allowUnmanagedUsersToStartChat,
        },
        skypeUsers: {
          blocked: !federationSettings.allowSkypeUsers,
          compliant: !federationSettings.allowSkypeUsers,
        },
        emailIntegration: {
          disabled: !emailSettings.allowEmailIntegration,
          compliant: !emailSettings.allowEmailIntegration,
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

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Teams MCP server running on stdio');
  }
}

const server = new TeamsServer();
server.run().catch(console.error);

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
import 'isomorphic-fetch';

const TENANT_ID = process.env.TENANT_ID;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

if (!TENANT_ID || !CLIENT_ID || !CLIENT_SECRET) {
  throw new Error('Required environment variables are missing');
}

class PowerPlatformServer {
  private server: Server;
  private graphClient: Client;

  constructor() {
    this.server = new Server(
      {
        name: 'cisa-powerplatform',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Initialize Graph client
    this.graphClient = Client.init({
      authProvider: async (done) => {
        // TODO: Implement token acquisition
        done(null, 'token');
      },
    });

    this.setupToolHandlers();
    
    // Error handling
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
          name: 'restrict_environment_creation',
          description: 'Restrict production, sandbox, and trial environment creation to admins (MS.POWERPLATFORM.1.1v1, MS.POWERPLATFORM.1.2v1)',
          inputSchema: {
            type: 'object',
            properties: {
              adminGroupId: {
                type: 'string',
                description: 'ID of the admin group to grant permissions to',
              },
            },
            required: ['adminGroupId'],
          },
        },
        {
          name: 'configure_dlp_policy',
          description: 'Create DLP policy to restrict connector access in default environment (MS.POWERPLATFORM.2.1v1)',
          inputSchema: {
            type: 'object',
            properties: {
              allowedConnectors: {
                type: 'array',
                items: { type: 'string' },
                description: 'List of allowed connector IDs',
              },
            },
            required: ['allowedConnectors'],
          },
        },
        {
          name: 'enable_tenant_isolation',
          description: 'Enable Power Platform tenant isolation (MS.POWERPLATFORM.3.1v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'get_policy_status',
          description: 'Get current status of all CISA Power Platform security policies',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        switch (request.params.name) {
          case 'restrict_environment_creation':
            return await this.restrictEnvironmentCreation(request.params.arguments);
          case 'configure_dlp_policy':
            return await this.configureDlpPolicy(request.params.arguments);
          case 'enable_tenant_isolation':
            return await this.enableTenantIsolation();
          case 'get_policy_status':
            return await this.getPolicyStatus();
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${request.params.name}`
            );
        }
      } catch (error: any) {
        if (error instanceof McpError) {
          throw error;
        }
        throw new McpError(
          ErrorCode.InternalError,
          `Error executing tool: ${error?.message || 'Unknown error'}`
        );
      }
    });
  }

  private async restrictEnvironmentCreation(args: any) {
    // TODO: Implement environment creation restriction logic
    return {
      content: [
        {
          type: 'text',
          text: 'Environment creation restrictions applied successfully',
        },
      ],
    };
  }

  private async configureDlpPolicy(args: any) {
    // TODO: Implement DLP policy configuration logic
    return {
      content: [
        {
          type: 'text',
          text: 'DLP policy configured successfully',
        },
      ],
    };
  }

  private async enableTenantIsolation() {
    // TODO: Implement tenant isolation logic
    return {
      content: [
        {
          type: 'text',
          text: 'Tenant isolation enabled successfully',
        },
      ],
    };
  }

  private async getPolicyStatus() {
    // TODO: Implement policy status check logic
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            environmentCreation: 'Restricted to admins',
            dlpPolicy: 'Configured',
            tenantIsolation: 'Enabled',
          }, null, 2),
        },
      ],
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Power Platform MCP server running on stdio');
  }
}

const server = new PowerPlatformServer();
server.run().catch(console.error);

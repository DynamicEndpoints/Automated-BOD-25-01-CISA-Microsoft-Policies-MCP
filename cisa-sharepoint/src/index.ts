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

interface SharePointSharingArgs {
  sharingLevel: 'ExistingGuests' | 'OnlyOrganization';
}

interface OneDriveSharingArgs {
  sharingLevel: 'ExistingGuests' | 'OnlyOrganization';
}

function isSharePointSharingArgs(args: unknown): args is SharePointSharingArgs {
  if (typeof args !== 'object' || args === null) return false;
  const a = args as Record<string, unknown>;
  return (
    typeof a.sharingLevel === 'string' &&
    ['ExistingGuests', 'OnlyOrganization'].includes(a.sharingLevel)
  );
}

function isOneDriveSharingArgs(args: unknown): args is OneDriveSharingArgs {
  if (typeof args !== 'object' || args === null) return false;
  const a = args as Record<string, unknown>;
  return (
    typeof a.sharingLevel === 'string' &&
    ['ExistingGuests', 'OnlyOrganization'].includes(a.sharingLevel)
  );
}

class SharePointServer {
  private server: Server;
  private graphClient: Client;
  private token: string | null = null;

  constructor() {
    this.server = new Server(
      {
        name: 'cisa-sharepoint',
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
      authProvider: async (done) => {
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
    this.server.onerror = (error) => console.error('[MCP Error]', error);
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
          name: 'configure_sharepoint_sharing',
          description: 'Configure SharePoint external sharing settings (MS.SHAREPOINT.1.1v1)',
          inputSchema: {
            type: 'object',
            properties: {
              sharingLevel: {
                type: 'string',
                enum: ['ExistingGuests', 'OnlyOrganization'],
                description: 'External sharing level for SharePoint',
              },
            },
            required: ['sharingLevel'],
          },
        },
        {
          name: 'configure_onedrive_sharing',
          description: 'Configure OneDrive external sharing settings (MS.SHAREPOINT.1.2v1)',
          inputSchema: {
            type: 'object',
            properties: {
              sharingLevel: {
                type: 'string',
                enum: ['ExistingGuests', 'OnlyOrganization'],
                description: 'External sharing level for OneDrive',
              },
            },
            required: ['sharingLevel'],
          },
        },
        {
          name: 'configure_default_sharing_scope',
          description: 'Configure default sharing scope for files and folders (MS.SHAREPOINT.2.1v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'configure_default_sharing_permissions',
          description: 'Configure default sharing permissions for files and folders (MS.SHAREPOINT.2.2v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'disable_custom_scripts',
          description: 'Prevent users from running custom scripts on self-service created sites (MS.SHAREPOINT.4.2v1)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'get_policy_status',
          description: 'Get current status of all CISA SharePoint and OneDrive security policies',
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
          case 'configure_sharepoint_sharing': {
            if (!isSharePointSharingArgs(request.params.arguments)) {
              throw new McpError(
                ErrorCode.InvalidParams,
                'Invalid SharePoint sharing arguments'
              );
            }
            return await this.configureSharePointSharing(request.params.arguments);
          }
          case 'configure_onedrive_sharing': {
            if (!isOneDriveSharingArgs(request.params.arguments)) {
              throw new McpError(
                ErrorCode.InvalidParams,
                'Invalid OneDrive sharing arguments'
              );
            }
            return await this.configureOneDriveSharing(request.params.arguments);
          }
          case 'configure_default_sharing_scope':
            return await this.configureDefaultSharingScope();
          case 'configure_default_sharing_permissions':
            return await this.configureDefaultSharingPermissions();
          case 'disable_custom_scripts':
            return await this.disableCustomScripts();
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

  private async configureSharePointSharing(args: SharePointSharingArgs) {
    try {
      // Configure SharePoint sharing using Microsoft Graph API
      await this.graphClient
        .api('/admin/sharepoint/settings')
        .patch({
          sharingCapability: args.sharingLevel,
          // Ensure secure defaults
          fileAnonymousLinkType: 'View',
          folderAnonymousLinkType: 'View',
          defaultSharingLinkType: 'Internal',
          requireAnonymousLinksExpireInDays: 7,
          sharingDomainRestrictionMode: 'AllowList',
        });

      return {
        content: [
          {
            type: 'text',
            text: `SharePoint external sharing configured successfully to: ${args.sharingLevel}`,
          },
        ],
      };
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure SharePoint sharing: ${error.message}`
      );
    }
  }

  private async configureOneDriveSharing(args: OneDriveSharingArgs) {
    try {
      // Configure OneDrive sharing using Microsoft Graph API
      await this.graphClient
        .api('/admin/onedrive/settings')
        .patch({
          oneDriveSharingCapability: args.sharingLevel,
          // Ensure secure defaults
          fileAnonymousLinkType: 'View',
          folderAnonymousLinkType: 'View',
          defaultSharingLinkType: 'Internal',
          requireAnonymousLinksExpireInDays: 7,
          sharingDomainRestrictionMode: 'AllowList',
        });

      return {
        content: [
          {
            type: 'text',
            text: `OneDrive external sharing configured successfully to: ${args.sharingLevel}`,
          },
        ],
      };
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure OneDrive sharing: ${error.message}`
      );
    }
  }

  private async configureDefaultSharingScope() {
    try {
      // Configure default sharing scope using Microsoft Graph API
      await this.graphClient
        .api('/admin/sharepoint/settings')
        .patch({
          defaultSharingLinkScope: 'SpecificPeople',
          requireSignInToAccessSites: true,
        });

      await this.graphClient
        .api('/admin/onedrive/settings')
        .patch({
          defaultSharingLinkScope: 'SpecificPeople',
          requireSignInToAccessFiles: true,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Default sharing scope set to Specific People successfully',
          },
        ],
      };
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure default sharing scope: ${error.message}`
      );
    }
  }

  private async configureDefaultSharingPermissions() {
    try {
      // Configure default sharing permissions using Microsoft Graph API
      await this.graphClient
        .api('/admin/sharepoint/settings')
        .patch({
          defaultLinkPermission: 'View',
          // Additional secure defaults
          preventExternalUsersFromResharing: true,
          emailAttestationRequired: true,
          blockDownloadLinksFileType: 'WebPreviewableFiles',
        });

      await this.graphClient
        .api('/admin/onedrive/settings')
        .patch({
          defaultLinkPermission: 'View',
          // Additional secure defaults
          preventExternalUsersFromResharing: true,
          emailAttestationRequired: true,
          blockDownloadLinksFileType: 'WebPreviewableFiles',
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Default sharing permissions set to View only successfully',
          },
        ],
      };
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to configure default sharing permissions: ${error.message}`
      );
    }
  }

  private async disableCustomScripts() {
    try {
      // Disable custom scripts using Microsoft Graph API
      await this.graphClient
        .api('/admin/sharepoint/settings')
        .patch({
          customScriptSites: 'Disabled',
          userCustomScriptSites: 'Disabled',
          // Additional security settings
          legacyAuthProtocolsEnabled: false,
          showPeoplePickerSuggestionsForGuestUsers: false,
        });

      return {
        content: [
          {
            type: 'text',
            text: 'Custom scripts disabled on self-service created sites successfully',
          },
        ],
      };
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to disable custom scripts: ${error.message}`
      );
    }
  }

  private async getPolicyStatus() {
    try {
      // Get current settings using Microsoft Graph API
      const [sharePointSettings, oneDriveSettings] = await Promise.all([
        this.graphClient.api('/admin/sharepoint/settings').get(),
        this.graphClient.api('/admin/onedrive/settings').get(),
      ]);

      const status = {
        sharePointSharing: {
          level: sharePointSettings.sharingCapability,
          compliant: ['ExistingGuests', 'OnlyOrganization'].includes(
            sharePointSettings.sharingCapability
          ),
        },
        oneDriveSharing: {
          level: oneDriveSettings.oneDriveSharingCapability,
          compliant: ['ExistingGuests', 'OnlyOrganization'].includes(
            oneDriveSettings.oneDriveSharingCapability
          ),
        },
        defaultSharingScope: {
          sharePoint: sharePointSettings.defaultSharingLinkScope === 'SpecificPeople',
          oneDrive: oneDriveSettings.defaultSharingLinkScope === 'SpecificPeople',
        },
        defaultSharingPermissions: {
          sharePoint: sharePointSettings.defaultLinkPermission === 'View',
          oneDrive: oneDriveSettings.defaultLinkPermission === 'View',
        },
        customScripts: {
          disabled: sharePointSettings.customScriptSites === 'Disabled' &&
                   sharePointSettings.userCustomScriptSites === 'Disabled',
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
    } catch (error: any) {
      throw new McpError(
        ErrorCode.InternalError,
        `Failed to get policy status: ${error.message}`
      );
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('SharePoint & OneDrive MCP server running on stdio');
  }
}

const server = new SharePointServer();
server.run().catch(console.error);

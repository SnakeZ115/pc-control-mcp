#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import {
  clipboardGet,
  clipboardGetInputSchema,
  clipboardSet,
  clipboardSetInputSchema,
  type DesktopToolsDeps,
  listAllowedFiles,
  listAllowedFilesInputSchema,
  mediaVolume,
  mediaVolumeInputSchema,
  systemPower,
  systemPowerInputSchema,
  takeScreenshot,
  takeScreenshotInputSchema,
} from './tools/desktop-tools.js';
import {
  getSystemMetrics,
  getSystemMetricsInputSchema,
  killProcess,
  killProcessInputSchema,
  listProcesses,
  listProcessesInputSchema,
  type SystemToolsDeps,
} from './tools/system-tools.js';

export interface ServerDependencies {
  system?: SystemToolsDeps;
  desktop?: DesktopToolsDeps;
}

function toJsonResult(payload: unknown): CallToolResult {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function toErrorResult(error: unknown): CallToolResult {
  const message = error instanceof Error ? error.message : String(error);
  return {
    content: [
      {
        type: 'text',
        text: message,
      },
    ],
    isError: true,
  };
}

async function runJsonTool<T>(fn: () => Promise<T>): Promise<CallToolResult> {
  try {
    const result = await fn();
    return toJsonResult(result);
  } catch (error) {
    return toErrorResult(error);
  }
}

export function createMcpServer(deps: ServerDependencies = {}): McpServer {
  const server = new McpServer({
    name: 'mcp-pc-control',
    version: '0.1.0',
  });

  server.registerTool(
    'get_system_metrics',
    {
      title: 'Get System Metrics',
      description:
        'Returns CPU load (%), RAM usage (GB), GPU VRAM and temperatures, disk space, and system uptime.',
      inputSchema: getSystemMetricsInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    () => runJsonTool(() => getSystemMetrics(deps.system)),
  );

  server.registerTool(
    'list_processes',
    {
      title: 'List Processes',
      description:
        'Lists top running processes sorted by CPU or RAM usage, with optional name filter and limit (max 30).',
      inputSchema: listProcessesInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    (args) => runJsonTool(() => listProcesses(args, deps.system)),
  );

  server.registerTool(
    'kill_process',
    {
      title: 'Kill Process',
      description:
        'Terminates a non-critical process by positive PID after verifying it is not a protected Windows system process.',
      inputSchema: killProcessInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    (args) => runJsonTool(() => killProcess(args, deps.system)),
  );

  server.registerTool(
    'take_screenshot',
    {
      title: 'Take Screenshot',
      description:
        'Captures the primary Windows display in memory and returns a Base64-encoded PNG image.',
      inputSchema: takeScreenshotInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async () => {
      try {
        const screenshot = await takeScreenshot(deps.desktop);
        return {
          content: [
            {
              type: 'image',
              data: screenshot.data,
              mimeType: screenshot.mimeType,
            },
          ],
        };
      } catch (error) {
        return toErrorResult(error);
      }
    },
  );

  server.registerTool(
    'clipboard_get',
    {
      title: 'Get Clipboard Text',
      description: 'Reads the current text content from the Windows clipboard.',
      inputSchema: clipboardGetInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    () => runJsonTool(() => clipboardGet(deps.desktop)),
  );

  server.registerTool(
    'clipboard_set',
    {
      title: 'Set Clipboard Text',
      description:
        'Safely writes text to the Windows clipboard via stdin without shell interpolation.',
      inputSchema: clipboardSetInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    (args) => runJsonTool(() => clipboardSet(args, deps.desktop)),
  );

  server.registerTool(
    'media_volume',
    {
      title: 'Media and Volume Control',
      description:
        'Controls Windows master audio volume, mute/unmute state, or sends media keys (mute, volume_up, volume_down, play_pause).',
      inputSchema: mediaVolumeInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    (args) => runJsonTool(() => mediaVolume(args, deps.desktop)),
  );

  server.registerTool(
    'system_power',
    {
      title: 'System Power Control',
      description:
        'Executes Windows power/session actions (lock, sleep, shutdown, restart, cancel_shutdown) with optional delay and dryRun mode.',
      inputSchema: systemPowerInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    (args) => runJsonTool(() => systemPower(args, deps.desktop)),
  );

  server.registerTool(
    'list_allowed_files',
    {
      title: 'List Allowed Files',
      description:
        'Lists files and subdirectories inside directories permitted by PC_ALLOWED_DIRS while blocking sensitive files.',
      inputSchema: listAllowedFilesInputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    (args) => runJsonTool(() => listAllowedFiles(args, deps.desktop)),
  );

  return server;
}

function isDirectExecution(): boolean {
  const entry = process.argv[1];
  if (!entry) {
    return false;
  }
  const currentFile = fileURLToPath(import.meta.url);
  try {
    return fs.realpathSync(entry) === fs.realpathSync(currentFile);
  } catch {
    return path.resolve(entry) === path.resolve(currentFile);
  }
}

async function main(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();

  const shutdown = async () => {
    try {
      await server.close();
    } finally {
      process.exit(0);
    }
  };

  process.once('SIGINT', () => {
    void shutdown();
  });
  process.once('SIGTERM', () => {
    void shutdown();
  });

  await server.connect(transport);
  console.error('mcp-pc-control server running on stdio');
}

if (isDirectExecution()) {
  main().catch((error) => {
    console.error('Fatal error in mcp-pc-control server:', error);
    process.exit(1);
  });
}

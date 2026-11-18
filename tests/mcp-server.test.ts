import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { Systeminformation } from 'systeminformation';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMcpServer } from '../src/index.js';
import type { DesktopToolsDeps } from '../src/tools/desktop-tools.js';
import type { SystemToolsDeps } from '../src/tools/system-tools.js';

describe('mcp-pc-control server', () => {
  const closers: Array<() => Promise<void>> = [];

  afterEach(async () => {
    while (closers.length > 0) {
      const close = closers.pop();
      if (close) await close();
    }
  });

  async function setupConnectedClient() {
    const fakePng = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';

    const systemDeps: SystemToolsDeps = {
      currentLoad: async () =>
        ({
          currentLoad: 12.5,
          currentLoadUser: 8.5,
          currentLoadSystem: 4.0,
          currentLoadIdle: 87.5,
          cpus: [{}, {}, {}, {}],
        }) as unknown as Systeminformation.CurrentLoadData,
      mem: async () =>
        ({
          total: 16 * 1024 ** 3,
          used: 8 * 1024 ** 3,
          free: 8 * 1024 ** 3,
          available: 8 * 1024 ** 3,
        }) as Systeminformation.MemData,
      graphics: async () => ({ controllers: [], displays: [] }),
      fsSize: async () => [],
      time: () => ({
        current: 1700000000000,
        uptime: 3661,
        timezone: 'UTC',
        timezoneName: 'UTC',
      }),
      processes: async () => ({
        all: 2,
        running: 2,
        blocked: 0,
        sleeping: 0,
        unknown: 0,
        list: [
          {
            pid: 5555,
            parentPid: 1,
            name: 'node.exe',
            cpu: 5.0,
            cpuu: 3.0,
            cpus: 2.0,
            mem: 1.5,
            priority: 8,
            memVsz: 1000,
            memRss: 20480,
            nice: 0,
            started: '2026-11-17',
            state: 'running',
            tty: '',
            user: 'SENTINEL',
            command: 'node.exe',
            params: '',
            path: 'C:\\Program Files\\nodejs\\node.exe',
          },
          {
            pid: 1200,
            parentPid: 1,
            name: 'lsass.exe',
            cpu: 0.2,
            cpuu: 0.1,
            cpus: 0.1,
            mem: 0.4,
            priority: 8,
            memVsz: 1000,
            memRss: 8192,
            nice: 0,
            started: '2026-11-17',
            state: 'running',
            tty: '',
            user: 'SYSTEM',
            command: 'lsass.exe',
            params: '',
            path: 'C:\\Windows\\System32\\lsass.exe',
          },
        ],
      }),
      killProcessByPid: vi.fn(),
      selfPid: 99999,
    };

    const desktopDeps: DesktopToolsDeps = {
      execFile: vi.fn(async (_file, args, opts) => {
        const script = args[3] ?? '';
        if (script.includes('System.Windows.Forms.Screen')) {
          return { stdout: fakePng, stderr: '' };
        }
        if (script.includes('Get-Clipboard')) {
          return { stdout: 'clip-value', stderr: '' };
        }
        if (script.includes('McpAudioControl')) {
          const payload = JSON.parse(opts?.input ?? '{}') as { action: string; level?: number };
          return {
            stdout: JSON.stringify({
              action: payload.action,
              volumePercent: payload.level ?? 50,
              muted: false,
            }),
            stderr: '',
          };
        }
        return { stdout: '', stderr: '' };
      }),
      platform: 'win32',
      validatePath: (p) => p,
      getAllowedDirs: () => ['C:\\Users\\SENTINEL\\Documents'],
    };

    const server = createMcpServer({ system: systemDeps, desktop: desktopDeps });
    const client = new Client({ name: 'test-client', version: '0.1.0' });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);

    closers.push(async () => {
      await client.close();
      await server.close();
    });

    return { client, systemDeps, desktopDeps, fakePng };
  }

  it('registers all 9 tools with valid schemas and dispatches tool calls end-to-end', async () => {
    const { client, fakePng } = await setupConnectedClient();

    const listed = await client.listTools();
    const names = listed.tools.map((t) => t.name).sort();
    expect(names).toEqual([
      'clipboard_get',
      'clipboard_set',
      'get_system_metrics',
      'kill_process',
      'list_allowed_files',
      'list_processes',
      'media_volume',
      'system_power',
      'take_screenshot',
    ]);

    const metricsRes = await client.callTool({ name: 'get_system_metrics', arguments: {} });
    expect(metricsRes.isError).not.toBe(true);
    const metricsText = (metricsRes.content as Array<{ type: string; text: string }>)[0].text;
    expect(JSON.parse(metricsText).cpu.cores).toBe(4);

    const screenshotRes = await client.callTool({ name: 'take_screenshot', arguments: {} });
    expect(screenshotRes.isError).not.toBe(true);
    expect(screenshotRes.content).toEqual([
      {
        type: 'image',
        data: fakePng,
        mimeType: 'image/png',
      },
    ]);

    const clipRes = await client.callTool({ name: 'clipboard_get', arguments: {} });
    const clipData = JSON.parse(
      (clipRes.content as Array<{ type: string; text: string }>)[0].text,
    );
    expect(clipData.text).toBe('clip-value');

    const killOk = await client.callTool({ name: 'kill_process', arguments: { pid: 5555 } });
    expect(killOk.isError).not.toBe(true);

    const killProtected = await client.callTool({ name: 'kill_process', arguments: { pid: 1200 } });
    expect(killProtected.isError).toBe(true);
    expect((killProtected.content as Array<{ type: string; text: string }>)[0].text).toMatch(
      /critical Windows process/i,
    );

    const powerDry = await client.callTool({
      name: 'system_power',
      arguments: { action: 'restart', delaySeconds: 15, dryRun: true },
    });
    expect(powerDry.isError).not.toBe(true);
    const powerPayload = JSON.parse(
      (powerDry.content as Array<{ type: string; text: string }>)[0].text,
    );
    expect(powerPayload).toEqual({
      executed: false,
      dryRun: true,
      action: 'restart',
      command: 'shutdown.exe',
      args: ['/r', '/t', '15'],
      delaySeconds: 15,
    });
  });

  it('rejects invalid input arguments via MCP schema validation', async () => {
    const { client } = await setupConnectedClient();

    const invalidLimit = await client.callTool({
      name: 'list_processes',
      arguments: { limit: 99 },
    });
    expect(invalidLimit.isError).toBe(true);

    const invalidMedia = await client.callTool({
      name: 'media_volume',
      arguments: { action: 'set' },
    });
    expect(invalidMedia.isError).toBe(true);
  });
});

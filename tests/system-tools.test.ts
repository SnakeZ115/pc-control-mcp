import { describe, expect, it, vi } from 'vitest';
import type { Systeminformation } from 'systeminformation';
import {
  getSystemMetrics,
  isCriticalProcessName,
  killProcess,
  listProcesses,
  type SystemToolsDeps,
} from '../src/tools/system-tools.js';

function createMockSystemDeps(
  overrides: Partial<SystemToolsDeps> = {},
): SystemToolsDeps {
  const procList: Systeminformation.ProcessesProcessData[] = [
    {
      pid: 4,
      parentPid: 0,
      name: 'System',
      cpu: 1.5,
      cpuu: 0,
      cpus: 1.5,
      mem: 0.1,
      priority: 8,
      memVsz: 100,
      memRss: 16384,
      nice: 0,
      started: '2026-11-15',
      state: 'running',
      tty: '',
      user: 'SYSTEM',
      command: 'System',
      params: '',
      path: '',
    },
    {
      pid: 1816,
      parentPid: 700,
      name: 'svchost.exe',
      cpu: 2.3,
      cpuu: 1.0,
      cpus: 1.3,
      mem: 1.2,
      priority: 8,
      memVsz: 20480,
      memRss: 32768,
      nice: 0,
      started: '2026-11-15',
      state: 'running',
      tty: '',
      user: 'SYSTEM',
      command: 'svchost.exe -k netsvcs',
      params: '-k netsvcs',
      path: 'C:\\Windows\\System32\\svchost.exe',
    },
    {
      pid: 4200,
      parentPid: 1200,
      name: 'Code.exe',
      cpu: 18.45,
      cpuu: 12.1,
      cpus: 6.35,
      mem: 8.5,
      priority: 8,
      memVsz: 512000,
      memRss: 524288,
      nice: 0,
      started: '2026-11-17',
      state: 'running',
      tty: '',
      user: 'SENTINEL',
      command: 'Code.exe',
      params: '',
      path: 'C:\\Program Files\\Microsoft VS Code\\Code.exe',
    },
    {
      pid: 4300,
      parentPid: 1200,
      name: 'chrome.exe',
      cpu: 6.2,
      cpuu: 4.0,
      cpus: 2.2,
      mem: 14.25,
      priority: 8,
      memVsz: 600000,
      memRss: 1048576,
      nice: 0,
      started: '2026-11-17',
      state: 'running',
      tty: '',
      user: 'SENTINEL',
      command: 'chrome.exe',
      params: '',
      path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    },
    {
      pid: 4400,
      parentPid: 1200,
      name: 'explorer.exe',
      cpu: 0.8,
      cpuu: 0.5,
      cpus: 0.3,
      mem: 1.8,
      priority: 8,
      memVsz: 120000,
      memRss: 65536,
      nice: 0,
      started: '2026-11-15',
      state: 'running',
      tty: '',
      user: 'SENTINEL',
      command: 'explorer.exe',
      params: '',
      path: 'C:\\Windows\\explorer.exe',
    },
  ];

  return {
    currentLoad: async () =>
      ({
        avgLoad: 0,
        currentLoad: 24.567,
        currentLoadUser: 18.123,
        currentLoadSystem: 6.444,
        currentLoadIdle: 75.433,
        cpus: new Array(16).fill({}),
      }) as unknown as Systeminformation.CurrentLoadData,
    mem: async () =>
      ({
        total: 32 * 1024 ** 3,
        used: 12 * 1024 ** 3,
        free: 20 * 1024 ** 3,
        available: 20 * 1024 ** 3,
      }) as Systeminformation.MemData,
    graphics: async () => ({
      controllers: [
        {
          vendor: 'NVIDIA',
          model: 'NVIDIA GeForce RTX 5070',
          name: 'NVIDIA GeForce RTX 5070',
          bus: 'PCI',
          vram: 12227,
          vramDynamic: false,
          memoryTotal: 12227,
          memoryUsed: 2000,
          memoryFree: 10227,
          temperatureGpu: 49,
          utilizationGpu: 5,
        },
        {
          vendor: 'AMD',
          model: 'AMD Radeon Graphics',
          bus: 'PCI',
          vram: 512,
          vramDynamic: true,
        },
      ],
      displays: [],
    }),
    fsSize: async () => [
      {
        fs: 'C:',
        type: 'NTFS',
        size: 1000 * 1024 ** 3,
        used: 400 * 1024 ** 3,
        available: 600 * 1024 ** 3,
        use: 40,
        mount: 'C:',
        rw: true,
      },
    ],
    time: () => ({
      current: 1794973776563,
      uptime: 90061,
      timezone: 'GMT-0700',
      timezoneName: 'America/Mazatlan',
    }),
    processes: async () => ({
      all: procList.length,
      running: procList.length,
      blocked: 0,
      sleeping: 0,
      unknown: 0,
      list: procList,
    }),
    killProcessByPid: vi.fn(),
    selfPid: 99999,
    ...overrides,
  };
}

describe('system-tools', () => {
  it('computes structured system metrics with GB conversion and optional GPU telemetry', async () => {
    const metrics = await getSystemMetrics(createMockSystemDeps());

    expect(metrics.cpu).toEqual({
      loadPercent: 24.57,
      userPercent: 18.12,
      systemPercent: 6.44,
      idlePercent: 75.43,
      cores: 16,
    });
    expect(metrics.memory).toEqual({
      totalGb: 32,
      usedGb: 12,
      freeGb: 20,
      availableGb: 20,
      usedPercent: 37.5,
    });
    expect(metrics.gpus).toEqual([
      {
        vendor: 'NVIDIA',
        model: 'NVIDIA GeForce RTX 5070',
        name: 'NVIDIA GeForce RTX 5070',
        vramMb: 12227,
        memoryTotalMb: 12227,
        memoryUsedMb: 2000,
        memoryFreeMb: 10227,
        temperatureCelsius: 49,
        utilizationPercent: 5,
      },
      {
        vendor: 'AMD',
        model: 'AMD Radeon Graphics',
        name: 'AMD Radeon Graphics',
        vramMb: 512,
        memoryTotalMb: null,
        memoryUsedMb: null,
        memoryFreeMb: null,
        temperatureCelsius: null,
        utilizationPercent: null,
      },
    ]);
    expect(metrics.disks[0]).toEqual({
      fs: 'C:',
      mount: 'C:',
      type: 'NTFS',
      totalGb: 1000,
      usedGb: 400,
      availableGb: 600,
      usedPercent: 40,
    });
    expect(metrics.uptime).toEqual({
      seconds: 90061,
      formatted: '1d 1h 1m 1s',
    });
  });

  it('lists processes sorted by cpu or mem with optional filter and limit up to 30', async () => {
    const deps = createMockSystemDeps();

    const byCpu = await listProcesses({ sortBy: 'cpu', limit: 2 }, deps);
    expect(byCpu.processes.map((p) => p.name)).toEqual(['Code.exe', 'chrome.exe']);
    expect(byCpu.processes[0].memRssMb).toBe(512);

    const byMem = await listProcesses({ sortBy: 'mem', limit: 2 }, deps);
    expect(byMem.processes.map((p) => p.name)).toEqual(['chrome.exe', 'Code.exe']);

    const filtered = await listProcesses({ filterName: 'code', limit: 10 }, deps);
    expect(filtered.matchedCount).toBe(1);
    expect(filtered.processes[0].pid).toBe(4200);

    await expect(listProcesses({ limit: 31 }, deps)).rejects.toThrow();
    await expect(listProcesses({ limit: 0 }, deps)).rejects.toThrow();
  });

  it('blocks terminating all critical Windows processes and invalid PIDs', async () => {
    const criticalNames = [
      'System',
      'svchost.exe',
      'csrss.exe',
      'wininit.exe',
      'winlogon.exe',
      'lsass.exe',
      'smss.exe',
      'explorer.exe',
      'SVCHOST',
    ];

    for (const name of criticalNames) {
      expect(isCriticalProcessName(name)).toBe(true);
    }
    expect(isCriticalProcessName('notepad.exe')).toBe(false);

    const killMock = vi.fn();
    const deps = createMockSystemDeps({ killProcessByPid: killMock });

    await expect(killProcess({ pid: 4 }, deps)).rejects.toThrow(/protected kernel\/system/i);
    await expect(killProcess({ pid: 1816 }, deps)).rejects.toThrow(/critical Windows process/i);
    await expect(killProcess({ pid: 4400 }, deps)).rejects.toThrow(/critical Windows process/i);
    await expect(killProcess({ pid: 99999 }, deps)).rejects.toThrow(/active MCP server/i);
    await expect(killProcess({ pid: 77777 }, deps)).rejects.toThrow(/not found/i);
    await expect(killProcess({ pid: -5 }, deps)).rejects.toThrow();
    expect(killMock).not.toHaveBeenCalled();

    const result = await killProcess({ pid: 4200 }, deps);
    expect(result).toEqual({ terminated: true, pid: 4200, name: 'Code.exe' });
    expect(killMock).toHaveBeenCalledWith(4200);
  });
});

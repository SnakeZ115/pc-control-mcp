import path from 'node:path';
import si from 'systeminformation';
import { z } from 'zod';

const BYTES_PER_GIB = 1024 ** 3;
const KIB_PER_MIB = 1024;
const MAX_PROCESS_LIMIT = 30;

export const CRITICAL_WINDOWS_PROCESSES: ReadonlySet<string> = new Set([
  'system',
  'system idle process',
  'secure system',
  'registry',
  'svchost.exe',
  'csrss.exe',
  'wininit.exe',
  'winlogon.exe',
  'lsass.exe',
  'smss.exe',
  'explorer.exe',
  'services.exe',
  'dwm.exe',
]);

export const getSystemMetricsInputSchema = z.object({});

export const listProcessesInputSchema = z.object({
  sortBy: z
    .enum(['cpu', 'mem'])
    .default('cpu')
    .describe('Sort processes descending by CPU or RAM usage'),
  filterName: z
    .string()
    .trim()
    .min(1)
    .optional()
    .describe('Optional case-insensitive substring filter applied to process name'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(MAX_PROCESS_LIMIT)
    .default(15)
    .describe('Maximum number of processes to return (1-30)'),
});

export const killProcessInputSchema = z.object({
  pid: z
    .number()
    .int()
    .positive()
    .describe('Positive integer PID of the non-critical process to terminate'),
});

export type ListProcessesInput = z.infer<typeof listProcessesInputSchema>;
export type KillProcessInput = z.infer<typeof killProcessInputSchema>;

export interface GpuMetricSummary {
  vendor: string;
  model: string;
  name: string;
  vramMb: number | null;
  memoryTotalMb: number | null;
  memoryUsedMb: number | null;
  memoryFreeMb: number | null;
  temperatureCelsius: number | null;
  utilizationPercent: number | null;
}

export interface DiskMetricSummary {
  fs: string;
  mount: string;
  type: string;
  totalGb: number;
  usedGb: number;
  availableGb: number;
  usedPercent: number;
}

export interface SystemMetricsSummary {
  timestamp: string;
  cpu: {
    loadPercent: number;
    userPercent: number;
    systemPercent: number;
    idlePercent: number;
    cores: number;
  };
  memory: {
    totalGb: number;
    usedGb: number;
    freeGb: number;
    availableGb: number;
    usedPercent: number;
  };
  gpus: GpuMetricSummary[];
  disks: DiskMetricSummary[];
  uptime: {
    seconds: number;
    formatted: string;
  };
}

export interface ProcessSummary {
  pid: number;
  parentPid: number;
  name: string;
  cpuPercent: number;
  memPercent: number;
  memRssMb: number;
  state: string;
  user: string;
  command: string;
}

export interface ListProcessesResult {
  totalProcesses: number;
  runningProcesses: number;
  matchedCount: number;
  sortBy: 'cpu' | 'mem';
  filterName: string | null;
  processes: ProcessSummary[];
}

export interface KillProcessResult {
  terminated: boolean;
  pid: number;
  name: string;
}

export interface SystemToolsDeps {
  currentLoad: typeof si.currentLoad;
  mem: typeof si.mem;
  graphics: typeof si.graphics;
  fsSize: typeof si.fsSize;
  time: typeof si.time;
  processes: typeof si.processes;
  killProcessByPid: (pid: number) => void;
  selfPid: number;
}

const defaultDeps: SystemToolsDeps = {
  currentLoad: () => si.currentLoad(),
  mem: () => si.mem(),
  graphics: () => si.graphics(),
  fsSize: () => si.fsSize(),
  time: () => si.time(),
  processes: () => si.processes(),
  killProcessByPid: (pid: number) => {
    process.kill(pid);
  },
  selfPid: process.pid,
};

function round2(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.round(value * 100) / 100;
}

function finiteOrZero(value: number | null | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function bytesToGb(bytes: number): number {
  return round2(bytes / BYTES_PER_GIB);
}

function formatUptime(totalSeconds: number): string {
  const safeSeconds = Math.max(0, Math.floor(totalSeconds));
  const days = Math.floor(safeSeconds / 86400);
  const hours = Math.floor((safeSeconds % 86400) / 3600);
  const minutes = Math.floor((safeSeconds % 3600) / 60);
  const seconds = safeSeconds % 60;

  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0 || days > 0) parts.push(`${hours}h`);
  if (minutes > 0 || hours > 0 || days > 0) parts.push(`${minutes}m`);
  parts.push(`${seconds}s`);
  return parts.join(' ');
}

export function isCriticalProcessName(processName: string): boolean {
  const normalized = processName.trim().toLowerCase();
  if (!normalized) {
    return false;
  }
  const baseName = path.win32.basename(normalized);
  return (
    CRITICAL_WINDOWS_PROCESSES.has(baseName) ||
    CRITICAL_WINDOWS_PROCESSES.has(`${baseName}.exe`)
  );
}

export async function getSystemMetrics(
  deps: SystemToolsDeps = defaultDeps,
): Promise<SystemMetricsSummary> {
  const [loadData, memData, graphicsData, fsData] = await Promise.all([
    deps.currentLoad(),
    deps.mem(),
    deps.graphics(),
    deps.fsSize(),
  ]);
  const timeData = deps.time();

  const totalGb = bytesToGb(memData.total);
  const usedGb = bytesToGb(memData.used);
  const freeGb = bytesToGb(memData.free);
  const availableGb = bytesToGb(memData.available);
  const usedPercent = memData.total > 0 ? round2((memData.used / memData.total) * 100) : 0;

  const gpus: GpuMetricSummary[] = graphicsData.controllers.map((controller) => ({
    vendor: controller.vendor,
    model: controller.model,
    name: controller.name ?? controller.model,
    vramMb: controller.vram ?? null,
    memoryTotalMb: controller.memoryTotal ?? null,
    memoryUsedMb: controller.memoryUsed ?? null,
    memoryFreeMb: controller.memoryFree ?? null,
    temperatureCelsius: controller.temperatureGpu ?? null,
    utilizationPercent: controller.utilizationGpu ?? null,
  }));

  const disks: DiskMetricSummary[] = fsData.map((disk) => ({
    fs: disk.fs,
    mount: disk.mount,
    type: disk.type,
    totalGb: bytesToGb(disk.size),
    usedGb: bytesToGb(disk.used),
    availableGb: bytesToGb(disk.available),
    usedPercent: round2(disk.use),
  }));

  const uptimeSeconds = round2(timeData.uptime);

  return {
    timestamp: new Date().toISOString(),
    cpu: {
      loadPercent: round2(loadData.currentLoad),
      userPercent: round2(loadData.currentLoadUser),
      systemPercent: round2(loadData.currentLoadSystem),
      idlePercent: round2(loadData.currentLoadIdle),
      cores: loadData.cpus.length,
    },
    memory: {
      totalGb,
      usedGb,
      freeGb,
      availableGb,
      usedPercent,
    },
    gpus,
    disks,
    uptime: {
      seconds: uptimeSeconds,
      formatted: formatUptime(uptimeSeconds),
    },
  };
}

export async function listProcesses(
  rawInput: z.input<typeof listProcessesInputSchema>,
  deps: SystemToolsDeps = defaultDeps,
): Promise<ListProcessesResult> {
  const input = listProcessesInputSchema.parse(rawInput);
  const processData = await deps.processes();
  const filterLower = input.filterName?.toLowerCase() ?? null;

  const filtered = filterLower
    ? processData.list.filter((proc) => proc.name.toLowerCase().includes(filterLower))
    : processData.list;

  const sorted = [...filtered].sort((a, b) => {
    const aCpu = finiteOrZero(a.cpu);
    const bCpu = finiteOrZero(b.cpu);
    const aMem = finiteOrZero(a.mem);
    const bMem = finiteOrZero(b.mem);
    if (input.sortBy === 'mem') {
      return bMem - aMem || bCpu - aCpu || a.pid - b.pid;
    }
    return bCpu - aCpu || bMem - aMem || a.pid - b.pid;
  });

  const limited = sorted.slice(0, input.limit).map((proc) => ({
    pid: proc.pid,
    parentPid: proc.parentPid,
    name: proc.name,
    cpuPercent: round2(proc.cpu),
    memPercent: round2(proc.mem),
    memRssMb: round2(proc.memRss / KIB_PER_MIB),
    state: proc.state,
    user: proc.user,
    command: proc.command,
  }));

  return {
    totalProcesses: processData.all,
    runningProcesses: processData.running,
    matchedCount: filtered.length,
    sortBy: input.sortBy,
    filterName: input.filterName ?? null,
    processes: limited,
  };
}

export async function killProcess(
  rawInput: z.input<typeof killProcessInputSchema>,
  deps: SystemToolsDeps = defaultDeps,
): Promise<KillProcessResult> {
  const { pid } = killProcessInputSchema.parse(rawInput);

  if (pid <= 4) {
    throw new Error(`Refusing to terminate protected kernel/system PID ${pid}`);
  }

  if (pid === deps.selfPid) {
    throw new Error(`Refusing to terminate the active MCP server process (PID ${pid})`);
  }

  const processData = await deps.processes();
  const target = processData.list.find((proc) => proc.pid === pid);

  if (!target) {
    throw new Error(`Process with PID ${pid} was not found`);
  }

  if (
    isCriticalProcessName(target.name) ||
    (target.path ? isCriticalProcessName(target.path) : false)
  ) {
    throw new Error(
      `Refusing to terminate critical Windows process "${target.name}" (PID ${pid})`,
    );
  }

  try {
    deps.killProcessByPid(pid);
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code === 'ESRCH') {
      throw new Error(`Process "${target.name}" (PID ${pid}) no longer exists`);
    }
    if (err.code === 'EPERM') {
      throw new Error(`Permission denied terminating "${target.name}" (PID ${pid})`);
    }
    throw new Error(
      `Failed to terminate "${target.name}" (PID ${pid}): ${err.message}`,
    );
  }

  return {
    terminated: true,
    pid,
    name: target.name,
  };
}

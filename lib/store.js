'use strict';

const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');

// ─── 数据模式 ───────────────────────────────────────────────
const SCHEMA_VERSION = 1;

const ENTITY_KEYS = Object.freeze([
  'reports',
  'reporter_identities',
  'attachments',
  'supplementary_clues',
  'case_events',
  'investigation_tasks',
  'investigation_reports',
  'approvals',
  'admin_users',
  'sessions',
  'audit_logs',
]);

const ALL_KEYS = Object.freeze([...ENTITY_KEYS, 'meta', 'settings']);

// ─── 工具函数 ───────────────────────────────────────────────
function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function todayStr(clock) {
  return clock().toISOString().slice(0, 10);
}

function defaultData(clock) {
  const now = clock().toISOString();
  return {
    meta: {
      version: SCHEMA_VERSION,
      created_at: now,
      updated_at: now,
      sequences: Object.fromEntries(ENTITY_KEYS.map((k) => [k, 0])),
    },
    settings: {
      site_name: '凯叔讲故事 廉洁举报平台',
      announcement: '',
      feishu_webhook_url: '',
    },
    reports: [],
    reporter_identities: [],
    attachments: [],
    supplementary_clues: [],
    case_events: [],
    investigation_tasks: [],
    investigation_reports: [],
    approvals: [],
    admin_users: [],
    sessions: [],
    audit_logs: [],
  };
}

function validateData(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('数据格式无效');
  }
  for (const key of ALL_KEYS) {
    if (!(key in data)) throw new Error(`数据缺少字段: ${key}`);
  }
  if (data.meta?.version !== SCHEMA_VERSION) {
    throw new Error(`数据版本不兼容 (期望 ${SCHEMA_VERSION}, 实际 ${data.meta?.version})`);
  }
  for (const key of ENTITY_KEYS) {
    if (!Array.isArray(data[key])) throw new Error(`字段 ${key} 必须为数组`);
  }
}

// ─── 存储引擎 ───────────────────────────────────────────────
function createStore({ dataDir, clock = () => new Date(), backupRetentionDays = 30 } = {}) {
  if (!dataDir) throw new TypeError('dataDir is required');

  const dataFile = path.join(dataDir, 'data.json');
  const tempFile = path.join(dataDir, 'data.json.tmp');
  const backupDir = path.join(dataDir, 'backups');
  let initPromise = null;
  let writeQueue = Promise.resolve();

  async function ensureDir() {
    await fs.mkdir(dataDir, { recursive: true });
    await fs.access(dataDir, fs.constants.W_OK);
  }

  async function atomicWrite(data) {
    const json = JSON.stringify(data, null, 2) + '\n';
    await fs.writeFile(tempFile, json, 'utf8');
    // 回读校验
    const readback = JSON.parse(await fs.readFile(tempFile, 'utf8'));
    validateData(readback);
    await fs.rename(tempFile, dataFile);
  }

  async function initialize() {
    await ensureDir();
    try {
      await fs.access(dataFile);
    } catch {
      // 首次启动，写入默认数据
      await atomicWrite(defaultData(clock));
      return;
    }
    // 已有数据，校验
    const existing = JSON.parse(await fs.readFile(dataFile, 'utf8'));
    validateData(existing);
  }

  function ensureInit() {
    if (!initPromise) {
      initPromise = initialize().catch((err) => {
        initPromise = null;
        throw err;
      });
    }
    return initPromise;
  }

  async function readRaw() {
    await ensureInit();
    const data = JSON.parse(await fs.readFile(dataFile, 'utf8'));
    validateData(data);
    return data;
  }

  async function createBackup() {
    await readRaw();
    await fs.mkdir(backupDir, { recursive: true });
    const name = `data-${todayStr(clock)}.json`;
    const backupFile = path.join(backupDir, name);
    try {
      await fs.access(backupFile);
    } catch {
      await fs.copyFile(dataFile, backupFile);
    }
    // 清理过期备份
    const cutoff = new Date(todayStr(clock) + 'T00:00:00.000Z');
    cutoff.setUTCDate(cutoff.getUTCDate() - backupRetentionDays + 1);
    const cutoffStr = cutoff.toISOString().slice(0, 10);
    const entries = await fs.readdir(backupDir, { withFileTypes: true });
    for (const entry of entries) {
      const m = /^data-(\d{4}-\d{2}-\d{2})\.json$/.exec(entry.name);
      if (entry.isFile() && m && m[1] < cutoffStr) {
        await fs.rm(path.join(backupDir, entry.name)).catch(() => {});
      }
    }
  }

  function enqueue(op) {
    const result = writeQueue.then(op);
    writeQueue = result.catch(() => {});
    return result;
  }

  return {
    async read() {
      return clone(await readRaw());
    },

    transaction(mutator) {
      return enqueue(async () => {
        const data = await readRaw();
        const draft = clone(data);
        await mutator(draft);
        draft.meta.updated_at = clock().toISOString();
        validateData(draft);
        await createBackup();
        await atomicWrite(draft);
        return clone(draft);
      });
    },

    async listBackups() {
      try {
        const entries = await fs.readdir(backupDir, { withFileTypes: true });
        return entries
          .filter((e) => e.isFile() && /^data-\d{4}-\d{2}-\d{2}\.json$/.test(e.name))
          .map((e) => e.name)
          .sort();
      } catch {
        return [];
      }
    },

    async health() {
      try {
        await readRaw();
        return { ready: true };
      } catch (err) {
        return { ready: false, error: err.message };
      }
    },

    // 生成自增 ID
    nextId(data, entity, prefix) {
      if (!data.meta.sequences[entity] && data.meta.sequences[entity] !== 0) {
        data.meta.sequences[entity] = 0;
      }
      data.meta.sequences[entity] += 1;
      return `${prefix}-${String(data.meta.sequences[entity]).padStart(8, '0')}`;
    },
  };
}

module.exports = { createStore, ENTITY_KEYS, SCHEMA_VERSION };

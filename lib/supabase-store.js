'use strict';

// ════════════════════════════════════════════════════════════
// Supabase 存储引擎 — 替代 JSON 文件存储
// 使用 Supabase REST API (PostgREST)，无需额外依赖
// ════════════════════════════════════════════════════════════

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

// ─── 默认数据 ───────────────────────────────────────────────
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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

// ─── 创建存储引擎 ───────────────────────────────────────────
function createSupabaseStore({ supabaseUrl, supabaseKey, clock = () => new Date() } = {}) {
  if (!supabaseUrl) throw new TypeError('supabaseUrl is required');
  if (!supabaseKey) throw new TypeError('supabaseKey is required');

  const baseUrl = supabaseUrl.replace(/\/$/, '');
  const baseHeaders = {
    apikey: supabaseKey,
    Authorization: `Bearer ${supabaseKey}`,
    'Content-Type': 'application/json',
  };

  let initPromise = null;
  let writeQueue = Promise.resolve();

  // ─── 数据库 CRUD ─────────────────────────────────────────
  async function fetchData() {
    const resp = await fetch(
      `${baseUrl}/rest/v1/app_data?id=eq.main&select=data`,
      { headers: { ...baseHeaders, Accept: 'application/json' } }
    );
    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      throw new Error(`Supabase query failed: ${resp.status} ${text}`);
    }
    const rows = await resp.json();
    return rows.length > 0 ? rows[0].data : null;
  }

  async function upsertData(data) {
    const body = JSON.stringify({
      id: 'main',
      data,
      updated_at: new Date().toISOString(),
    });
    // 使用 POST + merge-duplicates 实现 upsert
    const resp = await fetch(`${baseUrl}/rest/v1/app_data`, {
      method: 'POST',
      headers: {
        ...baseHeaders,
        Prefer: 'return=minimal,resolution=merge-duplicates',
      },
      body,
    });
    if (!resp.ok && resp.status !== 201) {
      const text = await resp.text().catch(() => '');
      throw new Error(`Supabase upsert failed: ${resp.status} ${text}`);
    }
  }

  async function initialize() {
    const existing = await fetchData();
    if (!existing) {
      await upsertData(defaultData(clock));
    }
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

  function enqueue(op) {
    const result = writeQueue.then(op);
    writeQueue = result.catch(() => {});
    return result;
  }

  // ─── 附件 CRUD ───────────────────────────────────────────
  async function saveAttachment(id, fileBuffer, originalName, mime) {
    const resp = await fetch(`${baseUrl}/rest/v1/app_attachments`, {
      method: 'POST',
      headers: {
        ...baseHeaders,
        Prefer: 'return=minimal,resolution=merge-duplicates',
      },
      body: JSON.stringify({
        id,
        data: fileBuffer.toString('base64'),
        original_name: originalName,
        mime,
        size: fileBuffer.length,
      }),
    });
    if (!resp.ok && resp.status !== 201) {
      const text = await resp.text().catch(() => '');
      throw new Error(`Attachment save failed: ${resp.status} ${text}`);
    }
  }

  async function getAttachment(id) {
    const resp = await fetch(
      `${baseUrl}/rest/v1/app_attachments?id=eq.${encodeURIComponent(id)}&select=data,original_name,mime,size`,
      { headers: { ...baseHeaders, Accept: 'application/json' } }
    );
    if (!resp.ok) {
      throw new Error(`Attachment query failed: ${resp.status}`);
    }
    const rows = await resp.json();
    if (rows.length === 0) return null;
    return {
      data: Buffer.from(rows[0].data, 'base64'),
      originalName: rows[0].original_name,
      mime: rows[0].mime,
      size: rows[0].size,
    };
  }

  // ─── 返回存储接口 ─────────────────────────────────────────
  return {
    async read() {
      await ensureInit();
      const data = await fetchData();
      if (!data) {
        // 数据被意外删除，重新初始化
        await upsertData(defaultData(clock));
        return clone(defaultData(clock));
      }
      return clone(data);
    },

    transaction(mutator) {
      return enqueue(async () => {
        await ensureInit();
        const data = await fetchData();
        const draft = data ? clone(data) : defaultData(clock);
        await mutator(draft);
        draft.meta.updated_at = clock().toISOString();
        await upsertData(draft);
        return clone(draft);
      });
    },

    async listBackups() {
      // Supabase 自动管理备份
      return [];
    },

    async health() {
      try {
        await ensureInit();
        return { ready: true };
      } catch (err) {
        return { ready: false, error: err.message };
      }
    },

    nextId(data, entity, prefix) {
      if (!data.meta.sequences[entity] && data.meta.sequences[entity] !== 0) {
        data.meta.sequences[entity] = 0;
      }
      data.meta.sequences[entity] += 1;
      return `${prefix}-${String(data.meta.sequences[entity]).padStart(8, '0')}`;
    },

    saveAttachment,
    getAttachment,
  };
}

module.exports = { createSupabaseStore, ENTITY_KEYS, SCHEMA_VERSION };

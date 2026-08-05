'use strict';

// ════════════════════════════════════════════════════════════
// 凯叔讲故事 廉洁举报平台 v3 — 主服务
// 纯 Node.js，无框架依赖
// ════════════════════════════════════════════════════════════

const http = require('node:http');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');

const { createStore } = require('./lib/store');
const { createSupabaseStore } = require('./lib/supabase-store');
const {
  hashPassword, verifyPassword, encryptIdentity, decryptIdentity,
  createToken, createSessionCookie, clearCookie,
  hmacDigest, timingSafeEqualStr, requireCsrf,
  createRateLimiter, parseCookies, validateFileDeclaration,
} = require('./lib/security');

// ─── 配置 ────────────────────────────────────────────────────
function loadConfig(env = process.env) {
  const nodeEnv = env.NODE_ENV || 'development';
  const port = parseInt(env.PORT || '3000', 10);
  const dataDir = env.DATA_DIR || path.join(__dirname, 'data');
  const uploadDir = env.UPLOAD_DIR || path.join(dataDir, 'uploads');
  const sessionTtlMin = parseInt(env.SESSION_TTL_MINUTES || '480', 10);
  const querySessionTtlMin = parseInt(env.QUERY_SESSION_TTL_MINUTES || '30', 10);
  const maxFileMb = parseInt(env.MAX_FILE_SIZE_MB || '100', 10);
  const maxTotalMb = parseInt(env.MAX_TOTAL_UPLOAD_MB || '500', 10);

  // Supabase 配置（部署到云端时使用）
  const supabaseUrl = env.SUPABASE_URL || '';
  const supabaseKey = env.SUPABASE_KEY || '';
  const useSupabase = !!(supabaseUrl && supabaseKey);

  // 开发模式下自动生成密钥
  const reporterDataKey = env.REPORTER_DATA_KEY || (nodeEnv === 'production'
    ? '' : crypto.randomBytes(32).toString('base64'));
  const queryCodePepper = env.QUERY_CODE_PEPPER || (nodeEnv === 'production'
    ? '' : crypto.randomBytes(32).toString('base64'));
  const sessionSecret = env.SESSION_SECRET || (nodeEnv === 'production'
    ? '' : crypto.randomBytes(32).toString('base64'));

  if (nodeEnv === 'production') {
    for (const [k, v] of [
      ['REPORTER_DATA_KEY', reporterDataKey],
      ['QUERY_CODE_PEPPER', queryCodePepper],
      ['SESSION_SECRET', sessionSecret],
    ]) {
      if (!v) throw new Error(`生产环境必须配置 ${k}`);
    }
  }

  return {
    nodeEnv, port, dataDir, uploadDir,
    supabaseUrl, supabaseKey, useSupabase,
    sessionTtlMin, querySessionTtlMin,
    maxFileBytes: maxFileMb * 1024 * 1024,
    maxTotalBytes: maxTotalMb * 1024 * 1024,
    reporterDataKey, queryCodePepper, sessionSecret,
  };
}

// ─── 常量 ────────────────────────────────────────────────────
const REPORT_CATEGORIES = [
  '贿赂、回扣或其他腐败行为',
  '利益冲突',
  '侵占或挪用公司财产、资金或资产',
  '虚假报销或其他违反财务制度的行为',
  '泄露商业秘密、个人信息或滥用系统权限',
  '性骚扰、骚扰、霸凌或歧视',
  '其他违反法律法规或公司规定的行为',
];

const TRANSITIONS = {
  pending: new Set(['accepted', 'not_accepted']),
  accepted: new Set(['investigating']),
  investigating: new Set(['pending_approval']),
  pending_approval: new Set(['closed', 'investigating']),
  closed: new Set(),
  not_accepted: new Set(),
};

const PUBLIC_STATUS_MAP = {
  pending: { label: '已接收', color: 'warning' },
  accepted: { label: '已受理', color: 'info' },
  investigating: { label: '调查中', color: 'info' },
  pending_approval: { label: '审批中', color: 'info' },
  closed: { label: '已办结', color: 'success' },
  not_accepted: { label: '未受理', color: 'danger' },
};

const ADMIN_ROLES = ['system_admin', 'case_manager', 'investigator', 'approver'];

// ─── HTTP 工具 ───────────────────────────────────────────────
class HttpError extends Error {
  constructor(statusCode, code, message) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.statusCode = statusCode;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('content-length', Buffer.byteLength(payload));
  res.end(payload);
}

function sendError(res, statusCode, code, message) {
  sendJson(res, statusCode, { error: { code, message } });
}

async function readJsonBody(req, maxBytes = 512 * 1024) {
  const ct = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'application/json') throw new HttpError(415, 'UNSUPPORTED_MEDIA_TYPE', '需要 JSON 格式');
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > maxBytes) {
    req.resume();
    throw new HttpError(413, 'PAYLOAD_TOO_LARGE', '请求体过大');
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new HttpError(413, 'PAYLOAD_TOO_LARGE', '请求体过大');
    chunks.push(chunk);
  }
  if (size === 0) throw new HttpError(400, 'INVALID_JSON', '请求体不能为空');
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'INVALID_JSON', 'JSON 格式无效');
  }
}

function getIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string') {
    const first = fwd.split(',')[0].trim();
    if (net.isIP(first)) return first;
  }
  return req.socket?.remoteAddress || 'unknown';
}

function requireString(value, name, { min = 1, max = 4000 } = {}) {
  if (typeof value !== 'string' || value.trim().length < min || value.length > max) {
    throw new HttpError(422, 'VALIDATION_ERROR', `${name} 无效`);
  }
  return value.trim();
}

function optionalString(value, name, max = 500) {
  if (value === undefined || value === null || value === '') return '';
  return requireString(value, name, { max });
}

function requireFields(obj, fields) {
  for (const f of fields) {
    if (obj[f] === undefined || obj[f] === null || obj[f] === '') {
      throw new HttpError(422, 'VALIDATION_ERROR', `缺少字段: ${f}`);
    }
  }
}

// ─── 业务逻辑 ────────────────────────────────────────────────
function generateCaseNo(clock) {
  const date = clock().toISOString().slice(0, 10).replace(/-/g, '');
  return `KS-${date}`;
}

function generateQueryCode() {
  // 8位分组，便于人工输入
  return crypto.randomBytes(6).toString('base64url').slice(0, 10).toUpperCase();
}

function publicEventTemplate(status) {
  const templates = {
    pending: { title: '提交成功', message: '举报材料已安全接收。' },
    accepted: { title: '已受理', message: '举报已由合规人员受理。' },
    investigating: { title: '调查中', message: '相关事项正在核查处理中。' },
    pending_approval: { title: '审批中', message: '相关事项已进入内部审核环节。' },
    closed: { title: '已办结', message: '相关事项已完成处理。' },
    not_accepted: { title: '未予受理', message: '经审查，该事项未进入受理流程。' },
  };
  return templates[status] || templates.investigating;
}

function publicViewOfReport(report, events) {
  const statusInfo = PUBLIC_STATUS_MAP[report.status] || { label: '未知', color: 'muted' };
  const publicEvents = events
    .filter((e) => e.public_visible)
    .map((e) => ({
      title: e.public_title,
      message: e.public_message,
      created_at: e.created_at,
    }));
  return {
    case_no: report.case_no,
    status: report.status,
    status_label: statusInfo.label,
    status_color: statusInfo.color,
    category: report.category,
    submitted_at: report.created_at,
    timeline: publicEvents,
    clues: report.clue_count || 0,
  };
}

function summarizeReport(report) {
  return {
    id: report.id,
    case_no: report.case_no,
    category: report.category,
    status: report.status,
    status_label: (PUBLIC_STATUS_MAP[report.status] || {}).label || '未知',
    subject_type: report.subject?.type,
    subject_name: report.subject?.type === 'internal_employee'
      ? report.subject.name || '(未填写)'
      : report.subject?.organization_name || '(未填写)',
    reporter_mode: report.reporter_mode,
    priority: report.priority || 'normal',
    created_at: report.created_at,
    updated_at: report.updated_at,
    assigned_to: report.assigned_investigator_ids || [],
    clue_count: report.clue_count || 0,
    attachment_count: report.attachment_count || 0,
  };
}

// ─── 会话管理 ────────────────────────────────────────────────
async function createAdminSession(store, config, user, ip) {
  const token = createToken(32);
  const csrfToken = createToken(24);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + config.sessionTtlMin * 60_000);

  await store.transaction((data) => {
    // 清理过期会话
    const cutoff = now.toISOString();
    data.sessions = data.sessions.filter((s) => s.expires_at > cutoff);
    // 生成新会话 ID
    data.meta.sequences.sessions = (data.meta.sequences.sessions || 0) + 1;
    const sessionId = `session-${String(data.meta.sequences.sessions).padStart(8, '0')}`;
    data.sessions.push({
      id: sessionId,
      kind: 'admin',
      user_id: user.id,
      user_name: user.name,
      user_roles: user.roles,
      token_hash: hmacDigest(token, config.sessionSecret),
      csrf_digest: hmacDigest(csrfToken, config.sessionSecret),
      ip,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    });
  });

  return { token, csrfToken, expiresAt: expiresAt.toISOString() };
}

async function resolveAdminSession(store, config, req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies['ks_admin_session'];
  if (!token) return null;

  const data = await store.read();
  const tokenHash = hmacDigest(token, config.sessionSecret);
  const session = data.sessions.find((s) =>
    s.kind === 'admin' && timingSafeEqualStr(s.token_hash, tokenHash)
  );
  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) return null;

  const user = data.admin_users.find((u) => u.id === session.user_id);
  if (!user || user.status === 'disabled') return null;

  return { session, user };
}

// ─── 案件状态转换 ────────────────────────────────────────────
async function transitionCase(store, config, caseId, to, actor, options = {}) {
  const { comment = '', publicVisible = false, mutate } = options;
  if (to === 'not_accepted' && !comment.trim()) {
    throw new HttpError(422, 'REJECTION_REASON_REQUIRED', '不受理需要填写原因');
  }

  let result;
  await store.transaction((data) => {
    const report = data.reports.find((r) => r.id === caseId || r.case_no === caseId);
    if (!report) throw new HttpError(404, 'CASE_NOT_FOUND', '工单不存在');
    if (!TRANSITIONS[report.status]?.has(to)) {
      throw new HttpError(409, 'INVALID_TRANSITION', `不允许从 ${report.status} 转为 ${to}`);
    }

    const from = report.status;
    const now = new Date().toISOString();
    const template = publicEventTemplate(to);

    report.status = to;
    report.updated_at = now;
    if (mutate) mutate(data, report, now, from);

    const eventId = `event-${String((data.meta.sequences.case_events || 0) + 1).padStart(8, '0')}`;
    data.meta.sequences.case_events = (data.meta.sequences.case_events || 0) + 1;
    data.case_events.push({
      id: eventId,
      case_id: report.id,
      from, to,
      actor_id: actor.id,
      actor_name: actor.name,
      comment: comment.trim(),
      public_visible: publicVisible,
      public_title: template.title,
      public_message: template.message,
      created_at: now,
    });

    const auditId = `audit-${String((data.meta.sequences.audit_logs || 0) + 1).padStart(8, '0')}`;
    data.meta.sequences.audit_logs = (data.meta.sequences.audit_logs || 0) + 1;
    data.audit_logs.push({
      id: auditId,
      action: 'case.status_transition',
      actor_id: actor.id,
      actor_name: actor.name,
      resource_type: 'report',
      resource_id: report.id,
      details: { from, to, comment: comment.trim() },
      created_at: now,
    });

    result = JSON.parse(JSON.stringify(report));
  });
  return result;
}

// ─── 创建 HTTP 服务器 ───────────────────────────────────────
async function createServer() {
  const config = loadConfig();
  const clock = () => new Date();
  const store = config.useSupabase
    ? createSupabaseStore({ supabaseUrl: config.supabaseUrl, supabaseKey: config.supabaseKey, clock })
    : createStore({ dataDir: config.dataDir, clock });
  const rateLimiter = createRateLimiter({ clock: () => Date.now() });

  // 确保上传目录存在（仅本地模式）
  if (!config.useSupabase) {
    await fsp.mkdir(config.uploadDir, { recursive: true });
  }

  // 加载前端 HTML
  const htmlPath = path.join(__dirname, 'index.html');
  const frontendHtml = await fsp.readFile(htmlPath, 'utf8');

  // 初始化默认管理员（开发模式）
  await store.transaction(async (data) => {
    if (data.admin_users.length === 0) {
      const adminId = `admin-00000001`;
      data.meta.sequences.admin_users = 1;
      const passwordHash = await hashPassword('admin123456');
      data.admin_users.push({
        id: adminId,
        username: 'admin',
        name: '系统管理员',
        password_hash: passwordHash,
        roles: ['system_admin', 'case_manager'],
        status: 'active',
        created_at: clock().toISOString(),
      });
    }
  });

  // ─── 路由分发 ─────────────────────────────────────────────
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;
    const method = req.method;

    // 安全头
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('cache-control', 'no-store');

    try {
      // ── 静态文件 ──
      if ((method === 'GET' || method === 'HEAD') && (pathname === '/' || pathname === '/index.html')) {
        res.setHeader('content-type', 'text/html; charset=utf-8');
        res.end(frontendHtml);
        return;
      }

      // ── 健康检查 ──
      if (pathname === '/health/live') {
        sendJson(res, 200, { status: 'ok' });
        return;
      }

      // ── 公共 API ──
      if (pathname === '/api/public/settings' && method === 'GET') {
        const data = await store.read();
        sendJson(res, 200, {
          site_name: data.settings.site_name,
          announcement: data.settings.announcement,
          categories: REPORT_CATEGORIES,
        });
        return;
      }

      if (pathname === '/api/public/reports' && method === 'POST') {
        await handlePublicSubmit(req, res, store, config, rateLimiter);
        return;
      }

      if (pathname === '/api/public/query' && method === 'POST') {
        await handlePublicQuery(req, res, store, config, rateLimiter);
        return;
      }

      if (pathname === '/api/public/clues' && method === 'POST') {
        await handlePublicClue(req, res, store, config, rateLimiter);
        return;
      }

      if (pathname === '/api/public/uploads' && method === 'POST') {
        await handlePublicUpload(req, res, store, config, rateLimiter);
        return;
      }

      // ── 管理 API ──
      if (pathname === '/api/admin/login' && method === 'POST') {
        await handleAdminLogin(req, res, store, config, rateLimiter);
        return;
      }

      if (pathname === '/api/admin/logout' && method === 'POST') {
        await handleAdminLogout(req, res, store, config);
        return;
      }

      if (pathname === '/api/admin/session' && method === 'GET') {
        await handleAdminSession(req, res, store, config);
        return;
      }

      // 以下管理 API 需要认证
      const auth = await resolveAdminSession(store, config, req);
      if (!auth) {
        sendError(res, 401, 'UNAUTHORIZED', '请先登录');
        return;
      }

      // CSRF 校验（非安全方法）
      const isSafe = ['GET', 'HEAD', 'OPTIONS'].includes(method);
      if (!isSafe) {
        if (!requireCsrf(req, auth.session, { origin: '', secret: config.sessionSecret })) {
          sendError(res, 403, 'CSRF_REJECTED', 'CSRF 校验失败');
          return;
        }
      }

      const actor = { id: auth.user.id, name: auth.user.name, roles: auth.user.roles };

      // ── 工作台 ──
      if (pathname === '/api/admin/dashboard' && method === 'GET') {
        await handleDashboard(req, res, store);
        return;
      }

      // ── 工单管理 ──
      if (pathname === '/api/admin/reports' && method === 'GET') {
        await handleListReports(req, res, store, url);
        return;
      }

      // ── 统计分析 ──
      if (pathname === '/api/admin/statistics' && method === 'GET') {
        await handleStatistics(req, res, store, url);
        return;
      }

      // ── 审计日志 ──
      if (pathname === '/api/admin/audit-logs' && method === 'GET') {
        await handleAuditLogs(req, res, store, url);
        return;
      }

      // ── 用户管理 ──
      if (pathname === '/api/admin/users' && method === 'GET') {
        await handleListUsers(req, res, store);
        return;
      }
      if (pathname === '/api/admin/users' && method === 'POST') {
        await handleCreateUser(req, res, store, actor);
        return;
      }

      // ── 系统设置 ──
      if (pathname === '/api/admin/settings' && method === 'GET') {
        const data = await store.read();
        sendJson(res, 200, data.settings);
        return;
      }
      if (pathname === '/api/admin/settings' && method === 'PUT') {
        await handleUpdateSettings(req, res, store, actor);
        return;
      }

      // ── 备份列表 ──
      if (pathname === '/api/admin/backups' && method === 'GET') {
        const backups = await store.listBackups();
        sendJson(res, 200, { backups });
        return;
      }

      // ── 工单详情及操作 ──
      const reportMatch = pathname.match(/^\/api\/admin\/reports\/([^/]+)$/);
      const reportActionMatch = pathname.match(/^\/api\/admin\/reports\/([^/]+)\/([a-z-]+)$/);

      if (reportMatch && method === 'GET') {
        await handleReportDetail(req, res, store, config, reportMatch[1]);
        return;
      }

      if (reportActionMatch) {
        const [, caseId, action] = reportActionMatch;
        await handleReportAction(req, res, store, config, caseId, action, actor);
        return;
      }

      // ── 调查任务 ──
      if (pathname === '/api/admin/investigation-tasks' && method === 'GET') {
        await handleListTasks(req, res, store, url);
        return;
      }

      const taskMatch = pathname.match(/^\/api\/admin\/investigation-tasks\/([^/]+)\/report$/);
      if (taskMatch && method === 'POST') {
        await handleTaskReport(req, res, store, taskMatch[1], actor);
        return;
      }

      // ── 附件下载 ──
      const downloadMatch = pathname.match(/^\/api\/admin\/attachments\/([^/]+)$/);
      if (downloadMatch && method === 'GET') {
        await handleDownloadAttachment(req, res, store, config, downloadMatch[1]);
        return;
      }

      // ── 用户管理（单用户操作）──
      const userMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
      if (userMatch) {
        const [, userId] = userMatch;
        if (method === 'PATCH') {
          await handleUpdateUser(req, res, store, userId, actor);
          return;
        }
        if (method === 'DELETE') {
          await handleDeleteUser(req, res, store, userId, actor);
          return;
        }
      }

      sendError(res, 404, 'NOT_FOUND', '接口不存在');
    } catch (err) {
      if (err instanceof HttpError) {
        sendError(res, err.statusCode, err.code, err.message);
      } else {
        console.error('Unhandled error:', err);
        sendError(res, 500, 'INTERNAL_ERROR', '服务器内部错误');
      }
    }
  });

  return server;
}

// ════════════════════════════════════════════════════════════
// API 处理函数
// ════════════════════════════════════════════════════════════

// ─── 公共：提交举报 ─────────────────────────────────────────
async function handlePublicSubmit(req, res, store, config, rateLimiter) {
  const ip = getIp(req);
  const rl = rateLimiter.attempt({ category: 'submit', ip });
  if (!rl.allowed) {
    res.setHeader('retry-after', Math.ceil(rl.retryAfterMs / 1000));
    sendError(res, 429, 'RATE_LIMITED', '提交过于频繁，请稍后再试');
    return;
  }

  const body = await readJsonBody(req);
  requireFields(body, ['category', 'event', 'subject', 'consent']);

  if (!REPORT_CATEGORIES.includes(body.category)) {
    throw new HttpError(422, 'VALIDATION_ERROR', '举报类型无效');
  }

  const event = body.event;
  requireFields(event, ['description']);
  const eventData = {
    occurred_at: optionalString(event.occurredAt, '事发日期', 100),
    location: optionalString(event.location, '地点', 500),
    description: requireString(event.description, '事件描述', { min: 10, max: 20000 }),
  };

  if (body.consent !== true) {
    throw new HttpError(422, 'VALIDATION_ERROR', '需要确认同意');
  }

  // 被举报对象
  const subject = body.subject;
  let subjectData;
  if (subject.type === 'internal_employee') {
    subjectData = {
      type: 'internal_employee',
      name: optionalString(subject.name, '姓名', 200),
      department: optionalString(subject.department, '部门', 200),
      position: optionalString(subject.position, '职务', 200),
    };
  } else if (subject.type === 'partner') {
    subjectData = {
      type: 'partner',
      organization_name: optionalString(subject.organizationName, '企业名称', 300),
      contact: optionalString(subject.contact, '联系人', 200),
      project: optionalString(subject.project, '合作项目', 300),
    };
  } else {
    throw new HttpError(422, 'VALIDATION_ERROR', '对象类型无效');
  }

  // 举报人
  const reporter = body.reporter || { mode: 'anonymous' };
  let reporterMode = 'anonymous';
  let identityRecord = null;
  if (reporter.mode === 'identified') {
    reporterMode = 'identified';
    const identity = {
      name: requireString(reporter.name, '举报人姓名', { max: 200 }),
      contact: requireString(reporter.contact, '联系方式', { max: 300 }),
    };
    const encrypted = encryptIdentity(identity, config.reporterDataKey);
    identityRecord = { encrypted };
  } else if (reporter.mode !== 'anonymous') {
    throw new HttpError(422, 'VALIDATION_ERROR', '举报方式无效');
  }

  // 附件
  const attachmentIds = Array.isArray(body.attachmentIds) ? body.attachmentIds : [];

  // 生成案件编号和查询码
  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10).replace(/-/g, '');
  const queryCode = generateQueryCode();
  const queryCodeHash = hmacDigest(queryCode, config.queryCodePepper);

  let createdReport;
  await store.transaction((data) => {
    const seq = (data.meta.sequences.reports || 0) + 1;
    data.meta.sequences.reports = seq;
    const caseNo = `KS-${dateStr}-${String(seq).padStart(6, '0')}`;
    const id = `report-${String(seq).padStart(8, '0')}`;
    const ts = now.toISOString();

    createdReport = {
      id,
      case_no: caseNo,
      category: body.category,
      event: eventData,
      subject: subjectData,
      reporter_mode: reporterMode,
      status: 'pending',
      priority: 'normal',
      assigned_investigator_ids: [],
      attachment_ids: attachmentIds,
      attachment_count: attachmentIds.length,
      clue_count: 0,
      created_at: ts,
      updated_at: ts,
    };

    data.reports.push(createdReport);

    // 举报人身份
    if (identityRecord) {
      data.meta.sequences.reporter_identities = (data.meta.sequences.reporter_identities || 0) + 1;
      data.reporter_identities.push({
        id: `identity-${String(data.meta.sequences.reporter_identities).padStart(8, '0')}`,
        report_id: id,
        ...identityRecord,
        created_at: ts,
      });
    }

    // 查询码
    data.meta.sequences.sessions = (data.meta.sequences.sessions || 0) + 1;
    data.sessions.push({
      id: `qsession-${String(data.meta.sequences.sessions).padStart(8, '0')}`,
      kind: 'query',
      report_id: id,
      query_code_hash: queryCodeHash,
      created_at: ts,
      expires_at: new Date(now.getTime() + 24 * 3600_000).toISOString(),
    });

    // 初始事件
    data.meta.sequences.case_events = (data.meta.sequences.case_events || 0) + 1;
    data.case_events.push({
      id: `event-${String(data.meta.sequences.case_events).padStart(8, '0')}`,
      case_id: id,
      from: null,
      to: 'pending',
      actor_id: 'system',
      actor_name: '系统',
      comment: '',
      public_visible: true,
      public_title: '提交成功',
      public_message: '举报材料已安全接收。',
      created_at: ts,
    });
  });

  sendJson(res, 201, {
    case_no: createdReport.case_no,
    query_code: queryCode,
    submitted_at: createdReport.created_at,
  });
}

// ─── 公共：查询举报 ─────────────────────────────────────────
async function handlePublicQuery(req, res, store, config, rateLimiter) {
  const ip = getIp(req);
  const rl = rateLimiter.attempt({ category: 'query', ip });
  if (!rl.allowed) {
    res.setHeader('retry-after', Math.ceil(rl.retryAfterMs / 1000));
    sendError(res, 429, 'RATE_LIMITED', '查询过于频繁，请稍后再试');
    return;
  }

  const body = await readJsonBody(req);
  const caseNo = requireString(body.caseNo, '案件编号', { max: 40 });
  const queryCode = requireString(body.queryCode, '查询码', { max: 128 });

  const data = await store.read();
  const report = data.reports.find((r) => r.case_no === caseNo);
  if (!report) {
    rateLimiter.attempt({ category: 'query', ip, success: false });
    throw new HttpError(404, 'NOT_FOUND', '案件编号或查询码不正确');
  }

  // 验证查询码
  const queryCodeHash = hmacDigest(queryCode, config.queryCodePepper);
  const session = data.sessions.find((s) =>
    s.kind === 'query' && s.report_id === report.id &&
    timingSafeEqualStr(s.query_code_hash, queryCodeHash)
  );
  if (!session) {
    rateLimiter.attempt({ category: 'query', ip, success: false });
    throw new HttpError(404, 'NOT_FOUND', '案件编号或查询码不正确');
  }

  rateLimiter.attempt({ category: 'query', ip, success: true });

  const events = data.case_events
    .filter((e) => e.case_id === report.id)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));
  const clues = data.supplementary_clues
    .filter((c) => c.report_id === report.id)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));

  sendJson(res, 200, {
    ...publicViewOfReport(report, events),
    clues: clues.map((c) => ({ content: c.content, created_at: c.created_at })),
  });
}

// ─── 公共：补充线索 ─────────────────────────────────────────
async function handlePublicClue(req, res, store, config, rateLimiter) {
  const ip = getIp(req);
  const rl = rateLimiter.attempt({ category: 'submit', ip });
  if (!rl.allowed) {
    sendError(res, 429, 'RATE_LIMITED', '提交过于频繁，请稍后再试');
    return;
  }

  const body = await readJsonBody(req);
  const caseNo = requireString(body.caseNo, '案件编号', { max: 40 });
  const queryCode = requireString(body.queryCode, '查询码', { max: 128 });
  const content = requireString(body.content, '线索内容', { min: 5, max: 10000 });

  const data = await store.read();
  const report = data.reports.find((r) => r.case_no === caseNo);
  if (!report) throw new HttpError(404, 'NOT_FOUND', '案件编号或查询码不正确');

  const queryCodeHash = hmacDigest(queryCode, config.queryCodePepper);
  const session = data.sessions.find((s) =>
    s.kind === 'query' && s.report_id === report.id &&
    timingSafeEqualStr(s.query_code_hash, queryCodeHash)
  );
  if (!session) throw new HttpError(404, 'NOT_FOUND', '案件编号或查询码不正确');

  if (report.status === 'closed' || report.status === 'not_accepted') {
    throw new HttpError(409, 'CASE_CLOSED', '该工单已结案，无法补充线索');
  }

  const attachmentIds = Array.isArray(body.attachmentIds) ? body.attachmentIds : [];

  await store.transaction((d) => {
    const r = d.reports.find((x) => x.id === report.id);
    if (!r) return;
    r.clue_count = (r.clue_count || 0) + 1;
    r.updated_at = new Date().toISOString();

    d.meta.sequences.supplementary_clues = (d.meta.sequences.supplementary_clues || 0) + 1;
    d.supplementary_clues.push({
      id: `clue-${String(d.meta.sequences.supplementary_clues).padStart(8, '0')}`,
      report_id: r.id,
      content,
      attachment_ids: attachmentIds,
      created_at: new Date().toISOString(),
    });
  });

  sendJson(res, 201, { success: true });
}

// ─── 公共：文件上传 ─────────────────────────────────────────
async function handlePublicUpload(req, res, store, config, rateLimiter) {
  const ip = getIp(req);
  const rl = rateLimiter.attempt({ category: 'submit', ip });
  if (!rl.allowed) {
    sendError(res, 429, 'RATE_LIMITED', '上传过于频繁，请稍后再试');
    return;
  }

  // 解析 multipart/form-data
  const boundary = extractBoundary(req);
  if (!boundary) {
    throw new HttpError(400, 'BAD_REQUEST', '需要 multipart/form-data');
  }

  const chunks = [];
  let totalSize = 0;
  for await (const chunk of req) {
    totalSize += chunk.length;
    if (totalSize > config.maxFileBytes * 1.1) {
      throw new HttpError(413, 'FILE_TOO_LARGE', '文件过大');
    }
    chunks.push(chunk);
  }
  const buffer = Buffer.concat(chunks);

  const files = parseMultipart(buffer, boundary);
  if (files.length === 0) throw new HttpError(400, 'NO_FILE', '未找到文件');
  if (files.length > 10) throw new HttpError(400, 'TOO_MANY_FILES', '最多 10 个文件');

  const uploadedAttachments = [];
  for (const file of files) {
    if (file.size > config.maxFileBytes) {
      throw new HttpError(413, 'FILE_TOO_LARGE', `${file.filename} 超过大小限制`);
    }
    const decl = validateFileDeclaration(file.filename, file.mime);
    if (!decl.valid) throw new HttpError(422, 'FILE_TYPE_REJECTED', decl.reason);

    let attachmentId;
    await store.transaction((d) => {
      d.meta.sequences.attachments = (d.meta.sequences.attachments || 0) + 1;
      attachmentId = `attachment-${String(d.meta.sequences.attachments).padStart(8, '0')}`;
      d.attachments.push({
        id: attachmentId,
        stored_name: attachmentId,
        original_name: file.filename,
        mime: decl.mime,
        size: file.size,
        status: 'uploaded',
        created_at: new Date().toISOString(),
      });
    });

    // 保存文件数据（本地文件系统或 Supabase）
    await store.saveAttachment(attachmentId, file.data, file.filename, decl.mime);

    uploadedAttachments.push({ id: attachmentId, name: file.filename, size: file.size });
  }

  sendJson(res, 201, { attachments: uploadedAttachments });
}

function extractBoundary(req) {
  const ct = req.headers['content-type'] || '';
  const m = /boundary=(.+)$/i.exec(ct);
  return m ? m[1].trim().replace(/^["']|["']$/g, '') : null;
}

function parseMultipart(buffer, boundary) {
  const files = [];
  const boundaryBuffer = Buffer.from(`--${boundary}`);
  const parts = [];

  let start = 0;
  while (true) {
    const idx = buffer.indexOf(boundaryBuffer, start);
    if (idx === -1) break;
    if (start > 0) parts.push(buffer.slice(start, idx));
    start = idx + boundaryBuffer.length;
    // 跳过 \r\n
    if (buffer[start] === 0x0d && buffer[start + 1] === 0x0a) start += 2;
    // 检查是否结束 --
    if (buffer[start] === 0x2d && buffer[start + 1] === 0x2d) break;
  }

  for (const part of parts) {
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd === -1) continue;
    const headerStr = part.slice(0, headerEnd).toString('utf8');
    const fileData = part.slice(headerEnd + 4, part.length - 2); // 去掉末尾 \r\n

    const nameMatch = /name="([^"]+)"/i.exec(headerStr);
    const filenameMatch = /filename="([^"]*)"/i.exec(headerStr);
    if (!filenameMatch) continue;

    const mimeMatch = /content-type:\s*(.+?)$/im.exec(headerStr);
    files.push({
      fieldname: nameMatch ? nameMatch[1] : '',
      filename: filenameMatch[1],
      mime: mimeMatch ? mimeMatch[1].trim() : 'application/octet-stream',
      data: fileData,
      size: fileData.length,
    });
  }
  return files;
}

// ─── 管理：登录 ─────────────────────────────────────────────
async function handleAdminLogin(req, res, store, config, rateLimiter) {
  const ip = getIp(req);
  const rl = rateLimiter.attempt({ category: 'login', ip });
  if (!rl.allowed) {
    res.setHeader('retry-after', Math.ceil(rl.retryAfterMs / 1000));
    sendError(res, 429, 'RATE_LIMITED', '登录尝试过多，请稍后再试');
    return;
  }

  const body = await readJsonBody(req);
  const username = requireString(body.username, '用户名', { max: 100 });
  const password = requireString(body.password, '密码', { max: 500 });

  const data = await store.read();
  const user = data.admin_users.find((u) => u.username === username);
  const valid = user && user.status === 'active'
    ? await verifyPassword(password, user.password_hash)
    : false;

  if (!valid) {
    rateLimiter.attempt({ category: 'login', ip, success: false });
    throw new HttpError(401, 'INVALID_CREDENTIALS', '用户名或密码错误');
  }

  rateLimiter.attempt({ category: 'login', ip, success: true });

  const { token, csrfToken, expiresAt } = await createAdminSession(store, config, user, ip);

  // 记录审计日志
  await store.transaction((d) => {
    d.meta.sequences.audit_logs = (d.meta.sequences.audit_logs || 0) + 1;
    d.audit_logs.push({
      id: `audit-${String(d.meta.sequences.audit_logs).padStart(8, '0')}`,
      action: 'admin.login',
      actor_id: user.id,
      actor_name: user.name,
      resource_type: 'session',
      resource_id: 'self',
      details: { ip },
      created_at: new Date().toISOString(),
    });
  });

  res.setHeader('set-cookie', createSessionCookie('ks_admin_session', token, {
    expiresAt,
    path: '/',
  }));
  sendJson(res, 200, {
    user: { id: user.id, username: user.username, name: user.name, roles: user.roles },
    csrf_token: csrfToken,
    expires_at: expiresAt,
  });
}

// ─── 管理：登出 ─────────────────────────────────────────────
async function handleAdminLogout(req, res, store, config) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies['ks_admin_session'];
  if (token) {
    const tokenHash = hmacDigest(token, config.sessionSecret);
    await store.transaction((d) => {
      d.sessions = d.sessions.filter((s) => !(s.kind === 'admin' && s.token_hash === tokenHash));
    });
  }
  res.setHeader('set-cookie', clearCookie('ks_admin_session', '/'));
  sendJson(res, 200, { success: true });
}

// ─── 管理：会话检查 ─────────────────────────────────────────
async function handleAdminSession(req, res, store, config) {
  const auth = await resolveAdminSession(store, config, req);
  if (!auth) {
    sendError(res, 401, 'UNAUTHORIZED', '会话已过期');
    return;
  }
  sendJson(res, 200, {
    user: {
      id: auth.user.id,
      username: auth.user.username,
      name: auth.user.name,
      roles: auth.user.roles,
    },
    csrf_token: undefined, // 不再返回，登录时已给
    expires_at: auth.session.expires_at,
  });
}

// ─── 管理：工作台 ───────────────────────────────────────────
async function handleDashboard(req, res, store) {
  const data = await store.read();
  const now = new Date();
  const todayStr = now.toISOString().slice(0, 10);
  const weekAgo = new Date(now.getTime() - 7 * 86400_000).toISOString();

  const reports = data.reports;
  const stats = {
    total: reports.length,
    pending: reports.filter((r) => r.status === 'pending').length,
    investigating: reports.filter((r) => r.status === 'investigating').length,
    pending_approval: reports.filter((r) => r.status === 'pending_approval').length,
    closed: reports.filter((r) => r.status === 'closed').length,
    today_new: reports.filter((r) => r.created_at.slice(0, 10) === todayStr).length,
    week_new: reports.filter((r) => r.created_at >= weekAgo).length,
  };

  // 最近 5 条
  const recent = reports
    .slice(-5)
    .reverse()
    .map(summarizeReport);

  // 待办
  const todo = reports
    .filter((r) => ['pending', 'investigating', 'pending_approval'].includes(r.status))
    .slice(-10)
    .reverse()
    .map(summarizeReport);

  sendJson(res, 200, { stats, recent, todo });
}

// ─── 管理：工单列表 ─────────────────────────────────────────
async function handleListReports(req, res, store, url) {
  const data = await store.read();
  let reports = data.reports;

  // 筛选
  const status = url.searchParams.get('status');
  const category = url.searchParams.get('category');
  const keyword = url.searchParams.get('q');
  const subjectType = url.searchParams.get('subjectType');

  if (status) reports = reports.filter((r) => r.status === status);
  if (category) reports = reports.filter((r) => r.category === category);
  if (subjectType) reports = reports.filter((r) => r.subject?.type === subjectType);
  if (keyword) {
    const kw = keyword.toLowerCase();
    reports = reports.filter((r) =>
      r.case_no.toLowerCase().includes(kw) ||
      r.category.includes(keyword) ||
      (r.subject?.name || '').includes(keyword) ||
      (r.subject?.organization_name || '').includes(keyword)
    );
  }

  // 分页
  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(url.searchParams.get('pageSize') || '20', 10)));
  const total = reports.length;
  const items = reports
    .slice(-((page) * pageSize)) // 最新的在前
    .reverse()
    .slice(0, pageSize)
    .map(summarizeReport);

  sendJson(res, 200, { items, total, page, pageSize, totalPages: Math.ceil(total / pageSize) });
}

// ─── 管理：工单详情 ─────────────────────────────────────────
async function handleReportDetail(req, res, store, config, caseId) {
  const data = await store.read();
  const report = data.reports.find((r) => r.id === caseId || r.case_no === caseId);
  if (!report) throw new HttpError(404, 'NOT_FOUND', '工单不存在');

  const events = data.case_events
    .filter((e) => e.case_id === report.id)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));

  const clues = data.supplementary_clues
    .filter((c) => c.report_id === report.id)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));

  const attachments = data.attachments
    .filter((a) => report.attachment_ids?.includes(a.id) || clues.some((c) => c.attachment_ids?.includes(a.id)))
    .map((a) => ({ id: a.id, original_name: a.original_name, mime: a.mime, size: a.size, status: a.status, created_at: a.created_at }));

  const tasks = data.investigation_tasks
    .filter((t) => t.case_id === report.id)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));

  const approvals = data.approvals
    .filter((a) => a.case_id === report.id)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));

  // 举报人身份（不解密，仅标记是否存在）
  const hasIdentity = data.reporter_identities.some((i) => i.report_id === report.id);
  const identityRevealed = report.identity_revealed || false;

  sendJson(res, 200, {
    ...summarizeReport(report),
    event: report.event,
    subject: report.subject,
    events: events.map((e) => ({
      id: e.id,
      from: e.from,
      to: e.to,
      actor_name: e.actor_name,
      comment: e.comment,
      public_visible: e.public_visible,
      public_title: e.public_title,
      created_at: e.created_at,
    })),
    clues: clues.map((c) => ({
      id: c.id,
      content: c.content,
      attachment_ids: c.attachment_ids || [],
      created_at: c.created_at,
    })),
    attachments,
    investigation_tasks: tasks,
    approvals,
    reporter_mode: report.reporter_mode,
    has_identity: hasIdentity,
    identity_revealed: identityRevealed,
    priority: report.priority || 'normal',
    assigned_investigator_ids: report.assigned_investigator_ids || [],
  });
}

// ─── 管理：工单操作 ─────────────────────────────────────────
async function handleReportAction(req, res, store, config, caseId, action, actor) {
  const body = ['POST', 'PUT', 'PATCH'].includes(req.method) ? await readJsonBody(req) : {};

  switch (action) {
    case 'accept': {
      await transitionCase(store, config, caseId, 'accepted', actor, {
        comment: body.comment || '',
        publicVisible: true,
      });
      sendJson(res, 200, { success: true });
      return;
    }
    case 'reject': {
      await transitionCase(store, config, caseId, 'not_accepted', actor, {
        comment: body.comment || '',
        publicVisible: true,
      });
      sendJson(res, 200, { success: true });
      return;
    }
    case 'investigate': {
      await transitionCase(store, config, caseId, 'investigating', actor, {
        comment: body.comment || '',
        publicVisible: true,
        mutate: (data, report) => {
          if (body.investigatorIds) {
            report.assigned_investigator_ids = body.investigatorIds;
          }
        },
      });
      sendJson(res, 200, { success: true });
      return;
    }
    case 'assign': {
      const data = await store.read();
      const report = data.reports.find((r) => r.id === caseId || r.case_no === caseId);
      if (!report) throw new HttpError(404, 'NOT_FOUND', '工单不存在');
      await store.transaction((d) => {
        const r = d.reports.find((x) => x.id === report.id);
        if (!r) return;
        r.assigned_investigator_ids = body.investigatorIds || [];
        r.updated_at = new Date().toISOString();
        d.meta.sequences.audit_logs = (d.meta.sequences.audit_logs || 0) + 1;
        d.audit_logs.push({
          id: `audit-${String(d.meta.sequences.audit_logs).padStart(8, '0')}`,
          action: 'case.assign',
          actor_id: actor.id,
          actor_name: actor.name,
          resource_type: 'report',
          resource_id: r.id,
          details: { investigator_ids: body.investigatorIds },
          created_at: new Date().toISOString(),
        });
      });
      sendJson(res, 200, { success: true });
      return;
    }
    case 'submit-approval': {
      await transitionCase(store, config, caseId, 'pending_approval', actor, {
        comment: body.comment || '',
        publicVisible: true,
      });
      sendJson(res, 200, { success: true });
      return;
    }
    case 'approve': {
      await transitionCase(store, config, caseId, 'closed', actor, {
        comment: body.comment || '',
        publicVisible: true,
        mutate: (data, report) => {
          data.meta.sequences.approvals = (data.meta.sequences.approvals || 0) + 1;
          data.approvals.push({
            id: `approval-${String(data.meta.sequences.approvals).padStart(8, '0')}`,
            case_id: report.id,
            approver_id: actor.id,
            approver_name: actor.name,
            decision: 'approved',
            comment: body.comment || '',
            created_at: new Date().toISOString(),
          });
        },
      });
      sendJson(res, 200, { success: true });
      return;
    }
    case 'return': {
      await transitionCase(store, config, caseId, 'investigating', actor, {
        comment: body.comment || '',
        publicVisible: false,
        mutate: (data, report) => {
          data.meta.sequences.approvals = (data.meta.sequences.approvals || 0) + 1;
          data.approvals.push({
            id: `approval-${String(data.meta.sequences.approvals).padStart(8, '0')}`,
            case_id: report.id,
            approver_id: actor.id,
            approver_name: actor.name,
            decision: 'returned',
            comment: body.comment || '',
            created_at: new Date().toISOString(),
          });
        },
      });
      sendJson(res, 200, { success: true });
      return;
    }
    case 'comment': {
      const comment = requireString(body.comment, '评论内容', { max: 5000 });
      await store.transaction((d) => {
        const r = d.reports.find((x) => x.id === caseId || x.case_no === caseId);
        if (!r) throw new HttpError(404, 'NOT_FOUND', '工单不存在');
        d.meta.sequences.case_events = (d.meta.sequences.case_events || 0) + 1;
        d.case_events.push({
          id: `event-${String(d.meta.sequences.case_events).padStart(8, '0')}`,
          case_id: r.id,
          from: r.status,
          to: r.status,
          actor_id: actor.id,
          actor_name: actor.name,
          comment,
          public_visible: false,
          public_title: '',
          public_message: '',
          created_at: new Date().toISOString(),
        });
      });
      sendJson(res, 200, { success: true });
      return;
    }
    case 'reveal': {
      const data = await store.read();
      const report = data.reports.find((r) => r.id === caseId || r.case_no === caseId);
      if (!report) throw new HttpError(404, 'NOT_FOUND', '工单不存在');

      const identity = data.reporter_identities.find((i) => i.report_id === report.id);
      if (!identity) {
        sendJson(res, 200, { identity: null, message: '该举报为匿名举报，无身份信息。' });
        return;
      }

      const decrypted = decryptIdentity(identity.encrypted, config.reporterDataKey);

      // 标记已解密
      await store.transaction((d) => {
        const r = d.reports.find((x) => x.id === report.id);
        if (r) r.identity_revealed = true;
        d.meta.sequences.audit_logs = (d.meta.sequences.audit_logs || 0) + 1;
        d.audit_logs.push({
          id: `audit-${String(d.meta.sequences.audit_logs).padStart(8, '0')}`,
          action: 'case.reveal_identity',
          actor_id: actor.id,
          actor_name: actor.name,
          resource_type: 'report',
          resource_id: report.id,
          details: {},
          created_at: new Date().toISOString(),
        });
      });

      sendJson(res, 200, { identity: decrypted });
      return;
    }
    case 'priority': {
      const priority = body.priority || 'normal';
      if (!['low', 'normal', 'high', 'urgent'].includes(priority)) {
        throw new HttpError(422, 'VALIDATION_ERROR', '优先级无效');
      }
      await store.transaction((d) => {
        const r = d.reports.find((x) => x.id === caseId || x.case_no === caseId);
        if (!r) throw new HttpError(404, 'NOT_FOUND', '工单不存在');
        r.priority = priority;
        r.updated_at = new Date().toISOString();
      });
      sendJson(res, 200, { success: true });
      return;
    }
    default:
      throw new HttpError(404, 'NOT_FOUND', `未知操作: ${action}`);
  }
}

// ─── 管理：调查任务列表 ─────────────────────────────────────
async function handleListTasks(req, res, store, url) {
  const data = await store.read();
  let tasks = data.investigation_tasks;

  const investigatorId = url.searchParams.get('investigatorId');
  const caseId = url.searchParams.get('caseId');
  const status = url.searchParams.get('status');

  if (investigatorId) tasks = tasks.filter((t) => t.investigator_id === investigatorId);
  if (caseId) tasks = tasks.filter((t) => t.case_id === caseId);
  if (status) tasks = tasks.filter((t) => t.status === status);

  sendJson(res, 200, { items: tasks });
}

// ─── 管理：调查报告提交 ─────────────────────────────────────
async function handleTaskReport(req, res, store, taskId, actor) {
  const body = await readJsonBody(req);
  const content = requireString(body.content, '调查报告内容', { min: 10, max: 20000 });

  await store.transaction((d) => {
    const task = d.investigation_tasks.find((t) => t.id === taskId);
    if (!task) throw new HttpError(404, 'NOT_FOUND', '调查任务不存在');
    task.status = 'completed';
    task.completed_at = new Date().toISOString();

    d.meta.sequences.investigation_reports = (d.meta.sequences.investigation_reports || 0) + 1;
    d.investigation_reports.push({
      id: `inv-report-${String(d.meta.sequences.investigation_reports).padStart(8, '0')}`,
      task_id: taskId,
      case_id: task.case_id,
      investigator_id: actor.id,
      investigator_name: actor.name,
      content,
      created_at: new Date().toISOString(),
    });

    d.meta.sequences.audit_logs = (d.meta.sequences.audit_logs || 0) + 1;
    d.audit_logs.push({
      id: `audit-${String(d.meta.sequences.audit_logs).padStart(8, '0')}`,
      action: 'investigation.submit_report',
      actor_id: actor.id,
      actor_name: actor.name,
      resource_type: 'investigation_task',
      resource_id: taskId,
      details: {},
      created_at: new Date().toISOString(),
    });
  });

  sendJson(res, 200, { success: true });
}

// ─── 管理：统计分析 ─────────────────────────────────────────
async function handleStatistics(req, res, store, url) {
  const data = await store.read();
  const reports = data.reports;

  // 按状态统计
  const byStatus = {};
  for (const r of reports) {
    byStatus[r.status] = (byStatus[r.status] || 0) + 1;
  }

  // 按类型统计
  const byCategory = {};
  for (const r of reports) {
    byCategory[r.category] = (byCategory[r.category] || 0) + 1;
  }

  // 按月统计
  const byMonth = {};
  for (const r of reports) {
    const month = r.created_at.slice(0, 7);
    byMonth[month] = (byMonth[month] || 0) + 1;
  }

  // 按对象类型
  const bySubjectType = {};
  for (const r of reports) {
    const type = r.subject?.type || 'unknown';
    bySubjectType[type] = (bySubjectType[type] || 0) + 1;
  }

  // 处理时长统计（已结案）
  const closed = reports.filter((r) => r.status === 'closed');
  const durations = closed.map((r) => {
    const start = new Date(r.created_at).getTime();
    const end = new Date(r.updated_at).getTime();
    return Math.round((end - start) / 86400_000); // 天
  });
  const avgDuration = durations.length > 0
    ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length)
    : 0;

  sendJson(res, 200, {
    by_status: byStatus,
    by_category: byCategory,
    by_month: byMonth,
    by_subject_type: bySubjectType,
    avg_duration_days: avgDuration,
    total: reports.length,
    closed: closed.length,
  });
}

// ─── 管理：审计日志 ─────────────────────────────────────────
async function handleAuditLogs(req, res, store, url) {
  const data = await store.read();
  let logs = data.audit_logs.slice().reverse();

  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10));
  const pageSize = Math.min(100, parseInt(url.searchParams.get('pageSize') || '50', 10));
  const action = url.searchParams.get('action');
  if (action) logs = logs.filter((l) => l.action === action);

  const total = logs.length;
  const items = logs.slice((page - 1) * pageSize, page * pageSize);

  sendJson(res, 200, { items, total, page, pageSize });
}

// ─── 管理：用户列表 ─────────────────────────────────────────
async function handleListUsers(req, res, store) {
  const data = await store.read();
  const users = data.admin_users.map((u) => ({
    id: u.id,
    username: u.username,
    name: u.name,
    roles: u.roles,
    status: u.status,
    created_at: u.created_at,
  }));
  sendJson(res, 200, { items: users });
}

// ─── 管理：创建用户 ─────────────────────────────────────────
async function handleCreateUser(req, res, store, actor) {
  const body = await readJsonBody(req);
  const username = requireString(body.username, '用户名', { min: 3, max: 50 });
  const name = requireString(body.name, '姓名', { max: 100 });
  const password = requireString(body.password, '密码', { min: 8, max: 500 });
  const roles = Array.isArray(body.roles) ? body.roles : [];

  if (roles.some((r) => !ADMIN_ROLES.includes(r))) {
    throw new HttpError(422, 'VALIDATION_ERROR', '角色无效');
  }

  const data = await store.read();
  if (data.admin_users.some((u) => u.username === username)) {
    throw new HttpError(409, 'DUPLICATE', '用户名已存在');
  }

  const passwordHash = await hashPassword(password);
  let newId;
  await store.transaction((d) => {
    d.meta.sequences.admin_users = (d.meta.sequences.admin_users || 0) + 1;
    newId = `admin-${String(d.meta.sequences.admin_users).padStart(8, '0')}`;
    d.admin_users.push({
      id: newId,
      username,
      name,
      password_hash: passwordHash,
      roles: roles.length > 0 ? roles : ['investigator'],
      status: 'active',
      created_at: new Date().toISOString(),
    });
    d.meta.sequences.audit_logs = (d.meta.sequences.audit_logs || 0) + 1;
    d.audit_logs.push({
      id: `audit-${String(d.meta.sequences.audit_logs).padStart(8, '0')}`,
      action: 'user.create',
      actor_id: actor.id,
      actor_name: actor.name,
      resource_type: 'admin_user',
      resource_id: newId,
      details: { username, name, roles },
      created_at: new Date().toISOString(),
    });
  });

  sendJson(res, 201, { id: newId, username, name, roles });
}

// ─── 管理：更新用户 ─────────────────────────────────────────
async function handleUpdateUser(req, res, store, userId, actor) {
  const body = await readJsonBody(req);
  await store.transaction((d) => {
    const user = d.admin_users.find((u) => u.id === userId);
    if (!user) throw new HttpError(404, 'NOT_FOUND', '用户不存在');
    if (body.name !== undefined) user.name = optionalString(body.name, '姓名', 100);
    if (body.roles !== undefined) {
      if (Array.isArray(body.roles) && body.roles.every((r) => ADMIN_ROLES.includes(r))) {
        user.roles = body.roles;
      }
    }
    if (body.status !== undefined) {
      user.status = body.status === 'active' ? 'active' : 'disabled';
    }
    if (body.password) {
      // 异步哈希需要在外部处理
    }
  });

  // 如果要改密码
  if (body.password) {
    const passwordHash = await hashPassword(requireString(body.password, '密码', { min: 8, max: 500 }));
    await store.transaction((d) => {
      const user = d.admin_users.find((u) => u.id === userId);
      if (user) user.password_hash = passwordHash;
    });
  }

  sendJson(res, 200, { success: true });
}

// ─── 管理：删除用户 ─────────────────────────────────────────
async function handleDeleteUser(req, res, store, userId, actor) {
  await store.transaction((d) => {
    const idx = d.admin_users.findIndex((u) => u.id === userId);
    if (idx === -1) throw new HttpError(404, 'NOT_FOUND', '用户不存在');
    if (d.admin_users.length === 1) throw new HttpError(409, 'LAST_ADMIN', '不能删除最后一个管理员');
    d.admin_users.splice(idx, 1);
    d.meta.sequences.audit_logs = (d.meta.sequences.audit_logs || 0) + 1;
    d.audit_logs.push({
      id: `audit-${String(d.meta.sequences.audit_logs).padStart(8, '0')}`,
      action: 'user.delete',
      actor_id: actor.id,
      actor_name: actor.name,
      resource_type: 'admin_user',
      resource_id: userId,
      details: {},
      created_at: new Date().toISOString(),
    });
  });
  sendJson(res, 200, { success: true });
}

// ─── 管理：更新设置 ─────────────────────────────────────────
async function handleUpdateSettings(req, res, store, actor) {
  const body = await readJsonBody(req);
  await store.transaction((d) => {
    if (body.site_name !== undefined) d.settings.site_name = optionalString(body.site_name, '站点名称', 200);
    if (body.announcement !== undefined) d.settings.announcement = optionalString(body.announcement, '公告', 2000);
    if (body.feishu_webhook_url !== undefined) d.settings.feishu_webhook_url = optionalString(body.feishu_webhook_url, '飞书 webhook', 500);
  });
  sendJson(res, 200, { success: true });
}

// ─── 管理：下载附件 ─────────────────────────────────────────
async function handleDownloadAttachment(req, res, store, config, attachmentId) {
  const data = await store.read();
  const attachment = data.attachments.find((a) => a.id === attachmentId);
  if (!attachment) throw new HttpError(404, 'NOT_FOUND', '附件不存在');

  const file = await store.getAttachment(attachmentId);
  if (!file) throw new HttpError(404, 'FILE_NOT_FOUND', '文件不存在');

  res.setHeader('content-type', attachment.mime || 'application/octet-stream');
  res.setHeader('content-length', file.data.length);
  res.setHeader('content-disposition', `attachment; filename*=UTF-8''${encodeURIComponent(attachment.original_name)}`);
  res.end(file.data);
}

// ════════════════════════════════════════════════════════════
// 启动
// ════════════════════════════════════════════════════════════
async function main() {
  const server = await createServer();
  const config = loadConfig();
  server.listen(config.port, '0.0.0.0', () => {
    process.stdout.write(`凯叔讲故事廉洁举报平台 v3 运行中，端口 ${config.port}\n`);
    if (config.nodeEnv === 'development') {
      process.stdout.write(`  前台: http://localhost:${config.port}\n`);
      process.stdout.write(`  后台: http://localhost:${config.port}#admin\n`);
      process.stdout.write(`  默认账号: admin / admin123456\n`);
    }
  });

  const shutdown = () => server.close(() => process.exit(0));
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`启动失败: ${err.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { createServer, loadConfig };

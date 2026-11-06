/**
 * 独立站春哥 · 会员中心服务端（Cloudflare Pages Advanced Mode）
 *
 * 该文件位于 public/_worker.js，Cloudflare Pages 会把它作为全站入口。
 * 职责：
 *   1. 静态资源交给 env.ASSETS；
 *   2. /api/* 走本文件内的接口；
 *   3. 会员登录、会话、访问码校验、管理员鉴权全部在服务端完成。
 *
 * 需要的环境变量（在 Cloudflare Pages 项目设置里配置，不要写进前端）：
 *   CODE_PEPPER      访问码哈希用的服务端密钥（长随机字符串）
 *   ADMIN_SETUP_TOKEN 可选，一次性初始化管理员时额外校验的令牌
 */

const MEMBER_COOKIE = "chunge_member";
const ADMIN_COOKIE = "chunge_admin";
const MEMBER_SESSION_MS = 30 * 24 * 60 * 60 * 1000; // 30 天登录保持
const ADMIN_SESSION_MS = 12 * 60 * 60 * 1000;       // 12 小时

const MAX_FAILURES = 5;
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;

const PBKDF2_ITERATIONS = 100000;
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // 去掉 I L O 0 1，避免抄错

const enc = new TextEncoder();

/* ------------------------------------------------------------------ */
/* 基础工具                                                            */
/* ------------------------------------------------------------------ */

const nowIso = () => new Date().toISOString();

function hex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomHex(size) {
  return hex(crypto.getRandomValues(new Uint8Array(size)));
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256Hex(input) {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(input)));
}

function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

async function pbkdf2(password, saltHex, iterations) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: hexToBytes(saltHex), iterations },
    key,
    256
  );
  return hex(bits);
}

async function hashPassword(password) {
  const salt = randomHex(16);
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${salt}$${hash}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = parseInt(parts[1], 10);
  const expected = parts[3];
  const actual = await pbkdf2(password, parts[2], iterations);
  // 定长比较，减少时序差异
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

/* ------------------------------------------------------------------ */
/* 访问码                                                              */
/* ------------------------------------------------------------------ */

function normalizeCode(input) {
  return String(input || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function formatCode(raw) {
  return raw.match(/.{1,4}/g).join("-");
}

function generateCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  let raw = "";
  for (const b of bytes) raw += CODE_ALPHABET[b % CODE_ALPHABET.length];
  return formatCode(raw);
}

async function hashCode(code, pepper) {
  return sha256Hex(`chunge:${pepper}:${normalizeCode(code)}`);
}

function codeHint(code) {
  return `${code.slice(0, 4)}-••••-••••`;
}

/* ------------------------------------------------------------------ */
/* HTTP 工具                                                           */
/* ------------------------------------------------------------------ */

const BASE_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...BASE_HEADERS,
      ...extraHeaders,
    },
  });
}

function fail(status, error, message, extraHeaders = {}) {
  return json({ ok: false, error, message }, status, extraHeaders);
}

function withBaseHeaders(res) {
  if (res.status === 304) return res;
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(BASE_HEADERS)) headers.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

function sessionCookie(name, value, maxAgeSeconds) {
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", "Secure", "SameSite=Lax"];
  parts.push(maxAgeSeconds > 0 ? `Max-Age=${maxAgeSeconds}` : "Max-Age=0");
  return parts.join("; ");
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "0.0.0.0";
}

async function ipHash(request, pepper) {
  return (await sha256Hex(`ip:${pepper}:${clientIp(request)}`)).slice(0, 24);
}

/** 拒绝跨站发起的写操作（配合 SameSite Cookie 形成双重保护） */
function originAllowed(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true; // 同源表单或非浏览器客户端
  try {
    return new URL(origin).host === new URL(request.url).host;
  } catch {
    return false;
  }
}

async function readJson(request) {
  const type = request.headers.get("Content-Type") || "";
  if (!type.includes("application/json")) return null;
  try {
    return await request.json();
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* 限流                                                                */
/* ------------------------------------------------------------------ */

async function checkLock(db, key) {
  const row = await db.prepare("SELECT locked_until FROM login_attempts WHERE attempt_key = ?").bind(key).first();
  if (!row || !row.locked_until) return 0;
  const left = Date.parse(row.locked_until) - Date.now();
  return left > 0 ? left : 0;
}

async function recordFailure(db, key) {
  const now = Date.now();
  const row = await db.prepare("SELECT failures, window_start FROM login_attempts WHERE attempt_key = ?").bind(key).first();
  if (!row) {
    await db
      .prepare("INSERT INTO login_attempts (attempt_key, failures, window_start, locked_until) VALUES (?, 1, ?, NULL)")
      .bind(key, new Date(now).toISOString())
      .run();
    return;
  }
  const withinWindow = now - Date.parse(row.window_start) < FAIL_WINDOW_MS;
  if (!withinWindow) {
    await db
      .prepare("UPDATE login_attempts SET failures = 1, window_start = ?, locked_until = NULL WHERE attempt_key = ?")
      .bind(new Date(now).toISOString(), key)
      .run();
    return;
  }
  const failures = row.failures + 1;
  const lockedUntil = failures >= MAX_FAILURES ? new Date(now + LOCK_MS).toISOString() : null;
  await db
    .prepare("UPDATE login_attempts SET failures = ?, locked_until = ? WHERE attempt_key = ?")
    .bind(failures, lockedUntil, key)
    .run();
}

async function clearFailures(db, keys) {
  for (const key of keys) {
    await db.prepare("DELETE FROM login_attempts WHERE attempt_key = ?").bind(key).run();
  }
}

/* ------------------------------------------------------------------ */
/* 审计日志                                                            */
/* ------------------------------------------------------------------ */

function audit(ctx, db, entry) {
  const stmt = db
    .prepare("INSERT INTO audit_logs (actor_type, actor_id, action, detail, ip_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(entry.actorType, entry.actorId ?? null, entry.action, entry.detail ?? null, entry.ipHash ?? null, nowIso());
  const run = stmt.run().catch(() => {});
  if (ctx && ctx.waitUntil) ctx.waitUntil(run);
}

/* ------------------------------------------------------------------ */
/* 会员会话                                                            */
/* ------------------------------------------------------------------ */

async function createMemberSession(db, memberId, request, pepper) {
  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const expires = new Date(Date.now() + MEMBER_SESSION_MS).toISOString();
  await db
    .prepare(
      `INSERT INTO sessions (member_id, token_hash, expires_at, created_at, last_seen_at, ip_hash, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      memberId,
      tokenHash,
      expires,
      nowIso(),
      nowIso(),
      await ipHash(request, pepper),
      (request.headers.get("User-Agent") || "").slice(0, 200)
    )
    .run();
  return token;
}

/**
 * 每次请求都回到数据库确认：会话有效 + 会员未被暂停/停用/删除。
 * 这样管理员一停用会员，已有 Cookie 立刻失效。
 */
async function getMemberSession(request, env) {
  const token = getCookie(request, MEMBER_COOKIE);
  if (!token) return { state: "anonymous" };

  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT s.id AS session_id, s.expires_at, s.last_seen_at,
            m.id AS member_id, m.member_code, m.name, m.status, m.member_type, m.deleted_at
       FROM sessions s JOIN members m ON m.id = s.member_id
      WHERE s.token_hash = ? AND s.revoked_at IS NULL`
  )
    .bind(tokenHash)
    .first();

  if (!row) return { state: "anonymous" };
  if (Date.parse(row.expires_at) < Date.now()) return { state: "expired" };
  if (row.deleted_at || row.status !== "active") {
    return { state: "blocked", member: { member_code: row.member_code, status: row.status } };
  }

  // 降低写入频率：超过 1 小时才刷新 last_seen_at
  if (Date.now() - Date.parse(row.last_seen_at) > 60 * 60 * 1000) {
    const stamp = nowIso();
    await env.DB.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?").bind(stamp, row.session_id).run();
  }

  return {
    state: "active",
    sessionId: row.session_id,
    member: {
      id: row.member_id,
      member_code: row.member_code,
      name: row.name,
      status: row.status,
      member_type: row.member_type,
    },
  };
}

async function revokeMemberSession(request, env) {
  const token = getCookie(request, MEMBER_COOKIE);
  if (!token) return false;
  const tokenHash = await sha256Hex(token);
  const res = await env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE token_hash = ?").bind(nowIso(), tokenHash).run();
  return res.meta && res.meta.changes > 0;
}

/* ------------------------------------------------------------------ */
/* 管理员会话                                                          */
/* ------------------------------------------------------------------ */

async function getAdminSession(request, env) {
  const token = getCookie(request, ADMIN_COOKIE);
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT a.id, a.username, a.status, s.expires_at
       FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
      WHERE s.token_hash = ? AND s.revoked_at IS NULL`
  )
    .bind(tokenHash)
    .first();
  if (!row) return null;
  if (Date.parse(row.expires_at) < Date.now()) return null;
  if (row.status !== "active") return null;
  return { id: row.id, username: row.username };
}

async function createAdminSession(db, adminId, request) {
  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const expires = new Date(Date.now() + ADMIN_SESSION_MS).toISOString();
  await db
    .prepare(
      `INSERT INTO admin_sessions (admin_id, token_hash, expires_at, created_at, last_seen_at, ip_hash)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(adminId, tokenHash, expires, nowIso(), nowIso(), null)
    .run();
  return token;
}

/* ------------------------------------------------------------------ */
/* 会员登录                                                            */
/* ------------------------------------------------------------------ */

const MSG = {
  codeInvalid: "请检查访问码是否输入正确。",
  memberDisabled: "当前会员权限暂不可用，请联系管理员。",
  rateLimited: "尝试次数过多，请稍后再试。",
  serverError: "系统暂时无法验证，请稍后重试。",
};

async function handleMemberLogin(request, env, ctx) {
  const body = await readJson(request);
  const pepper = env.CODE_PEPPER || "";
  const ip = await ipHash(request, pepper);

  const rawCode = normalizeCode(body && body.code);
  const codeKey = `code:${await sha256Hex(`c:${pepper}:${rawCode.slice(0, 6)}`)}`.slice(0, 30);

  const lock = Math.max(await checkLock(env.DB, `ip:${ip}`), await checkLock(env.DB, codeKey));
  if (lock > 0) {
    return fail(429, "rate_limited", MSG.rateLimited, { "Retry-After": String(Math.ceil(lock / 1000)) });
  }
  if (rawCode.length !== 12) {
    await recordFailure(env.DB, `ip:${ip}`);
    return fail(401, "code_invalid", MSG.codeInvalid);
  }

  const codeHash = await hashCode(rawCode, pepper);
  const row = await env.DB.prepare(
    `SELECT ac.id AS code_id, ac.status AS code_status,
            m.id AS member_id, m.member_code, m.name, m.status, m.member_type, m.deleted_at
       FROM access_codes ac JOIN members m ON m.id = ac.member_id
      WHERE ac.code_hash = ?`
  )
    .bind(codeHash)
    .first();

  if (!row || row.code_status !== "active" || row.deleted_at) {
    await recordFailure(env.DB, `ip:${ip}`);
    await recordFailure(env.DB, codeKey);
    return fail(401, "code_invalid", MSG.codeInvalid);
  }

  if (row.status !== "active") {
    await recordFailure(env.DB, `ip:${ip}`);
    return fail(403, "member_disabled", MSG.memberDisabled);
  }

  const token = await createMemberSession(env.DB, row.member_id, request, pepper);
  await env.DB.prepare("UPDATE members SET last_login_at = ?, updated_at = ? WHERE id = ?")
    .bind(nowIso(), nowIso(), row.member_id)
    .run();
  await clearFailures(env.DB, [`ip:${ip}`, codeKey]);
  audit(ctx, env.DB, { actorType: "member", actorId: row.member_id, action: "member.login", ipHash: ip });

  return json(
    {
      ok: true,
      member: {
        member_code: row.member_code,
        name: row.name,
        status: row.status,
        member_type: row.member_type,
      },
    },
    200,
    { "Set-Cookie": sessionCookie(MEMBER_COOKIE, token, MEMBER_SESSION_MS / 1000) }
  );
}

/* ------------------------------------------------------------------ */
/* 管理员接口：会员管理                                                */
/* ------------------------------------------------------------------ */

function toMemberDto(row) {
  return {
    id: row.id,
    member_code: row.member_code,
    name: row.name,
    contact: row.contact || "",
    wechat_note: row.wechat_note || "",
    source: row.source || "",
    notes: row.notes || "",
    status: row.status,
    member_type: row.member_type,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_login_at: row.last_login_at || "",
    code_hint: row.code_hint || "",
    has_active_code: !!row.code_hint,
  };
}

async function nextMemberCode(db) {
  const row = await db.prepare("SELECT MAX(CAST(SUBSTR(member_code, 3) AS INTEGER)) AS max_no FROM members").first();
  const next = (row && row.max_no ? row.max_no : 0) + 1;
  return `CH${String(next).padStart(3, "0")}`;
}

async function createMemberWithCode(db, input, pepper) {
  const code = generateCode();
  const hash = await hashCode(code, pepper);
  const ts = nowIso();

  for (let attempt = 0; attempt < 3; attempt++) {
    const memberCode = await nextMemberCode(db);
    try {
      const ins = await db
        .prepare(
          `INSERT INTO members (member_code, name, contact, wechat_note, source, notes, status, member_type, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, 'active', 'lifetime', ?, ?)`
        )
        .bind(memberCode, input.name, input.contact || null, input.wechat_note || null, input.source || null, input.notes || null, ts, ts)
        .run();
      const memberId = ins.meta.last_row_id;
      await db
        .prepare(
          `INSERT INTO access_codes (member_id, code_hash, code_hint, status, created_at)
           VALUES (?, ?, ?, 'active', ?)`
        )
        .bind(memberId, hash, codeHint(code), ts)
        .run();
      return { memberId, memberCode, code };
    } catch (err) {
      if (String(err.message || err).includes("UNIQUE")) continue;
      throw err;
    }
  }
  throw new Error("member_code_conflict");
}

async function requireAdmin(request, env) {
  if (!originAllowed(request)) return { error: fail(403, "forbidden_origin", "请求来源不被允许。") };
  const admin = await getAdminSession(request, env);
  if (!admin) return { error: fail(401, "unauthorized", "请先登录管理员后台。") };
  return { admin };
}

async function listMembers(env, url) {
  const q = (url.searchParams.get("q") || "").trim();
  const status = (url.searchParams.get("status") || "").trim();
  const page = Math.max(parseInt(url.searchParams.get("page") || "1", 10), 1);
  const pageSize = Math.min(Math.max(parseInt(url.searchParams.get("page_size") || "20", 10), 1), 100);
  const offset = (page - 1) * pageSize;

  const where = ["m.deleted_at IS NULL"];
  const params = [];
  if (q) {
    where.push("(m.name LIKE ? OR m.member_code LIKE ? OR m.contact LIKE ? OR m.notes LIKE ?)");
    const like = `%${q}%`;
    params.push(like, like, like, like);
  }
  if (status && ["active", "paused", "disabled"].includes(status)) {
    where.push("m.status = ?");
    params.push(status);
  }
  const whereSql = `WHERE ${where.join(" AND ")}`;

  const countRow = await env.DB.prepare(`SELECT COUNT(*) AS total FROM members m ${whereSql}`).bind(...params).first();
  const rows = await env.DB
    .prepare(
      `SELECT m.*, (SELECT ac.code_hint FROM access_codes ac
                     WHERE ac.member_id = m.id AND ac.status = 'active'
                     ORDER BY ac.id DESC LIMIT 1) AS code_hint
         FROM members m ${whereSql}
        ORDER BY m.id DESC LIMIT ? OFFSET ?`
    )
    .bind(...params, pageSize, offset)
    .all();

  return {
    items: (rows.results || []).map(toMemberDto),
    total: countRow ? countRow.total : 0,
    page,
    page_size: pageSize,
  };
}

/* ------------------------------------------------------------------ */
/* 会员中心页面渲染                                                     */
/* ------------------------------------------------------------------ */

const MEMBER_STATUS_TEXT = { active: "正常", paused: "已暂停", disabled: "已停用" };

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeHref(url) {
  const u = String(url || "").trim();
  if (/^https?:\/\//i.test(u) || u.startsWith("/")) return u;
  return "";
}

function plainText(value) {
  return String(value || "")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/[*_`>#]/g, "")
    .trim();
}

function inlineMd(text) {
  let s = escapeHtml(text);
  s = s.replace(/`([^`]+)`/g, (m, code) => `<code>${code}</code>`);
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, label, href) => {
    const safe = safeHref(href);
    if (!safe) return label;
    const external = /^https?:/i.test(safe) ? ' target="_blank" rel="noopener"' : "";
    return `<a href="${safe}"${external}>${label}</a>`;
  });
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  return s;
}

function splitTableRow(line) {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => cell.trim());
}

function isTableSeparator(line) {
  return /^[\s|:-]+$/.test(line) && line.includes("-");
}

function isBlockStart(lines, index) {
  const line = lines[index];
  if (!line) return false;
  return (
    /^#{1,4}\s+/.test(line) ||
    /^```/.test(line.trim()) ||
    /^>\s?/.test(line) ||
    /^\s*[-*]\s+/.test(line) ||
    /^\s*\d+\.\s+/.test(line) ||
    /^!\[[^\]]*\]\([^)]+\)$/.test(line.trim()) ||
    (line.trim().startsWith("|") && index + 1 < lines.length && isTableSeparator(lines[index + 1]))
  );
}

/**
 * 极简 Markdown 渲染（先整体转义，再生成受控标签），
 * 支持标题、段落、列表、引用、表格、代码块、图片与链接。
 */
function renderMarkdown(source) {
  const lines = String(source || "").replace(/\r\n?/g, "\n").split("\n");
  const html = [];
  const toc = [];
  let i = 0;
  let sectionNo = 0;

  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }

    // 代码块
    if (/^```/.test(line.trim())) {
      const lang = line.trim().slice(3).trim();
      const code = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i].trim())) {
        code.push(lines[i]);
        i++;
      }
      i++;
      html.push(`<pre><code>${escapeHtml(code.join("\n"))}</code></pre>`);
      continue;
    }

    // 标题
    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      const level = heading[1].length <= 2 ? 2 : heading[1].length;
      const raw = heading[2].trim();
      const id = `sec-${++sectionNo}`;
      html.push(`<h${level} id="${id}">${inlineMd(raw)}</h${level}>`);
      if (level === 2 || level === 3) toc.push({ id, level, text: plainText(raw) });
      i++;
      continue;
    }

    // 表格
    if (line.trim().startsWith("|") && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      const head = splitTableRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) {
        rows.push(splitTableRow(lines[i]));
        i++;
      }
      html.push(
        `<div class="table-wrap"><table><thead><tr>${head
          .map((c) => `<th>${inlineMd(c)}</th>`)
          .join("")}</tr></thead><tbody>${rows
          .map((r) => `<tr>${r.map((c) => `<td>${inlineMd(c)}</td>`).join("")}</tr>`)
          .join("")}</tbody></table></div>`
      );
      continue;
    }

    // 列表
    const orderedMatch = line.match(/^\s*\d+\.\s+(.*)$/);
    const unorderedMatch = line.match(/^\s*[-*]\s+(.*)$/);
    if (orderedMatch || unorderedMatch) {
      const ordered = !!orderedMatch;
      const items = [];
      while (i < lines.length) {
        const m = ordered ? lines[i].match(/^\s*\d+\.\s+(.*)$/) : lines[i].match(/^\s*[-*]\s+(.*)$/);
        if (!m) break;
        items.push(m[1]);
        i++;
      }
      html.push(
        ordered
          ? `<ol>${items.map((t) => `<li>${inlineMd(t)}</li>`).join("")}</ol>`
          : `<ul>${items.map((t) => `<li>${inlineMd(t)}</li>`).join("")}</ul>`
      );
      continue;
    }

    // 引用
    if (/^>\s?/.test(line)) {
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) {
        buf.push(lines[i].replace(/^>\s?/, ""));
        i++;
      }
      html.push(`<blockquote><p>${inlineMd(buf.join(" "))}</p></blockquote>`);
      continue;
    }

    // 独立图片
    const image = line.trim().match(/^!\[([^\]]*)\]\(([^)\s]+)\)$/);
    if (image) {
      const safe = safeHref(image[2]);
      if (safe) {
        html.push(
          `<figure><img src="${safe}" alt="${escapeHtml(image[1])}" loading="lazy">${
            image[1] ? `<figcaption>${escapeHtml(image[1])}</figcaption>` : ""
          }</figure>`
        );
      } else {
        html.push(`<p>${escapeHtml(image[1])}</p>`);
      }
      i++;
      continue;
    }

    // 段落
    const para = [line.trim()];
    i++;
    while (i < lines.length && lines[i].trim() && !isBlockStart(lines, i)) {
      para.push(lines[i].trim());
      i++;
    }
    html.push(`<p>${inlineMd(para.join(" "))}</p>`);
  }

  return { html: html.join("\n"), toc };
}

function formatDate(value) {
  return value ? String(value).slice(0, 10) : "";
}

function shortDate(value) {
  const d = formatDate(value);
  return d ? d.replace(/-/g, ".") : "—";
}

/* ------------------------------------------------------------------ */
/* 网站基础设置                                                        */
/* ------------------------------------------------------------------ */

const SITE_DEFAULT = {
  brand_name: "独立站春哥",
  tagline: "独立站出海实战教学与创业陪跑",
  intro: "帮助独立站新手从选品、建站、营销到实现第一单。",
  wechat: "ch022427",
  footer_text: "© 2026 独立站春哥（亿级操盘手）｜带教咨询微信：ch022427",
};

const SITE_LIMITS = { brand_name: 30, tagline: 60, intro: 200, wechat: 40, footer_text: 160 };

// 设置命中率极高、改动很少，按 Worker 实例缓存 60 秒，避免每个页面都查库
let siteCache = { at: 0, value: null };

async function loadSite(env) {
  const now = Date.now();
  if (siteCache.value && now - siteCache.at < 60000) return siteCache.value;

  const site = { ...SITE_DEFAULT };
  try {
    const rows = (await env.DB.prepare("SELECT key, value FROM settings").all()).results || [];
    for (const row of rows) {
      const value = typeof row.value === "string" ? row.value.trim() : "";
      if (row.key in SITE_DEFAULT && value) site[row.key] = value;
    }
  } catch {
    // settings 表尚未建立时使用默认值
  }
  siteCache = { at: now, value: site };
  return site;
}

function resetSiteCache() {
  siteCache = { at: 0, value: null };
}

function siteChanged(site) {
  return Object.keys(SITE_DEFAULT).some((key) => site[key] !== SITE_DEFAULT[key]);
}

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * 页面文案里的品牌名、微信、定位、简介与页脚都是固定默认文案，
 * 这里按整词替换成后台设置值，静态页与 Worker 渲染页都能统一生效。
 */
function rewriteSiteText(html, site) {
  const map = new Map();
  if (site.footer_text !== SITE_DEFAULT.footer_text) map.set(SITE_DEFAULT.footer_text, site.footer_text);
  if (site.tagline !== SITE_DEFAULT.tagline) map.set(SITE_DEFAULT.tagline, site.tagline);
  if (site.intro !== SITE_DEFAULT.intro) map.set(SITE_DEFAULT.intro, site.intro);
  if (site.brand_name !== SITE_DEFAULT.brand_name) map.set(SITE_DEFAULT.brand_name, site.brand_name);
  if (site.wechat !== SITE_DEFAULT.wechat) map.set(SITE_DEFAULT.wechat, site.wechat);
  if (!map.size) return html;

  const pattern = new RegExp([...map.keys()].map(escapeRegExp).join("|"), "g");
  return html.replace(pattern, (match) => map.get(match));
}

/** 统一在出口处给 HTML 页面套用网站设置（只改文案，不改逻辑） */
async function applySiteSettings(response, request, env) {
  const type = response.headers.get("Content-Type") || "";
  if (!type.includes("text/html") || request.method === "HEAD") return response;

  let site;
  try {
    site = await loadSite(env);
  } catch {
    return response;
  }
  if (!siteChanged(site)) return response;

  const html = await response.text();
  const rewritten = rewriteSiteText(html, site);

  const headers = new Headers(response.headers);
  headers.delete("Content-Length");
  headers.delete("ETag");
  headers.delete("Last-Modified");
  return new Response(rewritten, { status: response.status, headers });
}

function normalizeSiteInput(body) {
  const values = {};
  for (const key of Object.keys(SITE_DEFAULT)) {
    const raw = typeof body[key] === "string" ? body[key] : "";
    const value = raw.replace(/[<>]/g, "").trim();
    if (!value) {
      values[key] = SITE_DEFAULT[key];
      continue;
    }
    if (value.length > SITE_LIMITS[key]) {
      return { error: "invalid_settings", message: `字段内容过长，请控制在 ${SITE_LIMITS[key]} 个字符以内。` };
    }
    values[key] = value;
  }
  if (!values.brand_name) return { error: "invalid_settings", message: "品牌名称不能为空。" };
  if (!values.wechat) return { error: "invalid_settings", message: "咨询微信不能为空。" };
  return values;
}

function accessTag(level) {
  return level === "free"
    ? '<span class="m-tag free">免费</span>'
    : '<span class="m-tag member">会员</span>';
}

function memberInitial(name) {
  const s = String(name || "").trim();
  return s ? s.slice(0, 1) : "春";
}

function memberNav(active) {
  const items = [
    ["home", "/member/app/", "会员首页", "01"],
    ["courses", "/member/app/courses/", "图文实战课程", "02"],
    ["tools", "/member/app/tools/", "网页工具库", "03"],
    ["sop", "/member/app/sop/", "AI 实操 SOP", "04"],
    ["resources", "/member/app/resources/", "运营资料库", "05"],
    ["updates", "/member/app/updates/", "更新内容", "06"],
  ];
  return items
    .map(
      ([key, href, label, num]) =>
        `<a class="${active === key ? "is-active" : ""}" href="${href}"${
          active === key ? ' aria-current="page"' : ""
        }><span>${label}</span><small>${num}</small></a>`
    )
    .join("");
}

function memberShell({ title, active, member, body }) {
  const statusText = MEMBER_STATUS_TEXT[member.status] || "正常";
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}｜会员中心｜独立站春哥</title>
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#0e1318">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/css/style.css">
<link rel="stylesheet" href="/assets/css/member.css">
</head>
<body class="member-page">
<div class="m-overlay" id="m-overlay"></div>
<div class="m-shell">
  <aside class="m-side">
    <a class="brand" href="/member/app/" aria-label="会员中心首页">
      <span class="brand-mark">春</span>
      <span class="brand-text">
        <span class="brand-name">独立站春哥</span>
        <span class="brand-sub">MEMBER CENTER</span>
      </span>
    </a>
    <p class="m-side-badge">Member Only</p>
    <p class="m-side-owner">付费会员专享<br>带教咨询微信 ch022427</p>
    <nav class="m-nav" aria-label="会员中心导航">${memberNav(active)}</nav>
    <div class="m-side-foot">
      <div class="m-identity">
        <div class="m-identity-top">
          <span class="m-avatar" aria-hidden="true">${escapeHtml(memberInitial(member.name))}</span>
          <div>
            <div class="m-identity-name">${escapeHtml(member.name)}</div>
            <div class="m-identity-code">${escapeHtml(member.member_code)}</div>
          </div>
        </div>
        <span class="m-status"><i aria-hidden="true"></i>${statusText} · 永久会员</span>
        <div class="m-side-actions">
          <button class="m-linkbtn" type="button" data-logout>退出登录</button>
          <a class="m-linkbtn" href="/">返回公开站</a>
        </div>
        <p class="m-side-contact">带教咨询微信 ch022427</p>
      </div>
    </div>
  </aside>

  <main class="m-main">
    <div class="m-topbar">
      <button class="m-burger" id="m-burger" type="button" aria-label="打开会员导航" aria-expanded="false">
        <span></span><span></span><span></span>
      </button>
      <span class="m-topbar-title">会员中心</span>
      <span class="m-topbar-code">${escapeHtml(member.member_code)}</span>
    </div>
    <div class="m-page">
      <div class="m-container">
${body}
      </div>
    </div>
  </main>
</div>
<script src="/assets/js/member.js" defer></script>
</body>
</html>`;
}

function publicShell({ title, description, body }) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}｜独立站春哥</title>
<meta name="description" content="${escapeHtml(description)}">
<meta name="theme-color" content="#0e1318">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/css/style.css">
<link rel="stylesheet" href="/assets/css/member.css">
<script>document.documentElement.classList.add("js");</script>
</head>
<body>
<header class="site-header">
  <div class="container header-inner">
    <a class="brand" href="/" aria-label="独立站春哥 首页">
      <span class="brand-mark">春</span>
      <span class="brand-text">
        <span class="brand-name">独立站春哥</span>
        <span class="brand-sub">CHUNGE · DTC</span>
      </span>
    </a>
    <nav class="nav" aria-label="主导航">
      <a href="/">首页</a>
      <a href="/guide/">独立站入门</a>
      <a href="/products/">选品知识库</a>
      <a href="/build/">建站教程</a>
      <a href="/marketing/">营销知识</a>
      <a href="/cases/">学员案例</a>
    </nav>
    <a class="btn btn-dark btn-sm header-cta" href="/member/">会员中心</a>
    <button class="nav-toggle" type="button" aria-label="打开菜单" aria-expanded="false" aria-controls="mobile-nav">
      <span></span><span></span><span></span>
    </button>
  </div>
</header>
<div class="mobile-nav" id="mobile-nav">
  <a href="/">首页 <small>01</small></a>
  <a href="/guide/">独立站入门 <small>02</small></a>
  <a href="/products/">选品知识库 <small>03</small></a>
  <a href="/build/">建站教程 <small>04</small></a>
  <a href="/marketing/">营销知识 <small>05</small></a>
  <a href="/cases/">学员案例 <small>06</small></a>
  <a class="btn btn-primary btn-block" href="/member/">进入会员中心</a>
  <p class="mobile-nav-foot">付费会员专享｜带教咨询微信 ch022427</p>
</div>
<main>
  <div class="m-page">
    <div class="m-container">
${body}
    </div>
  </div>
</main>
<footer class="site-footer">
  <div class="container">
    <div class="footer-bottom" style="margin-top:0;padding-top:28px;border-top:1px solid var(--line);">
      <span>© 2026 独立站春哥（亿级操盘手）｜带教咨询微信：ch022427</span>
      <span class="mono">CHUNGE · MEMBER CENTER V1</span>
    </div>
  </div>
</footer>
<script src="/assets/js/site.js" defer></script>
</body>
</html>`;
}

function statePage({ title, heading, message, memberCode, actionHref, actionText, status = 403 }) {
  return new Response(
    `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}｜独立站春哥</title>
<meta name="robots" content="noindex, nofollow">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/css/style.css">
<link rel="stylesheet" href="/assets/css/member.css">
</head>
<body class="member-page">
<div class="m-state-page">
  <div class="m-state-card">
    <span class="m-state-ico" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
    </span>
    <h1>${escapeHtml(heading)}</h1>
    <p>${escapeHtml(message)}</p>
    ${memberCode ? `<p class="m-state-code">会员编号 ${escapeHtml(memberCode)}</p>` : ""}
    <a class="btn btn-primary" href="${actionHref}">${escapeHtml(actionText)}</a>
    <p style="margin-top:18px;font-size:12px;">带教咨询微信 ch022427</p>
  </div>
</div>
</body>
</html>`,
    {
      status,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS },
    }
  );
}

/* --------------------------- 管理后台页面 --------------------------- */

function adminAuthPage({ needsSetup }) {
  const setupBlock = needsSetup
    ? `<div class="a-auth-note">首次部署：请创建管理员账号。初始化完成后，本入口会自动关闭。</div>`
    : "";
  const fields = needsSetup
    ? `<label class="a-field"><span>管理员账号</span><input name="username" autocomplete="username" placeholder="3-20 位字母、数字或下划线" required></label>
       <label class="a-field"><span>管理员密码</span><input name="password" type="password" autocomplete="new-password" placeholder="至少 10 位" required></label>
       <label class="a-field"><span>初始化令牌（可选）</span><input name="setup_token" placeholder="如已配置 ADMIN_SETUP_TOKEN 请填写"></label>`
    : `<label class="a-field"><span>管理员账号</span><input name="username" autocomplete="username" placeholder="请输入管理员账号" required></label>
       <label class="a-field"><span>管理员密码</span><input name="password" type="password" autocomplete="current-password" placeholder="请输入管理员密码" required></label>`;

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${needsSetup ? "初始化管理员" : "管理员登录"}｜独立站春哥</title>
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#0e1318">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/css/style.css">
<link rel="stylesheet" href="/assets/css/admin.css">
</head>
<body class="admin-page" data-page="${needsSetup ? "setup" : "login"}">
<div class="a-auth">
  <div class="a-auth-card">
    <a class="a-brand" href="/">
      <span class="brand-mark">春</span>
      <span class="brand-text">
        <span class="brand-name">独立站春哥</span>
        <span class="brand-sub">ADMIN CONSOLE</span>
      </span>
    </a>
    <h1>${needsSetup ? "初始化管理员账号" : "管理员登录"}</h1>
    <p class="a-auth-desc">${needsSetup ? "该入口只在系统没有任何管理员时出现。初始化完成后，请妥善保存账号密码。" : "后台只允许管理员进入，会员账号无法访问。"}</p>
    ${setupBlock}
    <form id="admin-auth-form" class="a-form" novalidate>
      ${fields}
      <p class="a-form-alert" id="admin-auth-alert" hidden></p>
      <button class="btn btn-primary btn-block" type="submit" id="admin-auth-submit">${needsSetup ? "创建管理员" : "登录后台"}</button>
    </form>
    <p class="a-auth-foot">© 2026 独立站春哥（亿级操盘手）｜带教咨询微信：ch022427</p>
  </div>
</div>
<script src="/assets/js/admin.js" defer></script>
</body>
</html>`;
}

function adminShell({ title, active, admin, page, body }) {
  const nav = [
    ["overview", "/admin/", "概览"],
    ["members", "/admin/members/", "会员管理"],
    ["content", "/admin/content/", "课程管理"],
    ["resources", "/admin/resources/", "资料管理"],
    ["tools", "/admin/tools/", "工具管理"],
    ["settings", "/admin/settings/", "网站设置"],
    ["audit", "/admin/audit/", "操作日志"],
  ]
    .map(
      ([key, href, label]) =>
        `<a class="${active === key ? "is-active" : ""}" href="${href}"${
          active === key ? ' aria-current="page"' : ""
        }>${label}</a>`
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}｜管理后台｜独立站春哥</title>
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#0e1318">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/css/style.css">
<link rel="stylesheet" href="/assets/css/member.css">
<link rel="stylesheet" href="/assets/css/admin.css">
</head>
<body class="admin-page" data-page="${page}">
<header class="a-top">
  <div class="a-top-inner">
    <a class="a-brand" href="/admin/" aria-label="管理后台首页">
      <span class="brand-mark">春</span>
      <span class="brand-text">
        <span class="brand-name">独立站春哥</span>
        <span class="brand-sub">ADMIN CONSOLE</span>
      </span>
    </a>
    <nav class="a-nav" aria-label="后台导航">${nav}</nav>
    <div class="a-top-right">
      <a class="a-top-link" href="/member/app/" target="_blank" rel="noopener">会员中心</a>
      <span class="a-admin-name">${escapeHtml(admin.username)}</span>
      <button class="a-logout" type="button" data-admin-logout>退出</button>
    </div>
  </div>
</header>
<main class="a-wrap">
${body}
</main>
<div class="a-toast" id="a-toast" role="status" aria-live="polite"></div>
<script src="/assets/js/admin.js" defer></script>
</body>
</html>`;
}

function adminOverviewBody() {
  return `
<div class="a-page-head">
  <div>
    <span class="a-eyebrow">Dashboard</span>
    <h1>后台概览</h1>
    <p>会员、课程与资料的整体状态。所有操作都会记录到安全日志。</p>
  </div>
  <a class="btn btn-ghost btn-sm" href="/admin/members/">去添加会员</a>
</div>
<div class="a-stats" id="overview-stats">
  <div class="a-stat"><span>加载中</span><b>—</b></div>
</div>
<div class="a-two-col">
  <section class="a-panel">
    <div class="a-panel-head"><h2>最近操作</h2><a href="/admin/audit/">查看全部</a></div>
    <div id="overview-audit" class="a-panel-body"><p class="a-empty">加载中…</p></div>
  </section>
  <section class="a-panel">
    <div class="a-panel-head"><h2>常用操作</h2></div>
    <div class="a-panel-body a-quick">
      <a href="/admin/members/"><b>添加会员</b><span>生成会员编号与专属访问码</span></a>
      <a href="/admin/content/"><b>写一篇课程</b><span>Markdown 编辑，可存草稿或发布</span></a>
      <a href="/admin/resources/"><b>添加资料</b><span>登记文件信息，第五轮接入 R2 上传</span></a>
      <a href="/admin/audit/"><b>查看安全日志</b><span>登录、重置访问码与内容操作记录</span></a>
    </div>
  </section>
</div>`;
}

function adminMembersBody() {
  return `
<div class="a-page-head">
  <div>
    <span class="a-eyebrow">Members</span>
    <h1>会员管理</h1>
    <p>添加会员后系统会生成唯一编号与访问码。明文访问码只在生成时显示一次。</p>
  </div>
  <button class="btn btn-primary btn-sm" type="button" data-open-member>添加会员</button>
</div>
<div class="a-toolbar">
  <input class="a-input" id="member-search" type="search" placeholder="搜索姓名、编号、联系方式或备注">
  <select class="a-input" id="member-status">
    <option value="">全部状态</option>
    <option value="active">正常</option>
    <option value="paused">已暂停</option>
    <option value="disabled">已停用</option>
  </select>
  <button class="btn btn-ghost btn-sm" type="button" id="member-search-btn">筛选</button>
  <div class="a-toolbar-spacer"></div>
  <a class="btn btn-ghost btn-sm" href="/api/admin/members/export">导出 CSV</a>
</div>
<div class="a-table-wrap">
  <table class="a-table">
    <thead>
      <tr>
        <th>会员编号</th><th>会员</th><th>访问码</th><th>状态</th>
        <th>添加时间</th><th>最近登录</th><th class="a-right">操作</th>
      </tr>
    </thead>
    <tbody id="member-rows">
      <tr><td colspan="7" class="a-empty">加载中…</td></tr>
    </tbody>
  </table>
</div>
<div class="a-pager" id="member-pager"></div>

<dialog class="a-dialog" id="member-dialog">
  <form id="member-form" class="a-form">
    <div class="a-dialog-head"><h2>添加会员</h2><button type="button" class="a-close" data-close-dialog aria-label="关闭">×</button></div>
    <div class="a-form-grid">
      <label class="a-field"><span>会员姓名或昵称 *</span><input name="name" maxlength="60" required placeholder="例如：张三 / 阿 May"></label>
      <label class="a-field"><span>联系方式</span><input name="contact" maxlength="120" placeholder="手机号或邮箱，选填"></label>
      <label class="a-field"><span>微信备注</span><input name="wechat_note" maxlength="120" placeholder="微信号或备注名，选填"></label>
      <label class="a-field"><span>会员来源</span><input name="source" maxlength="60" placeholder="例如：老学员介绍 / 直播"></label>
    </div>
    <label class="a-field"><span>管理员备注</span><textarea name="notes" rows="3" maxlength="500" placeholder="选填"></textarea></label>
    <p class="a-form-alert" id="member-alert" hidden></p>
    <div class="a-dialog-foot">
      <button class="btn btn-ghost btn-sm" type="button" data-close-dialog>取消</button>
      <button class="btn btn-primary btn-sm" type="submit" id="member-submit">生成会员访问码</button>
    </div>
  </form>
</dialog>

<dialog class="a-dialog" id="code-dialog">
  <div class="a-dialog-head"><h2>访问码已生成</h2><button type="button" class="a-close" data-close-dialog aria-label="关闭">×</button></div>
  <div class="a-code-box">
    <p>请立即把下面的访问码发给会员。为安全起见，后台只保存哈希，之后无法再次查看明文。</p>
    <div class="a-code-value" id="code-value">—</div>
    <p class="a-code-meta" id="code-meta"></p>
    <div class="a-dialog-foot">
      <button class="btn btn-ghost btn-sm" type="button" id="code-copy">复制访问码</button>
      <button class="btn btn-primary btn-sm" type="button" data-close-dialog>我已保存</button>
    </div>
  </div>
</dialog>`;
}

function adminContentBody() {
  return `
<div class="a-page-head">
  <div>
    <span class="a-eyebrow">Courses</span>
    <h1>课程管理</h1>
    <p>课程正文使用 Markdown。草稿不会出现在会员中心；发布后立即对正常会员可见。</p>
  </div>
  <button class="btn btn-primary btn-sm" type="button" data-new-content>新建课程</button>
</div>
<div class="a-toolbar">
  <input class="a-input" id="content-search" type="search" placeholder="搜索课程标题或 slug">
  <select class="a-input" id="content-status">
    <option value="">全部状态</option>
    <option value="published">已发布</option>
    <option value="draft">草稿</option>
    <option value="archived">已下架</option>
  </select>
  <button class="btn btn-ghost btn-sm" type="button" id="content-search-btn">筛选</button>
  <div class="a-toolbar-spacer"></div>
  <span class="a-hint">支持标题、段落、列表、表格、图片与代码块</span>
</div>
<div class="a-table-wrap">
  <table class="a-table">
    <thead>
      <tr><th>课程</th><th>分类</th><th>权限</th><th>状态</th><th>排序</th><th>更新时间</th><th class="a-right">操作</th></tr>
    </thead>
    <tbody id="content-rows">
      <tr><td colspan="7" class="a-empty">加载中…</td></tr>
    </tbody>
  </table>
</div>

<dialog class="a-dialog a-dialog-wide" id="content-dialog">
  <form id="content-form" class="a-form">
    <div class="a-dialog-head">
      <h2 id="content-dialog-title">新建课程</h2>
      <button type="button" class="a-close" data-close-dialog aria-label="关闭">×</button>
    </div>
    <div class="a-form-grid">
      <label class="a-field"><span>标题 *</span><input name="title" maxlength="120" required placeholder="例如：90 天从 0 到第一单"></label>
      <label class="a-field"><span>访问路径（slug）*</span><input name="slug" maxlength="80" required placeholder="例如：90-day-roadmap"></label>
      <label class="a-field"><span>课程分类</span><select name="category_id" id="content-category"></select></label>
      <label class="a-field"><span>内容类型</span><select name="content_type"><option value="article">图文课程</option><option value="chapter">章节</option></select></label>
      <label class="a-field"><span>权限</span><select name="access_level"><option value="member">会员专属</option><option value="free">免费公开</option></select></label>
      <label class="a-field"><span>状态</span><select name="status"><option value="draft">草稿</option><option value="published">发布</option><option value="archived">下架</option></select></label>
      <label class="a-field"><span>排序（越小越靠前）</span><input name="sort_order" type="number" min="0" max="9999" value="0"></label>
    </div>
    <label class="a-field"><span>摘要（列表与搜索结果用）</span><textarea name="excerpt" rows="2" maxlength="300" placeholder="一句话说明这篇内容解决什么问题"></textarea></label>
    <label class="a-field"><span>正文（Markdown）*</span><textarea name="body" rows="16" class="a-code-input" placeholder="## 小节标题&#10;&#10;正文段落…"></textarea></label>
    <div class="a-media-bar">
      <span>正文配图</span>
      <input type="file" id="content-image" accept="image/png,image/jpeg,image/webp,image/gif">
      <button class="btn btn-ghost btn-sm" type="button" id="content-image-upload">上传并插入</button>
      <span class="a-hint" id="content-image-hint">支持 JPG / PNG / WebP / GIF，5 MB 以内。</span>
    </div>
    <div class="a-media-bar">
      <span>课程附件</span>
      <input type="file" id="content-attach">
      <button class="btn btn-ghost btn-sm" type="button" id="content-attach-upload">上传附件</button>
      <button class="btn btn-ghost btn-sm" type="button" id="content-attach-remove" hidden>删除附件</button>
      <span class="a-hint" id="content-attach-hint">保存课程后可上传，≤200 MB，存 R2 私有存储，仅授权用户可下载。</span>
    </div>
    <p class="a-form-alert" id="content-alert" hidden></p>
    <div class="a-dialog-foot">
      <span class="a-hint" id="content-meta"></span>
      <button class="btn btn-ghost btn-sm" type="button" data-close-dialog>取消</button>
      <button class="btn btn-primary btn-sm" type="submit" id="content-submit">保存</button>
    </div>
  </form>
</dialog>`;
}

function adminToolsBody() {
  return `
<div class="a-page-head">
  <div>
    <span class="a-eyebrow">Tools</span>
    <h1>工具管理</h1>
    <p>维护会员工具库的入口、说明与上下架状态。工具核心计算逻辑在服务端，页面入口必须使用站内受保护路径。</p>
  </div>
  <button class="btn btn-primary btn-sm" type="button" data-new-tool>添加工具</button>
</div>
<div class="a-toolbar">
  <span class="a-hint">新增工具前，先在 <code>public/tools/</code> 下准备好页面，再把入口填成 <code>/tools/工具标识/</code>。</span>
</div>
<div class="a-table-wrap">
  <table class="a-table">
    <thead>
      <tr><th>工具</th><th>入口</th><th>权限</th><th>状态</th><th>更新时间</th><th class="a-right">操作</th></tr>
    </thead>
    <tbody id="tool-rows">
      <tr><td colspan="6" class="a-empty">加载中…</td></tr>
    </tbody>
  </table>
</div>

<dialog class="a-dialog a-dialog-wide" id="tool-dialog">
  <form id="tool-form" class="a-form">
    <div class="a-dialog-head">
      <h2 id="tool-dialog-title">添加工具</h2>
      <button type="button" class="a-close" data-close-dialog aria-label="关闭">×</button>
    </div>
    <div class="a-form-grid">
      <label class="a-field"><span>工具名称 *</span><input name="name" maxlength="80" required placeholder="例如：物流成本计算器"></label>
      <label class="a-field"><span>工具标识（slug）*</span><input name="slug" maxlength="64" required placeholder="例如：logistics"></label>
      <label class="a-field"><span>入口路径 *</span><input name="entry_url" maxlength="200" required placeholder="例如：/tools/logistics/"></label>
      <label class="a-field"><span>权限</span><select name="access_level"><option value="member">会员专属</option><option value="free">免费公开</option></select></label>
      <label class="a-field"><span>状态</span><select name="status"><option value="draft">草稿</option><option value="published">发布</option><option value="archived">下架</option></select></label>
      <label class="a-field"><span>排序（越小越靠前）</span><input name="sort_order" type="number" min="0" max="9999" value="0"></label>
    </div>
    <label class="a-field"><span>工具介绍</span><textarea name="intro" rows="3" maxlength="300" placeholder="一句话说明这个工具解决什么问题"></textarea></label>
    <label class="a-field"><span>使用说明</span><textarea name="usage_text" rows="2" maxlength="300" placeholder="例如：填入采购成本与目标毛利，得到建议售价"></textarea></label>
    <p class="a-form-alert" id="tool-alert" hidden></p>
    <div class="a-dialog-foot">
      <button class="btn btn-ghost btn-sm" type="button" data-close-dialog>取消</button>
      <button class="btn btn-primary btn-sm" type="submit" id="tool-submit">保存</button>
    </div>
  </form>
</dialog>`;
}

function adminResourcesBody() {
  return `
<div class="a-page-head">
  <div>
    <span class="a-eyebrow">Resources</span>
    <h1>资料管理</h1>
    <p>登记资料元数据与 R2 文件路径。付费文件必须放在私有存储，由服务端校验会员后下载。</p>
  </div>
  <button class="btn btn-primary btn-sm" type="button" data-new-resource>添加资料</button>
</div>
<div class="a-toolbar">
  <span class="a-hint">文件可在编辑弹窗内直接上传到 R2 私有存储；付费资料只通过服务端校验会员后下载。</span>
</div>
<div class="a-table-wrap">
  <table class="a-table">
    <thead>
      <tr><th>资料</th><th>分类</th><th>文件</th><th>权限</th><th>状态</th><th>更新时间</th><th class="a-right">操作</th></tr>
    </thead>
    <tbody id="resource-rows">
      <tr><td colspan="7" class="a-empty">加载中…</td></tr>
    </tbody>
  </table>
</div>

<dialog class="a-dialog a-dialog-wide" id="resource-dialog">
  <form id="resource-form" class="a-form">
    <div class="a-dialog-head">
      <h2 id="resource-dialog-title">添加资料</h2>
      <button type="button" class="a-close" data-close-dialog aria-label="关闭">×</button>
    </div>
    <div class="a-form-grid">
      <label class="a-field"><span>资料名称 *</span><input name="title" maxlength="120" required placeholder="例如：独立站 90 天执行清单"></label>
      <label class="a-field"><span>资料分类</span><select name="category_id" id="resource-category"></select></label>
      <label class="a-field"><span>R2 文件路径 *</span><input name="file_key" maxlength="200" required placeholder="例如：resources/90-day-checklist.pdf"></label>
      <label class="a-field"><span>下载文件名 *</span><input name="file_name" maxlength="200" required placeholder="例如：chunge-90-day-checklist.pdf"></label>
      <label class="a-field"><span>文件类型</span><input name="file_type" maxlength="12" value="pdf" placeholder="pdf / xlsx / docx / zip"></label>
      <label class="a-field"><span>文件大小（字节）</span><input name="file_size" type="number" min="0" value="0"></label>
      <label class="a-field"><span>版本</span><input name="version" maxlength="30" value="v1.0"></label>
      <label class="a-field"><span>排序</span><input name="sort_order" type="number" min="0" max="9999" value="0"></label>
      <label class="a-field"><span>权限</span><select name="access_level"><option value="member">会员专属</option><option value="free">免费公开</option></select></label>
      <label class="a-field"><span>状态</span><select name="status"><option value="draft">草稿</option><option value="published">发布</option><option value="archived">下架</option></select></label>
    </div>
    <label class="a-field"><span>资料说明</span><textarea name="description" rows="3" maxlength="500" placeholder="这份资料能帮会员解决什么问题"></textarea></label>
    <div class="a-upload" id="resource-upload-box" hidden>
      <div class="a-upload-head">
        <b>上传文件到 R2 私有存储</b>
        <span>新建资料请先保存，再重新打开本弹窗上传。上传后会自动更新文件路径、文件名、类型与大小。</span>
      </div>
      <div class="a-upload-actions">
        <input type="file" id="resource-file">
        <button class="btn btn-ghost btn-sm" type="button" id="resource-upload">上传并保存</button>
      </div>
      <p class="a-hint" id="resource-upload-hint">单个文件不超过 200 MB，文件只对已登录且状态正常的会员开放下载。</p>
    </div>
    <p class="a-form-alert" id="resource-alert" hidden></p>
    <div class="a-dialog-foot">
      <button class="btn btn-ghost btn-sm" type="button" data-close-dialog>取消</button>
      <button class="btn btn-primary btn-sm" type="submit" id="resource-submit">保存</button>
    </div>
  </form>
</dialog>`;
}

function adminAuditBody() {
  return `
<div class="a-page-head">
  <div>
    <span class="a-eyebrow">Security Log</span>
    <h1>操作日志</h1>
    <p>会员登录、管理员操作与资料下载都会记录。IP 只保存哈希，用于异常排查。</p>
  </div>
  <button class="btn btn-ghost btn-sm" type="button" id="audit-refresh">刷新</button>
</div>
<div class="a-table-wrap">
  <table class="a-table">
    <thead><tr><th>时间</th><th>身份</th><th>操作</th><th>详情</th><th>IP 哈希</th></tr></thead>
    <tbody id="audit-rows"><tr><td colspan="5" class="a-empty">加载中…</td></tr></tbody>
  </table>
</div>`;
}

function adminSettingsBody(site) {
  const field = (name, label, hint, maxlength, tag) => {
    const value = escapeHtml(site[name] || SITE_DEFAULT[name]);
    const control =
      tag === "textarea"
        ? `<textarea name="${name}" rows="3" maxlength="${maxlength}">${value}</textarea>`
        : `<input name="${name}" maxlength="${maxlength}" value="${value}">`;
    return `<label class="a-field"><span>${label}</span>${control}<small class="a-hint">${hint}</small></label>`;
  };

  return `
<div class="a-page-head">
  <div>
    <span class="a-eyebrow">Site Settings</span>
    <h1>网站设置</h1>
    <p>这里修改的是全站文案（品牌名、定位、简介、微信与页脚），保存后约 1 分钟内对所有页面生效。页面结构与权限不受影响。</p>
  </div>
</div>
<form class="a-form a-settings-form" id="settings-form">
  <div class="a-form-grid">
    ${field("brand_name", "品牌名称", "显示在导航、页脚与浏览器标题。", 30)}
    ${field("wechat", "带教咨询微信", "页脚、会员中心与工具页都会使用这个微信号。", 40)}
  </div>
  <div class="a-form-grid">
    ${field("tagline", "网站定位", "首页标题与简介中出现的定位语。", 60)}
  </div>
  ${field("intro", "网站简介", "首页介绍文案，一句话说明帮谁解决什么问题。", 200, "textarea")}
  ${field("footer_text", "页脚版权与联系方式", "整行替换页脚文案，包含年份与微信。", 160)}
  <p class="a-form-alert" id="settings-alert" hidden></p>
  <div class="a-dialog-foot">
    <span class="a-hint">留空会恢复为默认文案；请勿填写 HTML 标签。</span>
    <button class="btn btn-primary btn-sm" type="submit" id="settings-submit">保存设置</button>
  </div>
</form>`;
}

async function handleAdminPage(request, env, url, admin) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return fail(405, "method_not_allowed", "不支持该请求方法。");
  }

  const path = url.pathname;
  const pages = {
    "/admin/": { title: "后台概览", active: "overview", page: "overview", body: adminOverviewBody() },
    "/admin/members/": { title: "会员管理", active: "members", page: "members", body: adminMembersBody() },
    "/admin/content/": { title: "课程管理", active: "content", page: "content", body: adminContentBody() },
    "/admin/resources/": { title: "资料管理", active: "resources", page: "resources", body: adminResourcesBody() },
    "/admin/tools/": { title: "工具管理", active: "tools", page: "tools", body: adminToolsBody() },
    "/admin/settings/": { title: "网站设置", active: "settings", page: "settings", body: "" },
    "/admin/audit/": { title: "操作日志", active: "audit", page: "audit", body: adminAuditBody() },
  };
  if (path === "/admin/settings/") pages[path].body = adminSettingsBody(await loadSite(env));
  const page = pages[path];
  if (!page) {
    return new Response(
      adminShell({ title: "页面不存在", active: "", admin, page: "notfound", body: `<div class="a-page-head"><h1>页面不存在</h1></div><a class="btn btn-primary" href="/admin/">返回后台首页</a>` }),
      { status: 404, headers: { "Content-Type": "text/html; charset=utf-8", ...BASE_HEADERS } }
    );
  }
  return new Response(adminShell({ ...page, admin }), {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS },
  });
}

/* --------------------------- 数据查询 --------------------------- */

async function loadCourseData(env) {
  const cats = (await env.DB.prepare(
    "SELECT id, name, slug, description, sort_order FROM content_categories WHERE type = 'course' ORDER BY sort_order, id"
  ).all()).results || [];
  const items = (await env.DB.prepare(
    `SELECT id, title, slug, excerpt, access_level, sort_order, published_at, updated_at, category_id
       FROM contents WHERE status = 'published' ORDER BY sort_order, id`
  ).all()).results || [];
  const grouped = new Map();
  for (const item of items) {
    const key = item.category_id;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(item);
  }
  return { cats, items, grouped };
}

async function loadPublishedTools(env) {
  const rows = await env.DB.prepare(
    "SELECT id, name, slug, intro, usage_text, entry_url, access_level, updated_at FROM tools WHERE status = 'published' ORDER BY sort_order, id"
  ).all();
  return rows.results || [];
}

async function loadPublishedResources(env, slugs) {
  let sql = `SELECT r.*, c.name AS category_name, c.slug AS category_slug
               FROM resources r LEFT JOIN content_categories c ON c.id = r.category_id
              WHERE r.status = 'published'`;
  const params = [];
  if (slugs && slugs.length) {
    sql += ` AND c.slug IN (${slugs.map(() => "?").join(",")})`;
    params.push(...slugs);
  }
  sql += " ORDER BY c.sort_order, r.sort_order, r.id";
  const rows = await env.DB.prepare(sql).bind(...params).all();
  return rows.results || [];
}

/* --------------------------- 页面内容 --------------------------- */

function contentRow(item, index, categoryName) {
  const date = shortDate(item.published_at || item.updated_at);
  return `<div class="m-row">
  <span class="m-row-num">${String(index + 1).padStart(2, "0")}</span>
  <div class="m-row-main">
    <a class="m-row-title" href="/member/app/courses/${escapeHtml(item.slug)}">${escapeHtml(item.title)} ${accessTag(item.access_level)}</a>
    ${item.excerpt ? `<p class="m-row-desc">${escapeHtml(item.excerpt)}</p>` : ""}
  </div>
  <div class="m-row-meta"><span>${escapeHtml(categoryName || "")}</span><span>${date}</span></div>
  <span class="m-row-arrow" aria-hidden="true">→</span>
</div>`;
}

async function renderMemberHome(env, member) {
  const { cats, items, grouped } = await loadCourseData(env);
  const tools = await loadPublishedTools(env);
  const resources = await loadPublishedResources(env);
  const sopContents = items.filter((it) => {
    const cat = cats.find((c) => c.id === it.category_id);
    return cat && ["sop", "prompt"].includes(cat.slug);
  });

  const latest = items
    .slice()
    .sort((a, b) => String(b.published_at || b.updated_at).localeCompare(String(a.published_at || a.updated_at)))
    .slice(0, 4);

  const latestRows = latest
    .map((item, index) => {
      const cat = cats.find((c) => c.id === item.category_id);
      return contentRow(item, index, cat ? cat.name : "");
    })
    .join("");

  const publishedCats = cats.filter((c) => (grouped.get(c.id) || []).length);

  return memberShell({
    title: "会员首页",
    active: "home",
    member,
    body: `
<div class="m-hero">
  <span class="m-eyebrow">Member Center / 会员首页</span>
  <h1>欢迎回来，${escapeHtml(member.name)}</h1>
  <p class="m-hero-lead">这里是你的独立站实战工作台：课程、工具、SOP 与资料都在同一处。建议按模块顺序学习，遇到问题随时微信联系。</p>
  <div class="m-hero-meta">
    <span>会员编号 <b>${escapeHtml(member.member_code)}</b></span>
    <span class="m-tag-ok">正常 · 永久会员</span>
    <span>已发布课程 <b>${items.length}</b> 篇</span>
  </div>
  <div class="m-hero-actions">
    <a class="btn btn-primary" href="/member/app/courses/">开始学习</a>
    <a class="btn btn-ghost-light" href="/member/app/updates/">查看最新更新</a>
  </div>
</div>

<section class="m-section">
  <div class="m-section-head">
    <div>
      <h2>四个常用入口</h2>
      <p>按需求直接进入，不用在导航里来回找。</p>
    </div>
  </div>
  <div class="m-cards">
    <a class="m-card" href="/member/app/courses/">
      <span class="m-card-kicker">COURSE</span>
      <h3>图文实战课程</h3>
      <p>从入门到增长，按模块顺序学完一套完整打法。</p>
      <span class="m-card-foot"><b>${items.length}</b><span>篇已发布 · ${publishedCats.length} 个模块</span></span>
    </a>
    <a class="m-card" href="/member/app/tools/">
      <span class="m-card-kicker">TOOL</span>
      <h3>网页工具库</h3>
      <p>定价、广告、利润计算器，边算边做决策。</p>
      <span class="m-card-foot"><b>${tools.length}</b><span>个工具入口</span></span>
    </a>
    <a class="m-card" href="/member/app/sop/">
      <span class="m-card-kicker">SOP</span>
      <h3>AI 实操 SOP</h3>
      <p>把 AI 用在选品、文案和客服，按步骤执行。</p>
      <span class="m-card-foot"><b>${sopContents.length + resources.filter((r) => ["sop", "prompt"].includes(r.category_slug)).length}</b><span>份流程与提示词</span></span>
    </a>
    <a class="m-card" href="/member/app/resources/">
      <span class="m-card-kicker">RESOURCE</span>
      <h3>运营资料库</h3>
      <p>清单、表格、模板，下载后直接改成自己的。</p>
      <span class="m-card-foot"><b>${resources.length}</b><span>份可下载资料</span></span>
    </a>
  </div>
</section>

<section class="m-section">
  <div class="m-section-head">
    <div>
      <h2>最新更新</h2>
      <p>最近发布的课程与资料。</p>
    </div>
    <a class="m-section-link" href="/member/app/updates/">全部更新</a>
  </div>
  <div class="m-panel">
    <div class="m-panel-body">${latestRows || '<p class="m-empty-row">暂无已发布内容。</p>'}</div>
  </div>
</section>

<div class="m-note">
  <span class="m-note-ico" aria-hidden="true">i</span>
  <div><b>关于演示数据：</b>当前课程与资料为结构与流程示例，管理员可在后台上传正式内容替换。会员访问码只保存在服务端哈希，请勿转发给他人。</div>
</div>`,
  });
}

async function renderCourseIndex(env, member) {
  const { cats, grouped } = await loadCourseData(env);

  const blocks = cats
    .map((cat, index) => {
      const items = grouped.get(cat.id) || [];
      const rows = items.length
        ? items
            .map(
              (item, i) => `<div class="m-row">
  <span class="m-row-num">${String(i + 1).padStart(2, "0")}</span>
  <div class="m-row-main">
    <a class="m-row-title" href="/member/app/courses/${escapeHtml(item.slug)}">${escapeHtml(item.title)} ${accessTag(item.access_level)}</a>
    ${item.excerpt ? `<p class="m-row-desc">${escapeHtml(item.excerpt)}</p>` : ""}
  </div>
  <div class="m-row-meta"><span>${shortDate(item.published_at || item.updated_at)}</span></div>
  <span class="m-row-arrow" aria-hidden="true">→</span>
</div>`
            )
            .join("")
        : '<p class="m-empty-row">该模块内容准备中，敬请期待。</p>';

      return `<div class="m-cat">
  <div class="m-cat-head">
    <span class="m-cat-idx">${String(index + 1).padStart(2, "0")}</span>
    <div>
      <p class="m-cat-name">${escapeHtml(cat.name)}</p>
      ${cat.description ? `<p class="m-cat-desc">${escapeHtml(cat.description)}</p>` : ""}
    </div>
    <span class="m-cat-count">${items.length} 篇</span>
  </div>
  ${rows}
</div>`;
    })
    .join("");

  return memberShell({
    title: "图文实战课程",
    active: "courses",
    member,
    body: `
<div class="m-page-head">
  <div class="m-crumb"><a href="/member/app/">会员首页</a><span>/</span><span>图文实战课程</span></div>
  <h1>图文实战课程</h1>
  <p>按 10 个模块组织，建议从「独立站创业入门」开始顺序阅读。带 <span class="m-tag free">免费</span> 标记的内容同时开放给公开知识库。</p>
</div>

<div class="m-note">
  <span class="m-note-ico" aria-hidden="true">i</span>
  <div><b>学习建议：</b>每个模块先读路线图，再按顺序做一遍。不要只收藏不动手，独立站的进步来自一次次小规模测试。</div>
</div>

<div class="m-cats">${blocks}</div>`,
  });
}

async function renderCourseDetail(env, member, slug) {
  const row = await env.DB.prepare(
    `SELECT c.*, cat.name AS category_name, cat.slug AS category_slug
       FROM contents c LEFT JOIN content_categories cat ON cat.id = c.category_id
      WHERE c.slug = ? AND c.status = 'published'`
  )
    .bind(slug)
    .first();

  if (!row) {
    return {
      status: 404,
      html: memberShell({
        title: "内容不存在",
        active: "courses",
        member,
        body: `<div class="m-page-head"><h1>内容不存在或尚未发布</h1><p>这篇内容可能已下架，或链接不正确。</p></div><a class="btn btn-primary" href="/member/app/courses/">返回课程列表</a>`,
      }),
    };
  }

  const siblings = (await env.DB.prepare(
    "SELECT id, title, slug FROM contents WHERE category_id = ? AND status = 'published' ORDER BY sort_order, id"
  )
    .bind(row.category_id)
    .all()).results || [];

  const currentIndex = siblings.findIndex((s) => s.slug === row.slug);
  const prev = currentIndex > 0 ? siblings[currentIndex - 1] : null;
  const next = currentIndex >= 0 && currentIndex < siblings.length - 1 ? siblings[currentIndex + 1] : null;

  const rendered = renderMarkdown(row.body);
  const attachment = await env.DB.prepare(
    "SELECT file_name, file_size, file_type FROM content_files WHERE content_id = ?"
  )
    .bind(row.id)
    .first();
  const attachmentHtml = attachment
    ? `<div class="m-attach">
      <div>
        <b>课程附件</b>
        <span>${escapeHtml(attachment.file_name)}${
          attachment.file_size ? ` · ${(Number(attachment.file_size) / 1024 / 1024).toFixed(2)} MB` : ""
        }</span>
      </div>
      <a class="btn btn-ghost btn-sm" href="/courses/${escapeHtml(row.slug)}/attachment">下载附件</a>
    </div>`
    : "";
  const tocHtml = rendered.toc.length >= 2
    ? `<div class="m-aside-card"><h3>本篇目录</h3><div class="m-toc">${rendered.toc
        .filter((t) => t.level === 2)
        .map((t) => `<a class="lv2" href="#${t.id}">${escapeHtml(t.text)}</a>`)
        .join("")}</div></div>`
    : "";

  const chaptersHtml = siblings.length
    ? `<div class="m-aside-card"><h3>${escapeHtml(row.category_name || "本模块")}</h3><div class="m-chapters">${siblings
        .map(
          (s, i) =>
            `<a class="${s.slug === row.slug ? "is-current" : ""}" href="/member/app/courses/${escapeHtml(s.slug)}"><i>${String(
              i + 1
            ).padStart(2, "0")}</i>${escapeHtml(s.title)}</a>`
        )
        .join("")}</div></div>`
    : "";

  const body = `
<div class="m-article-layout">
  <div>
    <div class="m-crumb" style="margin-bottom:18px;">
      <a href="/member/app/">会员首页</a><span>/</span>
      <a href="/member/app/courses/">图文实战课程</a><span>/</span>
      <span>${escapeHtml(row.category_name || "课程")}</span>
    </div>
    <div class="m-article-head">
      <div style="display:flex;gap:8px;align-items:center;">${accessTag(row.access_level)}<span class="m-tag soon">${escapeHtml(
        row.category_name || "课程"
      )}</span></div>
      <h1>${escapeHtml(row.title)}</h1>
      <div class="m-article-meta">
        <span>发布 ${formatDate(row.published_at || row.created_at)}</span>
        <span>更新 ${formatDate(row.updated_at)}</span>
        ${row.excerpt ? `<span>${escapeHtml(row.excerpt)}</span>` : ""}
      </div>
    </div>
    ${attachmentHtml}
    <article class="prose m-article-body">${rendered.html}</article>
    <div class="m-article-foot">
      <span>${prev ? `<a href="/member/app/courses/${escapeHtml(prev.slug)}">← ${escapeHtml(prev.title)}</a>` : "<span>已经是第一篇</span>"}</span>
      <span>${next ? `<a href="/member/app/courses/${escapeHtml(next.slug)}">${escapeHtml(next.title)} →</a>` : "<span>本模块已全部读完</span>"}</span>
    </div>
  </div>
  <aside class="m-aside">
    ${tocHtml}
    ${chaptersHtml}
    <div class="m-aside-card">
      <h3>需要帮助</h3>
      <p style="margin-top:10px;font-size:12.5px;line-height:1.8;color:var(--muted);">实操卡住了，直接微信联系带教，说明你卡在哪一步。</p>
      <p style="margin-top:8px;font-family:var(--font-mono);font-size:12px;color:var(--ink);">ch022427</p>
      <button class="m-linkbtn" type="button" data-copy="ch022427">复制微信号</button>
    </div>
  </aside>
</div>`;

  return { status: 200, html: memberShell({ title: row.title, active: "courses", member, body }) };
}

async function renderToolsPage(env, member) {
  const tools = await loadPublishedTools(env);
  const cards = tools
    .map(
      (tool, index) => `<div class="m-tool">
  <span class="m-tool-ico" aria-hidden="true">${String(index + 1).padStart(2, "0")}</span>
  <h3>${escapeHtml(tool.name)}</h3>
  <p>${escapeHtml(tool.intro || "")}</p>
  ${tool.usage_text ? `<div class="m-tool-usage"><b>怎么用：</b>${escapeHtml(tool.usage_text)}</div>` : ""}
  <div class="m-tool-foot">
    ${accessTag(tool.access_level)}
    <span>更新 ${formatDate(tool.updated_at)}</span>
  </div>
  <a class="m-tool-go" href="${escapeHtml(tool.entry_url)}">打开工具 <span aria-hidden="true">→</span></a>
</div>`
    )
    .join("");

  return memberShell({
    title: "网页工具库",
    active: "tools",
    member,
    body: `
<div class="m-page-head">
  <div class="m-crumb"><a href="/member/app/">会员首页</a><span>/</span><span>网页工具库</span></div>
  <h1>网页工具库</h1>
  <p>把定价、广告、利润这些重复计算做成网页工具，填几个数字就能得到结论。</p>
</div>
<div class="m-note">
  <span class="m-note-ico" aria-hidden="true">i</span>
  <div><b>入口已迁移到站内受保护路径：</b>每次打开工具页与每次提交计算，服务端都会重新校验会员身份与工具状态，旧 GitHub Pages 地址不再作为会员入口。</div>
</div>
<div class="m-tools">${cards || '<p class="m-empty-row">暂无已发布工具。</p>'}</div>`,
  });
}

async function renderResourceList(env, member, slugs, title, active, intro) {
  const resources = await loadPublishedResources(env, slugs);
  const rows = resources
    .map(
      (item) => `<div class="m-res">
  <span class="m-file" aria-hidden="true">${escapeHtml(item.file_type || "FILE")}</span>
  <div class="m-res-main">
    <h3>${escapeHtml(item.title)} ${accessTag(item.access_level)}</h3>
    ${item.description ? `<p>${escapeHtml(item.description)}</p>` : ""}
    <div class="m-res-meta">
      <span>${escapeHtml(item.category_name || "资料")}</span>
      <span>${item.version ? escapeHtml(item.version) : "v1.0"}</span>
      <span>${item.file_size ? `${Math.round(item.file_size / 1024)} KB` : "文件待上传"}</span>
      <span>更新 ${formatDate(item.updated_at)}</span>
    </div>
  </div>
  <a class="btn btn-ghost btn-sm" href="/member/app/resources/${item.id}/download">下载</a>
</div>`
    )
    .join("");

  return memberShell({
    title,
    active,
    member,
    body: `
<div class="m-page-head">
  <div class="m-crumb"><a href="/member/app/">会员首页</a><span>/</span><span>${escapeHtml(title)}</span></div>
  <h1>${escapeHtml(title)}</h1>
  <p>${escapeHtml(intro)}</p>
</div>
<div class="m-note">
  <span class="m-note-ico" aria-hidden="true">i</span>
  <div><b>文件保护：</b>付费资料存放在 R2 私有存储，每次下载都会先校验会员身份，不提供公开直链。演示数据尚未上传真实文件。</div>
</div>
<div class="m-res-list">${rows || '<p class="m-empty-row">暂无已发布资料。</p>'}</div>`,
  });
}

async function renderUpdates(env, member) {
  const { cats, items } = await loadCourseData(env);
  const resources = await loadPublishedResources(env);
  const entries = [];

  for (const item of items) {
    const cat = cats.find((c) => c.id === item.category_id);
    entries.push({
      date: item.published_at || item.updated_at,
      type: "课程",
      title: item.title,
      href: `/member/app/courses/${item.slug}`,
      desc: item.excerpt || "",
      tag: accessTag(item.access_level),
    });
  }
  for (const item of resources) {
    entries.push({
      date: item.updated_at,
      type: "资料",
      title: item.title,
      href: `/member/app/resources/${item.id}/download`,
      desc: item.description || "",
      tag: accessTag(item.access_level),
    });
  }

  entries.sort((a, b) => String(b.date).localeCompare(String(a.date)));
  const latest = entries.slice(0, 20);

  const rows = latest
    .map(
      (entry) => `<div class="m-update">
  <span class="m-update-date">${shortDate(entry.date)}</span>
  <div class="m-update-main">
    <a class="m-update-title" href="${entry.href}">${escapeHtml(entry.title)}</a>
    <div class="m-row-title" style="gap:6px;margin-top:6px;">${entry.tag}<span class="m-tag soon">${entry.type}</span></div>
    ${entry.desc ? `<p class="m-update-desc">${escapeHtml(entry.desc)}</p>` : ""}
  </div>
</div>`
    )
    .join("");

  return memberShell({
    title: "更新内容",
    active: "updates",
    member,
    body: `
<div class="m-page-head">
  <div class="m-crumb"><a href="/member/app/">会员首页</a><span>/</span><span>更新内容</span></div>
  <h1>更新内容</h1>
  <p>课程与资料的最近变动，按时间倒序排列。每次更新都会出现在这里。</p>
</div>
<div class="m-panel" style="padding:24px 26px;">
  <div class="m-updates">${rows || '<p class="m-empty-row">暂无更新。</p>'}</div>
</div>`,
  });
}

async function handleMemberApp(request, env, ctx, url, session) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return fail(405, "method_not_allowed", "不支持该请求方法。");
  }

  const path = url.pathname;
  const member = session.member;

  if (path === "/member/app" || path === "/member/app/") {
    return new Response(await renderMemberHome(env, member), {
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS },
    });
  }

  if (path === "/member/app/courses/") {
    return new Response(await renderCourseIndex(env, member), {
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS },
    });
  }

  const courseMatch = path.match(/^\/member\/app\/courses\/([a-z0-9][a-z0-9-]*)\/?$/);
  if (courseMatch) {
    const page = await renderCourseDetail(env, member, courseMatch[1]);
    return new Response(page.html, {
      status: page.status,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS },
    });
  }

  if (path === "/member/app/tools/") {
    return new Response(await renderToolsPage(env, member), {
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS },
    });
  }

  if (path === "/member/app/resources/") {
    return new Response(
      await renderResourceList(
        env,
        member,
        null,
        "运营资料库",
        "resources",
        "SOP、清单、表格与提示词模板，下载后改成自己的版本直接使用。"
      ),
      { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS } }
    );
  }

  if (path === "/member/app/sop/") {
    return new Response(
      await renderResourceList(
        env,
        member,
        ["sop", "prompt"],
        "AI 实操 SOP",
        "sop",
        "把 AI 工作流固化成步骤，从扩词、选品到文案与客服，照着做就能复用。"
      ),
      { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS } }
    );
  }

  if (path === "/member/app/updates/") {
    return new Response(await renderUpdates(env, member), {
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS },
    });
  }

  const downloadMatch = path.match(/^\/member\/app\/resources\/(\d+)\/download$/);
  if (downloadMatch) {
    return handleResourceDownload(request, env, ctx, parseInt(downloadMatch[1], 10), session);
  }

  return new Response(
    memberShell({
      title: "页面不存在",
      active: "",
      member,
      body: `<div class="m-page-head"><h1>页面不存在</h1><p>请从左侧导航重新进入会员中心。</p></div><a class="btn btn-primary" href="/member/app/">返回会员首页</a>`,
    }),
    { status: 404, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS } }
  );
}

async function handleResourceDownload(request, env, ctx, resourceId, session) {
  const row = await env.DB.prepare("SELECT * FROM resources WHERE id = ? AND status = 'published'").bind(resourceId).first();
  if (!row) {
    return statePage({
      title: "资料不存在",
      heading: "资料不存在或已下架",
      message: "该资料可能已被管理员下架，请返回资料库查看最新版本。",
      actionHref: "/member/app/resources/",
      actionText: "返回资料库",
      status: 404,
    });
  }
  if (row.access_level === "member" && session.state !== "active") {
    return statePage({
      title: "需要会员权限",
      heading: "当前账号无权下载该资料",
      message: "请确认会员状态正常后再试。",
      actionHref: "/member/app/resources/",
      actionText: "返回资料库",
    });
  }
  if (!env.R2) {
    return statePage({
      title: "文件尚未上传",
      heading: "文件尚未上传到私有存储",
      message: "当前为演示数据。管理员在后台把真实文件上传到 R2 私有存储后，会员即可在此下载。",
      memberCode: session.member ? session.member.member_code : "",
      actionHref: "/member/app/resources/",
      actionText: "返回资料库",
      status: 404,
    });
  }

  const object = await env.R2.get(row.file_key);
  if (!object) {
    return statePage({
      title: "文件不存在",
      heading: "文件暂不可用",
      message: "文件可能正在更新，请稍后再试或联系管理员。",
      actionHref: "/member/app/resources/",
      actionText: "返回资料库",
      status: 404,
    });
  }

  audit(ctx, env.DB, {
    actorType: "member",
    actorId: session.member.id,
    action: "resource.download",
    detail: `${row.id} ${row.title}`,
  });

  const asciiName = String(row.file_name || "download").replace(/[^\x20-\x7e]/g, "_");
  return new Response(object.body, {
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(row.file_name || "download")}`,
      "Cache-Control": "private, no-store",
      ...BASE_HEADERS,
    },
  });
}

/* --------------------------- 公开免费内容 --------------------------- */

async function handlePublicLibrary(request, env, ctx, url) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return fail(405, "method_not_allowed", "不支持该请求方法。");
  }

  const slug = url.pathname.replace(/^\/library\//, "").replace(/\/$/, "");
  if (!/^[a-z0-9][a-z0-9-]*$/.test(slug)) {
    return new Response("页面不存在", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });
  }

  const row = await env.DB.prepare(
    `SELECT c.*, cat.name AS category_name
       FROM contents c LEFT JOIN content_categories cat ON cat.id = c.category_id
      WHERE c.slug = ? AND c.status = 'published'`
  )
    .bind(slug)
    .first();

  if (!row) {
    return new Response(
      publicShell({
        title: "内容不存在",
        description: "内容不存在或尚未发布。",
        body: `<div class="m-page-head"><h1>内容不存在或尚未发布</h1><p>可以返回首页浏览免费知识库。</p></div><a class="btn btn-primary" href="/">返回首页</a>`,
      }),
      { status: 404, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS } }
    );
  }

  // 会员专属内容不允许通过公开路径绕过登录
  if (row.access_level !== "free") {
    return Response.redirect(`${url.origin}/member/?next=${encodeURIComponent(`/member/app/courses/${row.slug}`)}`, 302);
  }

  const rendered = renderMarkdown(row.body);
  const tocHtml = rendered.toc.length >= 2
    ? `<div class="m-aside-card"><h3>本篇目录</h3><div class="m-toc">${rendered.toc
        .filter((t) => t.level === 2)
        .map((t) => `<a class="lv2" href="#${t.id}">${escapeHtml(t.text)}</a>`)
        .join("")}</div></div>`
    : "";

  const body = `
<div class="m-article-layout">
  <div>
    <div class="m-crumb" style="margin-bottom:18px;">
      <a href="/">首页</a><span>/</span><span>免费知识库</span><span>/</span><span>${escapeHtml(row.category_name || "文章")}</span>
    </div>
    <div class="m-article-head">
      <div style="display:flex;gap:8px;align-items:center;"><span class="m-tag free">免费</span><span class="m-tag soon">${escapeHtml(
        row.category_name || "知识库"
      )}</span></div>
      <h1>${escapeHtml(row.title)}</h1>
      <div class="m-article-meta">
        <span>发布 ${formatDate(row.published_at || row.created_at)}</span>
        <span>更新 ${formatDate(row.updated_at)}</span>
      </div>
    </div>
    <article class="prose m-article-body">${rendered.html}</article>
    <div class="m-note" style="margin-top:40px;">
      <span class="m-note-ico" aria-hidden="true">i</span>
      <div>这篇内容来自公开知识库。想系统学完 10 个模块，并获得工具与资料，可以了解会员权益：<a href="/member/" style="color:var(--orange-deep);">进入会员中心</a>。</div>
    </div>
  </div>
  <aside class="m-aside">
    ${tocHtml}
    <div class="m-aside-card">
      <h3>会员专享</h3>
      <p style="margin-top:10px;font-size:12.5px;line-height:1.8;color:var(--muted);">体系课程、网页工具与可下载资料，凭专属访问码进入。</p>
      <a class="btn btn-primary btn-sm" style="margin-top:14px;" href="/member/">了解会员</a>
    </div>
  </aside>
</div>`;

  return new Response(publicShell({ title: row.title, description: row.excerpt || row.title, body }), {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS },
  });
}

/* --------------------------- 后台输入校验 --------------------------- */

function asInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeContentInput(body) {
  const title = String(body.title || "").trim();
  if (!title || title.length > 120) {
    return { error: "invalid_title", message: "标题不能为空，且不超过 120 个字。" };
  }

  const slug = String(body.slug || "").trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{0,80}$/.test(slug)) {
    return { error: "invalid_slug", message: "访问路径只能使用小写字母、数字和短横线。" };
  }

  const accessLevel = ["free", "member"].includes(body.access_level) ? body.access_level : "member";
  const status = ["draft", "published", "archived"].includes(body.status) ? body.status : "draft";
  const contentType = ["article", "chapter"].includes(body.content_type) ? body.content_type : "article";

  const text = String(body.body || "");
  if (text.length > 200000) {
    return { error: "body_too_long", message: "正文超过 20 万字符，请拆分为多篇。" };
  }

  const excerpt = String(body.excerpt || "").trim().slice(0, 300);
  const categoryId = body.category_id === null || body.category_id === "" || body.category_id === undefined
    ? null
    : asInt(body.category_id, -1);
  if (categoryId !== null && categoryId < 1) {
    return { error: "invalid_category", message: "请选择有效的课程分类。" };
  }

  const sortOrder = Math.max(0, Math.min(9999, asInt(body.sort_order, 0)));

  return {
    title,
    slug,
    categoryId,
    contentType,
    excerpt,
    body: text,
    accessLevel,
    status,
    sortOrder,
  };
}

function normalizeResourceInput(body) {
  const title = String(body.title || "").trim();
  if (!title || title.length > 120) {
    return { error: "invalid_title", message: "资料名称不能为空，且不超过 120 个字。" };
  }

  const fileKey = String(body.file_key || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(fileKey) || fileKey.includes("..")) {
    return { error: "invalid_file_key", message: "R2 文件路径不正确，只能包含字母、数字、点、下划线与斜杠。" };
  }

  const fileName = String(body.file_name || "").trim() || fileKey.split("/").pop();
  if (fileName.length > 200) {
    return { error: "invalid_file_name", message: "文件名过长。" };
  }

  const fileType = String(body.file_type || "file").trim().toLowerCase();
  if (!/^[a-z0-9]{1,12}$/.test(fileType)) {
    return { error: "invalid_file_type", message: "文件类型只能使用字母或数字，例如 pdf、xlsx。" };
  }

  const fileSize = Math.max(0, asInt(body.file_size, 0));
  const categoryId = body.category_id === null || body.category_id === "" || body.category_id === undefined
    ? null
    : asInt(body.category_id, -1);
  if (categoryId !== null && categoryId < 1) {
    return { error: "invalid_category", message: "请选择有效的资料分类。" };
  }

  const accessLevel = ["free", "member"].includes(body.access_level) ? body.access_level : "member";
  const status = ["draft", "published", "archived"].includes(body.status) ? body.status : "draft";
  const version = String(body.version || "v1.0").trim().slice(0, 30);
  const description = String(body.description || "").trim().slice(0, 500);
  const sortOrder = Math.max(0, Math.min(9999, asInt(body.sort_order, 0)));

  return {
    title,
    description,
    fileKey,
    fileName,
    fileType,
    fileSize,
    categoryId,
    accessLevel,
    status,
    version,
    sortOrder,
  };
}

function normalizeToolInput(body) {
  const name = String(body.name || "").trim();
  if (!name || name.length > 80) {
    return { error: "invalid_name", message: "工具名称不能为空，且不超过 80 个字。" };
  }

  const slug = String(body.slug || "").trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(slug)) {
    return { error: "invalid_slug", message: "工具标识只能使用小写字母、数字与短横线。" };
  }

  const entryUrl = String(body.entry_url || "").trim();
  if (!entryUrl.startsWith("/tools/") || entryUrl.length > 200 || entryUrl.includes("..")) {
    return { error: "invalid_entry_url", message: "入口路径必须以 /tools/ 开头，例如 /tools/pricing/。" };
  }

  const intro = String(body.intro || "").trim().slice(0, 300);
  const usageText = String(body.usage_text || "").trim().slice(0, 300);
  const accessLevel = ["free", "member"].includes(body.access_level) ? body.access_level : "member";
  const status = ["draft", "published", "archived"].includes(body.status) ? body.status : "draft";
  const sortOrder = Math.max(0, Math.min(9999, asInt(body.sort_order, 0)));

  return { name, slug, entryUrl, intro, usageText, accessLevel, status, sortOrder };
}

/* ------------------------------------------------------------------ */
/* 会员工具计算（全部在服务端完成，前端只拿结果）                        */
/* ------------------------------------------------------------------ */

const CURRENCY_SYMBOLS = { USD: "$", EUR: "€", GBP: "£", CNY: "¥" };

function currencyOf(body) {
  const code = String((body && body.currency) || "USD").toUpperCase();
  return CURRENCY_SYMBOLS[code] ? code : "USD";
}

function moneyValue(value, currency) {
  const symbol = CURRENCY_SYMBOLS[currency] || "$";
  const num = Number(value);
  const safe = Number.isFinite(num) ? num : 0;
  const sign = safe < 0 ? "-" : "";
  return `${sign}${symbol}${Math.abs(safe).toFixed(2)}`;
}

function pctValue(value) {
  const num = Number(value);
  return `${(Number.isFinite(num) ? num : 0).toFixed(1)}%`;
}

function pickNumbers(body, spec) {
  const values = {};
  for (const [key, min, max, label] of spec) {
    const raw = body ? body[key] : undefined;
    const num = Number(raw);
    if (raw === "" || raw === null || raw === undefined || !Number.isFinite(num) || num < min || num > max) {
      return { error: "invalid_input", message: `请填写有效的${label}（范围 ${min} 到 ${max}）。` };
    }
    values[key] = num;
  }
  return { values };
}

function pickText(body, key, label, maxLength) {
  const value = String((body && body[key]) || "").trim();
  if (!value) return { error: "invalid_input", message: `请填写${label}。` };
  if (value.length > maxLength) {
    return { error: "invalid_input", message: `${label}不能超过 ${maxLength} 个字。` };
  }
  return { value };
}

function calcPricing(body, currency) {
  const picked = pickNumbers(body, [
    ["product_cost", 0, 1000000, "产品成本"],
    ["shipping_cost", 0, 1000000, "物流成本"],
    ["ad_cost", 0, 1000000, "广告获客成本"],
    ["fee_rate", 0, 50, "交易费率"],
    ["target_margin", 0, 90, "目标毛利率"],
  ]);
  if (picked.error) return picked;
  const v = picked.values;

  const feeRate = v.fee_rate / 100;
  const margin = v.target_margin / 100;
  if (feeRate + margin >= 1) {
    return { error: "invalid_margin", message: "目标毛利率与交易费率之和必须小于 100%。" };
  }

  const unitCost = v.product_cost + v.shipping_cost + v.ad_cost;
  const breakeven = unitCost / (1 - feeRate);
  const suggested = unitCost / (1 - feeRate - margin);
  const feeAtPrice = suggested * feeRate;
  const grossProfit = suggested - unitCost - feeAtPrice;
  const adShare = suggested > 0 ? (v.ad_cost / suggested) * 100 : 0;

  const advice = [];
  if (adShare > 30) {
    advice.push(`广告获客成本占售价 ${pctValue(adShare)}，占比偏高；先用小预算验证素材与转化率，再考虑放量。`);
  } else {
    advice.push(`广告获客成本占售价 ${pctValue(adShare)}，在可接受区间；放量时仍需盯住 CPA 变化。`);
  }
  if (v.target_margin < 20) {
    advice.push("目标毛利率低于 20%，退款、汇损或运费上涨就可能吃掉利润，建议留出更高安全垫。");
  }
  if (suggested < 20) {
    advice.push("建议售价偏低，低价品的物流与客服成本占比更高，优先考虑提高客单价或做组合销售。");
  }
  advice.push(`定价前再用利润计算器复核一遍：按 ${moneyValue(suggested, currency)} 售价，退款与广告波动会直接影响净利。`);

  return {
    ok: true,
    data: {
      headline: {
        label: "建议售价",
        value: moneyValue(suggested, currency),
        note: `保本价 ${moneyValue(breakeven, currency)} · 单件毛利 ${moneyValue(grossProfit, currency)}`,
      },
      items: [
        { label: "到手成本", value: moneyValue(unitCost, currency), note: "产品 + 物流 + 广告获客" },
        { label: "保本售价", value: moneyValue(breakeven, currency), note: "不含目标毛利，低于此价即亏损" },
        { label: "交易费（按建议售价）", value: moneyValue(feeAtPrice, currency), note: `${pctValue(v.fee_rate)} 费率` },
        { label: "单件毛利", value: moneyValue(grossProfit, currency), note: `实际毛利率 ${pctValue(suggested > 0 ? (grossProfit / suggested) * 100 : 0)}` },
        { label: "广告占售价", value: pctValue(adShare), note: "高于 30% 时放量风险较大" },
      ],
      advice,
    },
  };
}

function calcAds(body, currency) {
  const picked = pickNumbers(body, [
    ["aov", 0.01, 1000000, "客单价"],
    ["cvr", 0.01, 100, "转化率"],
    ["cpc", 0.001, 10000, "CPC"],
    ["gross_margin", 0, 100, "毛利率"],
  ]);
  if (picked.error) return picked;
  const v = picked.values;

  const cvr = v.cvr / 100;
  const grossMargin = v.gross_margin / 100;
  const cpa = v.cpc / cvr;
  const grossProfitPerOrder = v.aov * grossMargin;
  const allowedCpc = grossProfitPerOrder * cvr;
  const roas = cpa > 0 ? v.aov / cpa : 0;
  const profitPerOrder = grossProfitPerOrder - cpa;
  const adShare = v.aov > 0 ? (cpa / v.aov) * 100 : 0;
  const clicksPerOrder = 1 / cvr;
  const breakevenRoas = grossMargin > 0 ? 1 / grossMargin : 0;

  const money = (n) => moneyValue(n, currency);
  const advice = [];
  if (cpa > grossProfitPerOrder) {
    advice.push(`当前 CPA 已高于每单毛利，直接放量会放大亏损；先优化转化率、素材与落地页，或提高客单价。`);
  } else {
    advice.push(`当前结构每单可剩 ${money(profitPerOrder)}，具备放量空间；把 CPA 上限设为 ${money(grossProfitPerOrder)}，超过就降预算。`);
  }
  if (allowedCpc > v.cpc) {
    advice.push(`按当前转化率，CPC 可承受上限为 ${money(allowedCpc)}，还有 ${pctValue(allowedCpc > 0 ? ((allowedCpc - v.cpc) / allowedCpc) * 100 : 0)} 的空间。`);
  } else {
    advice.push(`当前 CPC 已超过可承受上限 ${money(allowedCpc)}，优先换素材或换受众，而不是继续加预算。`);
  }
  if (breakevenRoas > 0) {
    advice.push(`按 ${pctValue(v.gross_margin)} 毛利计算，保本 ROAS 约为 ${breakevenRoas.toFixed(2)}；当前 ROAS 约 ${roas.toFixed(2)}。`);
  }

  return {
    ok: true,
    data: {
      headline: {
        label: "单笔获客成本（CPA）",
        value: money(cpa),
        note: `保本 CPA ${money(grossProfitPerOrder)} · ${profitPerOrder >= 0 ? "每单余 " : "每单亏 "}${money(Math.abs(profitPerOrder))}`,
      },
      items: [
        { label: "每单毛利", value: money(grossProfitPerOrder), note: `客单价 × ${pctValue(v.gross_margin)} 毛利率` },
        { label: "单笔订单成本", value: money(cpa), note: `CPC ${money(v.cpc)} ÷ 转化率 ${pctValue(v.cvr)}` },
        { label: "当前每单盈亏", value: money(profitPerOrder), note: profitPerOrder >= 0 ? "广告后有正利润" : "广告后为亏损" },
        { label: "ROAS", value: roas.toFixed(2), note: `保本约 ${breakevenRoas.toFixed(2)}` },
        { label: "可承受 CPC 上限", value: money(allowedCpc), note: `当前 CPC ${money(v.cpc)}` },
        { label: "每单所需点击数", value: clicksPerOrder.toFixed(1), note: "用于估算广告点击量需求" },
        { label: "广告占售价", value: pctValue(adShare), note: "高于 40% 时利润空间很薄" },
      ],
      advice,
    },
  };
}

function calcProfit(body, currency) {
  const picked = pickNumbers(body, [
    ["price", 0.01, 1000000, "售价"],
    ["product_cost", 0, 1000000, "采购成本"],
    ["shipping_cost", 0, 1000000, "物流成本"],
    ["ad_cost", 0, 1000000, "广告成本"],
    ["fee_rate", 0, 50, "平台与收款费率"],
    ["refund_rate", 0, 100, "退款率"],
    ["other_cost", 0, 1000000, "其他成本"],
  ]);
  if (picked.error) return picked;
  const v = picked.values;

  const fee = v.price * (v.fee_rate / 100);
  const refundLoss = v.price * (v.refund_rate / 100);
  const totalCost = v.product_cost + v.shipping_cost + v.ad_cost + fee + refundLoss + v.other_cost;
  const netProfit = v.price - totalCost;
  const netMargin = (netProfit / v.price) * 100;
  const money = (n) => moneyValue(n, currency);

  const advice = [];
  if (netProfit < 0) {
    advice.push(`当前每单亏损 ${money(Math.abs(netProfit))}，不要放量；优先降低广告成本、提高售价，或重新核算物流。`);
  } else if (netMargin < 10) {
    advice.push(`净利率 ${pctValue(netMargin)}，低于 10% 安全线；退款率或运费稍有波动就可能吞掉利润。`);
  } else if (netMargin >= 20) {
    advice.push(`净利率 ${pctValue(netMargin)}，结构健康；可以测试放量，但持续盯住退款率与广告成本。`);
  } else {
    advice.push(`净利率 ${pctValue(netMargin)}，处于合理区间；建议保留 5% 以上的价格缓冲应对汇损与退货。`);
  }
  if (v.refund_rate > 8) {
    advice.push(`退款率 ${pctValue(v.refund_rate)} 偏高，检查产品描述、尺码表与物流时效承诺。`);
  }
  advice.push("把广告成本按「每单」录入，不要用账户总花费除以总订单数，否则会低估旺季获客成本。");

  return {
    ok: true,
    data: {
      headline: {
        label: "单笔净利",
        value: money(netProfit),
        note: `净利率 ${pctValue(netMargin)} · 总成本 ${money(totalCost)}`,
      },
      items: [
        { label: "采购成本", value: money(v.product_cost), note: "含包装与质检" },
        { label: "物流与尾程", value: money(v.shipping_cost), note: "头程 + 尾程 + 仓储" },
        { label: "广告成本", value: money(v.ad_cost), note: "按每单分摊" },
        { label: "平台与收款费", value: money(fee), note: `${pctValue(v.fee_rate)} 费率` },
        { label: "退款损耗", value: money(refundLoss), note: `按售价 × ${pctValue(v.refund_rate)} 估算` },
        { label: "其他成本", value: money(v.other_cost), note: "客服、汇损、耗材等" },
        { label: "总成本", value: money(totalCost), note: "以上各项之和" },
        { label: "净利率", value: pctValue(netMargin), note: "净利 ÷ 售价" },
      ],
      advice,
    },
  };
}

const EU_US_CALENDAR = {
  1: [
    { name: "元旦 New Year's Day", date: "1 月 1 日", prep: "12 月前完成库存与素材", theme: "新年计划、健身、家居整理" },
    { name: "马丁·路德·金纪念日", date: "1 月第三个周一", prep: "提前 4 周备货", theme: "冬季清仓、办公与家居" },
    { name: "冬季清仓季", date: "1 月下旬至 2 月", prep: "1 月初开始排期", theme: "保暖、收纳、室内运动" },
  ],
  2: [
    { name: "情人节 Valentine's Day", date: "2 月 14 日", prep: "提前 6-8 周，1 月上旬入仓", theme: "礼品、情侣、香氛与饰品" },
    { name: "总统日 Presidents' Day", date: "2 月第三个周一", prep: "提前 4 周备货", theme: "家具、家电、床品促销" },
    { name: "春季上新", date: "2 月下旬", prep: "提前 8 周开发与备货", theme: "户外、园艺、春季穿搭" },
  ],
  3: [
    { name: "圣帕特里克节", date: "3 月 17 日", prep: "提前 5 周备货", theme: "绿色主题、派对装饰" },
    { name: "复活节 Easter", date: "3 月底至 4 月初（每年浮动）", prep: "提前 8 周，确认当年日期", theme: "礼品、糖果、亲子与家居" },
    { name: "春季大促", date: "3 月中下旬", prep: "提前 6 周排期", theme: "户外、园艺、春季焕新" },
  ],
  4: [
    { name: "复活节（部分年份）", date: "4 月上旬（每年浮动）", prep: "提前 8 周备货", theme: "礼品、亲子、装饰" },
    { name: "地球日 Earth Day", date: "4 月 22 日", prep: "提前 4 周准备内容", theme: "环保、可持续、户外" },
    { name: "春季户外季", date: "4 月全月", prep: "提前 8-10 周备货", theme: "露营、骑行、园艺" },
  ],
  5: [
    { name: "母亲节 Mother's Day", date: "5 月第二个周日", prep: "提前 8 周，4 月上旬入仓", theme: "珠宝、家居、个护与礼品" },
    { name: "阵亡将士纪念日", date: "5 月最后一个周一", prep: "提前 4-6 周", theme: "户外、烧烤、家居" },
    { name: "毕业季", date: "5-6 月", prep: "提前 8 周备货", theme: "礼品、摄影、纪念品" },
  ],
  6: [
    { name: "父亲节 Father's Day", date: "6 月第三个周日", prep: "提前 8 周备货", theme: "工具、户外、数码与礼品" },
    { name: "暑期开始", date: "6 月下旬", prep: "提前 6 周排期", theme: "旅行、泳装、户外" },
    { name: "年中大促", date: "6 月底至 7 月", prep: "提前 6 周准备", theme: "全品类清仓与组合销售" },
  ],
  7: [
    { name: "美国独立日", date: "7 月 4 日", prep: "提前 6-8 周备货", theme: "派对、国旗、烧烤" },
    { name: "Prime Day", date: "7 月中旬（每年浮动）", prep: "提前 8 周备货与素材", theme: "会员专属折扣、爆款" },
    { name: "夏日户外", date: "7 月全月", prep: "提前 6 周补货", theme: "露营、水上运动、防晒" },
  ],
  8: [
    { name: "返校季 Back to School", date: "8 月中下旬", prep: "提前 8-10 周备货", theme: "文具、宿舍、学生服饰" },
    { name: "劳动节备货", date: "9 月第一个周一（8 月入仓）", prep: "8 月完成入仓", theme: "家具、户外、烧烤" },
    { name: "夏末清仓", date: "8 月下旬", prep: "提前 4 周排期", theme: "泳装、夏季品清仓" },
  ],
  9: [
    { name: "劳动节 Labor Day", date: "9 月第一个周一", prep: "提前 6 周备货", theme: "家居、户外、开学季" },
    { name: "慕尼黑啤酒节", date: "9 月下旬至 10 月初", prep: "提前 6 周备货", theme: "派对、餐具、节庆装饰" },
    { name: "万圣节预热", date: "9 月下旬", prep: "提前 8 周备货", theme: "装饰、服饰、糖果" },
  ],
  10: [
    { name: "万圣节 Halloween", date: "10 月 31 日", prep: "提前 8-10 周，9 月入仓", theme: "服饰、装饰、糖果与派对" },
    { name: "Prime Big Deal Days", date: "10 月（每年浮动）", prep: "提前 6 周准备", theme: "会员促销、爆款折扣" },
    { name: "黑五预热", date: "10 月下旬", prep: "提前 8 周备货", theme: "全品类、礼品清单" },
  ],
  11: [
    { name: "感恩节 Thanksgiving", date: "11 月第四个周四", prep: "提前 8 周备货", theme: "家居、厨房、聚会" },
    { name: "黑色星期五 Black Friday", date: "11 月第四个周五", prep: "提前 8-10 周，10 月入仓", theme: "全品类、年度最大折扣" },
    { name: "网络星期一 Cyber Monday", date: "黑五后的周一", prep: "提前 8 周准备", theme: "数码、礼品、办公" },
  ],
  12: [
    { name: "圣诞节 Christmas", date: "12 月 25 日", prep: "提前 10-12 周，10 月入仓", theme: "礼品、装饰、节日套装" },
    { name: "光明节 Hanukkah", date: "11 月底至 12 月（每年浮动）", prep: "提前 8 周备货", theme: "礼品、家居、节庆用品" },
    { name: "节礼日 Boxing Day", date: "12 月 26 日", prep: "提前 6 周准备", theme: "清仓、礼品、冬季品" },
    { name: "跨年 New Year's Eve", date: "12 月 31 日", prep: "提前 4 周排期", theme: "派对、日历、新年礼品" },
  ],
};

const MONTH_TIPS = {
  1: ["1 月是健身、收纳与办公品类的起量期，适合用小预算测试新素材。"],
  2: ["情人节礼品要突出「送礼场景」，2 月上旬前完成物流时效承诺。"],
  3: ["复活节日期每年浮动，备货前先确认当年日期，避免错过入仓窗口。"],
  4: ["春季户外品类搜索量在 4 月快速上升，提前布局露营与园艺内容。"],
  5: ["母亲节是全年礼品类高峰之一，素材要提前 3-4 周测试。"],
  6: ["毕业季与父亲节相邻，可以用组合礼盒提高客单价。"],
  7: ["Prime Day 期间 CPC 普遍上涨，提前锁定预算并准备非会员日素材。"],
  8: ["返校季订单集中，物流时效比价格更影响评价。"],
  9: ["9 月就要开始准备万圣节与黑五素材，不要等到 10 月。"],
  10: ["万圣节与黑五备货重叠，优先保证黑五核心 SKU 的库存。"],
  11: ["黑五网一是全年广告成本最高的窗口，提前 2 周完成素材与库存检查。"],
  12: ["圣诞节后立即清点库存，1 月前决定清仓或留到下一年度。"],
};

function calcCalendar(body) {
  const month = Math.round(Number(body && body.month));
  if (!Number.isFinite(month) || month < 1 || month > 12) {
    return { error: "invalid_input", message: "请选择 1-12 月之间的有效月份。" };
  }

  const list = EU_US_CALENDAR[month] || [];
  const items = list.map((f) => ({
    label: f.name,
    value: f.date,
    note: `备货：${f.prep}；素材：${f.theme}`,
  }));

  const advice = [
    ...(MONTH_TIPS[month] || []),
    "欧美节日营销至少提前 6-8 周备货；装饰、礼品、节日服饰建议提前 10-12 周。",
    "素材提前 3-4 周测好，节日前 2 周才开始投放通常已经错过低成本流量窗口。",
    "节日结束后立刻清点库存，把剩余库存转入清仓或下一年度备货计划。",
  ];

  return {
    ok: true,
    data: {
      headline: {
        label: `${month} 月重点`,
        value: list.length ? list[0].name : "暂无节点",
        note: list.length ? `共 ${list.length} 个节点 · 最早备货：${list[0].prep}` : "该月份暂无节日数据",
      },
      items,
      advice,
    },
  };
}

const MARKET_NAMES = { US: "美国", EU: "欧洲", UK: "英国" };

function calcAiSourcing(body) {
  const category = pickText(body, "category", "品类方向", 40);
  if (category.error) return category;
  const audience = pickText(body, "audience", "目标人群", 80);
  if (audience.error) return audience;
  const priceBand = pickText(body, "price_band", "目标价格带", 20);
  if (priceBand.error) return priceBand;

  const market = MARKET_NAMES[String((body && body.market) || "US").toUpperCase()] ? String((body && body.market) || "US").toUpperCase() : "US";
  const marketName = MARKET_NAMES[market];

  const items = [
    { label: "步骤 1 · 关键词扩词", value: "30 个需求词", note: "从竞品评论、搜索下拉与 Reddit 帖子里提炼真实搜索词。" },
    { label: "步骤 2 · 需求证据", value: "3 类证据", note: "搜索趋势、竞品评论数量与差评关键词、社媒讨论量。" },
    { label: "步骤 3 · 竞品拆解", value: "5 个对标", note: "记录售价、评分、差评前 3 名与配送时效。" },
    { label: "步骤 4 · 利润试算", value: "目标毛利 35%+", note: "用定价与利润计算器验证成本结构。" },
    { label: "步骤 5 · 风险排查", value: "合规与侵权", note: "检查商标、专利、认证（如 CPSIA/CE）与物流限制。" },
    { label: "步骤 6 · 小单验证", value: "首批 50-100 件", note: "先测素材与转化率，数据达标再补货。" },
  ];

  const prompt = `你是一名跨境电商选品分析师。请围绕以下条件，输出一份可执行的选品报告：
品类：${category.value}
目标人群：${audience.value}
目标市场：${marketName}
目标价格带：${priceBand.value}

请按以下结构输出：
1. 需求词清单：给出 30 个真实搜索词，标注搜索意图（痛点 / 场景 / 礼品）。
2. 需求证据：列出 3 类可验证证据（搜索趋势、竞品评论数量与差评关键词、社媒讨论量）。
3. 竞品拆解：挑 5 个对标产品，列出售价、评分、差评前 3 名与配送时效。
4. 利润试算：按目标价格带估算采购、物流、平台费与广告成本，给出建议毛利率。
5. 风险清单：商标 / 专利 / 认证 / 物流限制，逐条标注风险等级。
6. 验证计划：给出首批订货量、测试预算与 14 天判断标准。

要求：所有结论必须给出依据，不确定的地方明确标注「需人工核实」，不要编造数据。`;

  return {
    ok: true,
    data: {
      headline: {
        label: "选品方向",
        value: category.value,
        note: `${marketName} · ${audience.value} · 价格带 ${priceBand.value}`,
      },
      items,
      advice: [
        "先用 3 天完成扩词与竞品拆解，不要直接下大货。",
        "所有候选品必须过一遍合规与侵权检查：商标、专利、认证与物流限制。",
        "首批 50-100 件小单验证素材与转化率，数据达标再补货。",
      ],
      prompt,
    },
  };
}

function computeTool(slug, body) {
  const currency = currencyOf(body);
  switch (slug) {
    case "pricing":
      return calcPricing(body, currency);
    case "ads":
      return calcAds(body, currency);
    case "profit":
      return calcProfit(body, currency);
    case "calendar":
      return calcCalendar(body);
    case "ai-sourcing":
      return calcAiSourcing(body);
    default:
      return { error: "tool_not_found", message: "工具不存在或尚未发布。" };
  }
}

/* ------------------------------------------------------------------ */
/* 路由                                                                */
/* ------------------------------------------------------------------ */

async function handleApi(request, env, ctx, url) {
  const method = request.method;
  const path = url.pathname;
  const pepper = env.CODE_PEPPER || "";

  // ---------- 公开 ----------
  if (path === "/api/health" && method === "GET") {
    return json({ ok: true, service: "chunge-member-center" });
  }

  // 生产环境必须配置 CODE_PEPPER；缺失时拒绝服务，避免静默退化为弱哈希
  if (!pepper) {
    return fail(500, "missing_config", "服务端尚未完成初始化配置，请联系管理员。");
  }

  if (path === "/api/member/login" && method === "POST") {
    return handleMemberLogin(request, env, ctx);
  }

  if (path === "/api/member/logout" && method === "POST") {
    if (!originAllowed(request)) return fail(403, "forbidden_origin", "请求来源不被允许。");
    const session = await getMemberSession(request, env);
    const revoked = await revokeMemberSession(request, env);
    if (revoked && session.member) {
      audit(ctx, env.DB, { actorType: "member", actorId: session.member.id, action: "member.logout" });
    }
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(MEMBER_COOKIE, "", 0) });
  }

  if (path === "/api/member/session" && method === "GET") {
    const session = await getMemberSession(request, env);
    if (session.state === "anonymous" || session.state === "expired") {
      return fail(401, "not_logged_in", "尚未登录会员中心。");
    }
    if (session.state === "blocked") {
      return fail(403, "member_disabled", MSG.memberDisabled, { "Set-Cookie": sessionCookie(MEMBER_COOKIE, "", 0) });
    }
    return json({ ok: true, member: session.member });
  }

  // ---------- 会员工具：每次计算都重新校验会员与工具状态 ----------
  const toolCalcMatch = path.match(/^\/api\/tools\/([a-z0-9][a-z0-9-]*)\/calc$/);
  if (toolCalcMatch) {
    if (method !== "POST") return fail(405, "method_not_allowed", "不支持该请求方法。");
    if (!originAllowed(request)) return fail(403, "forbidden_origin", "请求来源不被允许。");

    const slug = toolCalcMatch[1];
    const toolRow = await env.DB.prepare(
      "SELECT slug, access_level FROM tools WHERE slug = ? AND status = 'published'"
    )
      .bind(slug)
      .first();
    if (!toolRow) return fail(404, "tool_not_found", "工具不存在或尚未发布。");

    if (toolRow.access_level === "member") {
      const session = await getMemberSession(request, env);
      if (session.state === "blocked") {
        return fail(403, "member_disabled", MSG.memberDisabled, { "Set-Cookie": sessionCookie(MEMBER_COOKIE, "", 0) });
      }
      if (session.state !== "active") {
        return fail(401, "not_logged_in", "请先输入会员访问码。");
      }
    }

    const body = await readJson(request);
    if (!body) return fail(400, "invalid_body", "请求格式不正确。");

    const result = computeTool(slug, body);
    if (result.error) return fail(400, result.error, result.message);

    return json({ ok: true, tool: slug, ...result.data });
  }

  // ---------- 管理员初始化（只在没有管理员时可用） ----------
  if (path === "/api/admin/setup" && method === "POST") {
    if (!originAllowed(request)) return fail(403, "forbidden_origin", "请求来源不被允许。");
    const exists = await env.DB.prepare("SELECT COUNT(*) AS n FROM admins").first();
    if (exists && exists.n > 0) return fail(403, "setup_closed", "管理员已初始化，初始化入口已关闭。");

    const body = await readJson(request);
    const username = String((body && body.username) || "").trim();
    const password = String((body && body.password) || "");
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return fail(400, "invalid_username", "管理员账号需为 3-20 位字母、数字或下划线。");
    if (password.length < 10) return fail(400, "weak_password", "管理员密码至少 10 位。");
    if (env.ADMIN_SETUP_TOKEN && String((body && body.setup_token) || "") !== env.ADMIN_SETUP_TOKEN) {
      return fail(403, "invalid_setup_token", "初始化令牌不正确。");
    }

    const ts = nowIso();
    await env.DB.prepare(
      "INSERT INTO admins (username, password_hash, status, created_at) VALUES (?, ?, 'active', ?)"
    )
      .bind(username, await hashPassword(password), ts)
      .run();
    audit(ctx, env.DB, { actorType: "admin", actorId: null, action: "admin.setup", detail: username });
    return json({ ok: true, username });
  }

  if (path === "/api/admin/login" && method === "POST") {
    if (!originAllowed(request)) return fail(403, "forbidden_origin", "请求来源不被允许。");
    const ip = await ipHash(request, pepper);
    const body = await readJson(request);
    const username = String((body && body.username) || "").trim();
    const password = String((body && body.password) || "");
    const lockKey = `admin:${ip}`;

    if ((await checkLock(env.DB, lockKey)) > 0) {
      return fail(429, "rate_limited", MSG.rateLimited, { "Retry-After": String(Math.ceil((await checkLock(env.DB, lockKey)) / 1000)) });
    }
    if (!username || !password) return fail(400, "missing_credentials", "请输入管理员账号和密码。");

    const row = await env.DB.prepare("SELECT id, username, password_hash, status FROM admins WHERE username = ?")
      .bind(username)
      .first();
    const ok = row && row.status === "active" && (await verifyPassword(password, row.password_hash));
    if (!ok) {
      await recordFailure(env.DB, lockKey);
      return fail(401, "invalid_credentials", "账号或密码不正确。");
    }

    const token = await createAdminSession(env.DB, row.id, request);
    await env.DB.prepare("UPDATE admins SET last_login_at = ? WHERE id = ?").bind(nowIso(), row.id).run();
    await clearFailures(env.DB, [lockKey]);
    audit(ctx, env.DB, { actorType: "admin", actorId: row.id, action: "admin.login", ipHash: ip });
    return json({ ok: true, admin: { username: row.username } }, 200, {
      "Set-Cookie": sessionCookie(ADMIN_COOKIE, token, ADMIN_SESSION_MS / 1000),
    });
  }

  if (path === "/api/admin/logout" && method === "POST") {
    if (!originAllowed(request)) return fail(403, "forbidden_origin", "请求来源不被允许。");
    const token = getCookie(request, ADMIN_COOKIE);
    if (token) {
      await env.DB.prepare("UPDATE admin_sessions SET revoked_at = ? WHERE token_hash = ?")
        .bind(nowIso(), await sha256Hex(token))
        .run();
    }
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(ADMIN_COOKIE, "", 0) });
  }

  // ---------- 管理接口（全部需要管理员会话） ----------
  if (path === "/api/admin/me" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    return json({ ok: true, admin: auth.admin });
  }

  if (path === "/api/admin/members" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const data = await listMembers(env, url);
    return json({ ok: true, ...data });
  }

  if (path === "/api/admin/members" && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const body = await readJson(request);
    const name = String((body && body.name) || "").trim();
    if (!name || name.length > 60) return fail(400, "invalid_name", "请填写会员姓名或昵称（60 字以内）。");

    const created = await createMemberWithCode(env.DB, {
      name,
      contact: String((body && body.contact) || "").trim().slice(0, 120),
      wechat_note: String((body && body.wechat_note) || "").trim().slice(0, 120),
      source: String((body && body.source) || "").trim().slice(0, 60),
      notes: String((body && body.notes) || "").trim().slice(0, 500),
    }, pepper);

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "member.create",
      detail: `${created.memberCode} ${name}`,
      ipHash: await ipHash(request, pepper),
    });

    return json({
      ok: true,
      member: {
        id: created.memberId,
        member_code: created.memberCode,
        name,
        status: "active",
        member_type: "lifetime",
      },
      // 明文访问码只在本次响应里出现一次，之后数据库只有哈希
      access_code: created.code,
    });
  }

  const memberActionMatch = path.match(/^\/api\/admin\/members\/(\d+)\/([a-z-]+)$/);
  if (memberActionMatch && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const memberId = parseInt(memberActionMatch[1], 10);
    const action = memberActionMatch[2];
    const ip = await ipHash(request, pepper);

    const member = await env.DB.prepare("SELECT * FROM members WHERE id = ? AND deleted_at IS NULL").bind(memberId).first();
    if (!member) return fail(404, "member_not_found", "会员不存在或已被删除。");

    if (action === "rotate-code") {
      const code = generateCode();
      const ts = nowIso();
      await env.DB.prepare("UPDATE access_codes SET status = 'revoked', revoked_at = ? WHERE member_id = ? AND status = 'active'")
        .bind(ts, memberId)
        .run();
      await env.DB.prepare(
        "INSERT INTO access_codes (member_id, code_hash, code_hint, status, created_at) VALUES (?, ?, ?, 'active', ?)"
      )
        .bind(memberId, await hashCode(code, pepper), codeHint(code), ts)
        .run();
      audit(ctx, env.DB, { actorType: "admin", actorId: auth.admin.id, action: "member.rotate_code", detail: member.member_code, ipHash: ip });
      return json({ ok: true, access_code: code, member_code: member.member_code });
    }

    if (action === "status") {
      const body = await readJson(request);
      const status = String((body && body.status) || "");
      if (!["active", "paused", "disabled"].includes(status)) return fail(400, "invalid_status", "会员状态不合法。");
      const ts = nowIso();
      await env.DB.prepare("UPDATE members SET status = ?, updated_at = ? WHERE id = ?").bind(status, ts, memberId).run();
      if (status !== "active") {
        await env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE member_id = ? AND revoked_at IS NULL").bind(ts, memberId).run();
      }
      audit(ctx, env.DB, { actorType: "admin", actorId: auth.admin.id, action: `member.status.${status}`, detail: member.member_code, ipHash: ip });
      return json({ ok: true, status });
    }

    if (action === "revoke-sessions") {
      const ts = nowIso();
      const res = await env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE member_id = ? AND revoked_at IS NULL").bind(ts, memberId).run();
      audit(ctx, env.DB, { actorType: "admin", actorId: auth.admin.id, action: "member.revoke_sessions", detail: member.member_code, ipHash: ip });
      return json({ ok: true, revoked: res.meta ? res.meta.changes : 0 });
    }

    return fail(404, "unknown_action", "未知操作。");
  }

  const memberDeleteMatch = path.match(/^\/api\/admin\/members\/(\d+)$/);
  if (memberDeleteMatch && method === "DELETE") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const memberId = parseInt(memberDeleteMatch[1], 10);
    const member = await env.DB.prepare("SELECT * FROM members WHERE id = ? AND deleted_at IS NULL").bind(memberId).first();
    if (!member) return fail(404, "member_not_found", "会员不存在或已被删除。");
    const ts = nowIso();
    await env.DB.prepare("UPDATE members SET deleted_at = ?, status = 'disabled', updated_at = ? WHERE id = ?").bind(ts, ts, memberId).run();
    await env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE member_id = ? AND revoked_at IS NULL").bind(ts, memberId).run();
    await env.DB.prepare("UPDATE access_codes SET status = 'revoked', revoked_at = ? WHERE member_id = ? AND status = 'active'").bind(ts, memberId).run();
    audit(ctx, env.DB, { actorType: "admin", actorId: auth.admin.id, action: "member.delete", detail: member.member_code, ipHash: await ipHash(request, pepper) });
    return json({ ok: true, deleted: member.member_code });
  }

  if (path === "/api/admin/members/export" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const status = (url.searchParams.get("status") || "").trim();
    const q = (url.searchParams.get("q") || "").trim();
    const where = ["deleted_at IS NULL"];
    const params = [];
    if (q) {
      where.push("(name LIKE ? OR member_code LIKE ? OR contact LIKE ? OR notes LIKE ?)");
      const like = `%${q}%`;
      params.push(like, like, like, like);
    }
    if (status && ["active", "paused", "disabled"].includes(status)) {
      where.push("status = ?");
      params.push(status);
    }
    const rows = await env.DB
      .prepare(`SELECT * FROM members WHERE ${where.join(" AND ")} ORDER BY id DESC LIMIT 5000`)
      .bind(...params)
      .all();

    const header = ["会员编号", "会员姓名", "联系方式", "微信备注", "来源", "会员状态", "备注", "添加时间", "最近登录时间"];
    const statusMap = { active: "正常", paused: "已暂停", disabled: "已停用" };
    const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [header.map(esc).join(",")];
    for (const r of rows.results || []) {
      lines.push(
        [
          r.member_code, r.name, r.contact, r.wechat_note, r.source,
          statusMap[r.status] || r.status, r.notes, r.created_at, r.last_login_at,
        ].map(esc).join(",")
      );
    }
    const csv = "\uFEFF" + lines.join("\r\n");
    const stamp = new Date().toISOString().slice(0, 10);
    return new Response(csv, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="chunge-members-${stamp}.csv"`,
        "Cache-Control": "no-store",
        ...BASE_HEADERS,
      },
    });
  }

  if (path === "/api/admin/audit" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "50", 10), 1), 200);
    const rows = await env.DB.prepare("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?").bind(limit).all();
    return json({ ok: true, items: rows.results || [] });
  }

  /* ---------------- 管理员概览 ---------------- */

  if (path === "/api/admin/overview" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;

    const memberRows = (await env.DB.prepare(
      "SELECT status, COUNT(*) AS n FROM members WHERE deleted_at IS NULL GROUP BY status"
    ).all()).results || [];
    const memberTotal = memberRows.reduce((sum, r) => sum + Number(r.n), 0);
    const memberStats = { active: 0, paused: 0, disabled: 0 };
    for (const r of memberRows) if (r.status in memberStats) memberStats[r.status] = Number(r.n);

    const contentRows = (await env.DB.prepare(
      "SELECT status, COUNT(*) AS n FROM contents GROUP BY status"
    ).all()).results || [];
    const contentStats = { draft: 0, published: 0, archived: 0 };
    for (const r of contentRows) if (r.status in contentStats) contentStats[r.status] = Number(r.n);

    const resourceCount = (await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM resources WHERE status = 'published'"
    ).first()) || { n: 0 };
    const toolCount = (await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM tools WHERE status = 'published'"
    ).first()) || { n: 0 };
    const recent = (await env.DB.prepare(
      "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 8"
    ).all()).results || [];

    return json({
      ok: true,
      members: { total: memberTotal, ...memberStats },
      contents: contentStats,
      resources: Number(resourceCount.n || 0),
      tools: Number(toolCount.n || 0),
      recent,
    });
  }

  /* ---------------- 网站基础设置 ---------------- */

  if (path === "/api/admin/settings" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    return json({ ok: true, item: await loadSite(env), defaults: SITE_DEFAULT });
  }

  if (path === "/api/admin/settings" && method === "POST") {
    if (!originAllowed(request)) return fail(403, "forbidden_origin", "请求来源不被允许。");
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;

    const body = await readJson(request);
    if (!body) return fail(400, "invalid_body", "请求格式不正确。");
    const values = normalizeSiteInput(body);
    if (values.error) return fail(400, values.error, values.message);

    const now = nowIso();
    for (const [key, value] of Object.entries(values)) {
      await env.DB.prepare(
        `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
      )
        .bind(key, value, now)
        .run();
    }
    resetSiteCache();

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "settings.update",
      detail: values.brand_name,
    });

    return json({ ok: true, item: values });
  }

  /* ---------------- 分类 ---------------- */

  if (path === "/api/admin/categories" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const rows = await env.DB.prepare(
      "SELECT id, name, slug, type, description, sort_order FROM content_categories ORDER BY type, sort_order, id"
    ).all();
    return json({ ok: true, items: rows.results || [] });
  }

  /* ---------------- 课程内容管理 ---------------- */

  if (path === "/api/admin/contents" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;

    const q = (url.searchParams.get("q") || "").trim();
    const status = (url.searchParams.get("status") || "").trim();
    const where = [];
    const params = [];
    if (q) {
      where.push("(c.title LIKE ? OR c.slug LIKE ?)");
      params.push(`%${q}%`, `%${q}%`);
    }
    if (["draft", "published", "archived"].includes(status)) {
      where.push("c.status = ?");
      params.push(status);
    }
    const sql = `SELECT c.id, c.title, c.slug, c.category_id, c.excerpt, c.access_level, c.content_type,
                        c.status, c.sort_order, c.created_at, c.updated_at, c.published_at,
                        cat.name AS category_name, LENGTH(c.body) AS body_length,
                        cf.file_name AS attachment_name
                   FROM contents c LEFT JOIN content_categories cat ON cat.id = c.category_id
                   LEFT JOIN content_files cf ON cf.content_id = c.id
                   ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
                  ORDER BY c.updated_at DESC, c.id DESC LIMIT 300`;
    const rows = await env.DB.prepare(sql).bind(...params).all();
    return json({ ok: true, items: rows.results || [] });
  }

  if (path === "/api/admin/contents" && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const body = await readJson(request);
    if (!body) return fail(400, "invalid_body", "请求格式不正确。");

    const input = normalizeContentInput(body);
    if (input.error) return fail(400, input.error, input.message);

    const exists = await env.DB.prepare("SELECT id FROM contents WHERE slug = ?").bind(input.slug).first();
    if (exists) return fail(409, "slug_taken", "该访问路径（slug）已被占用，请换一个。");

    const now = nowIso();
    const publishedAt = input.status === "published" ? now : null;
    const result = await env.DB.prepare(
      `INSERT INTO contents (title, slug, category_id, content_type, excerpt, body, access_level, status, sort_order, created_at, updated_at, published_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        input.title,
        input.slug,
        input.categoryId,
        input.contentType,
        input.excerpt,
        input.body,
        input.accessLevel,
        input.status,
        input.sortOrder,
        now,
        now,
        publishedAt
      )
      .run();

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "content.create",
      detail: `${input.slug} ${input.title}`,
    });

    return json({
      ok: true,
      item: { id: Number(result.meta.last_row_id), slug: input.slug, title: input.title, status: input.status },
    });
  }

  const contentIdMatch = path.match(/^\/api\/admin\/contents\/(\d+)$/);
  if (contentIdMatch) {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const contentId = parseInt(contentIdMatch[1], 10);
    const row = await env.DB.prepare("SELECT * FROM contents WHERE id = ?").bind(contentId).first();
    if (!row) return fail(404, "not_found", "内容不存在。");

    if (method === "GET") {
      const attachment = await env.DB.prepare("SELECT * FROM content_files WHERE content_id = ?")
        .bind(contentId)
        .first();
      return json({ ok: true, item: { ...row, attachment: attachment || null } });
    }

    if (method === "POST") {
      const body = await readJson(request);
      if (!body) return fail(400, "invalid_body", "请求格式不正确。");
      const input = normalizeContentInput({ ...row, ...body });
      if (input.error) return fail(400, input.error, input.message);

      const slugTaken = await env.DB.prepare("SELECT id FROM contents WHERE slug = ? AND id <> ?")
        .bind(input.slug, contentId)
        .first();
      if (slugTaken) return fail(409, "slug_taken", "该访问路径（slug）已被占用，请换一个。");

      const now = nowIso();
      const publishedAt =
        input.status === "published" ? row.published_at || now : row.published_at || null;
      await env.DB.prepare(
        `UPDATE contents SET title = ?, slug = ?, category_id = ?, content_type = ?, excerpt = ?, body = ?,
                            access_level = ?, status = ?, sort_order = ?, updated_at = ?, published_at = ?
          WHERE id = ?`
      )
        .bind(
          input.title,
          input.slug,
          input.categoryId,
          input.contentType,
          input.excerpt,
          input.body,
          input.accessLevel,
          input.status,
          input.sortOrder,
          now,
          publishedAt,
          contentId
        )
        .run();

      audit(ctx, env.DB, {
        actorType: "admin",
        actorId: auth.admin.id,
        action: "content.update",
        detail: `${input.slug} ${input.status}`,
      });

      return json({ ok: true, item: { id: contentId, slug: input.slug, status: input.status } });
    }

    return fail(405, "method_not_allowed", "不支持该请求方法。");
  }

  const contentStatusMatch = path.match(/^\/api\/admin\/contents\/(\d+)\/status$/);
  if (contentStatusMatch && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const contentId = parseInt(contentStatusMatch[1], 10);
    const body = await readJson(request);
    const status = body && body.status;
    if (!["draft", "published", "archived"].includes(status)) {
      return fail(400, "invalid_status", "内容状态不正确。");
    }
    const row = await env.DB.prepare("SELECT id, title, slug, published_at FROM contents WHERE id = ?")
      .bind(contentId)
      .first();
    if (!row) return fail(404, "not_found", "内容不存在。");

    const now = nowIso();
    const publishedAt = status === "published" ? row.published_at || now : row.published_at || null;
    await env.DB.prepare("UPDATE contents SET status = ?, updated_at = ?, published_at = ? WHERE id = ?")
      .bind(status, now, publishedAt, contentId)
      .run();

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "content.status",
      detail: `${row.slug} ${status}`,
    });

    return json({ ok: true, item: { id: contentId, status } });
  }

  /* ---------------- 课程附件（R2 私有存储） ---------------- */

  const contentAttachmentMatch = path.match(/^\/api\/admin\/contents\/(\d+)\/attachment$/);
  if (contentAttachmentMatch && method === "POST") {
    if (!originAllowed(request)) return fail(403, "forbidden_origin", "请求来源不被允许。");
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    if (!env.R2) {
      return fail(503, "r2_not_configured", "尚未配置 R2 私有存储，请先按部署说明绑定存储桶。");
    }

    const contentId = parseInt(contentAttachmentMatch[1], 10);
    const row = await env.DB.prepare("SELECT id, slug, title FROM contents WHERE id = ?").bind(contentId).first();
    if (!row) return fail(404, "not_found", "课程不存在。");

    const contentType = request.headers.get("Content-Type") || "";
    if (!contentType.includes("multipart/form-data")) {
      return fail(400, "invalid_body", "请使用文件上传表单提交。");
    }

    let form;
    try {
      form = await request.formData();
    } catch {
      return fail(400, "invalid_body", "上传数据解析失败，请重试。");
    }

    const file = form.get("file");
    if (!file || typeof file === "string" || !file.size) {
      return fail(400, "missing_file", "请选择要上传的附件。");
    }
    if (file.size > 200 * 1024 * 1024) {
      return fail(413, "file_too_large", "单个附件不能超过 200 MB。");
    }

    const originalName = String(file.name || "file");
    const safeName = originalName
      .replace(/[^\w.\- \u4e00-\u9fa5]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(-90) || "file";
    const rawExt = safeName.includes(".") ? safeName.split(".").pop().toLowerCase() : "";
    const ext = /^[a-z0-9]{1,12}$/.test(rawExt) ? rawExt : "bin";
    const fileKey = `courses/${contentId}/${Date.now().toString(36)}-${randomHex(4)}.${ext}`;

    await env.R2.put(fileKey, file.stream(), {
      httpMetadata: { contentType: file.type || "application/octet-stream" },
    });

    const previous = await env.DB.prepare("SELECT file_key FROM content_files WHERE content_id = ?")
      .bind(contentId)
      .first();
    const now = nowIso();
    await env.DB.prepare(
      `INSERT INTO content_files (content_id, file_key, file_name, file_type, file_size, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(content_id) DO UPDATE SET file_key = excluded.file_key, file_name = excluded.file_name,
         file_type = excluded.file_type, file_size = excluded.file_size, updated_at = excluded.updated_at`
    )
      .bind(contentId, fileKey, safeName, ext, file.size, now, now)
      .run();

    if (previous && previous.file_key && previous.file_key !== fileKey) {
      await env.R2.delete(previous.file_key).catch(() => {});
    }

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "content.attachment",
      detail: `${row.slug} ${fileKey}`,
    });

    return json({ ok: true, item: { file_key: fileKey, file_name: safeName, file_type: ext, file_size: file.size } });
  }

  const contentAttachmentRemoveMatch = path.match(/^\/api\/admin\/contents\/(\d+)\/attachment\/remove$/);
  if (contentAttachmentRemoveMatch && method === "POST") {
    if (!originAllowed(request)) return fail(403, "forbidden_origin", "请求来源不被允许。");
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;

    const contentId = parseInt(contentAttachmentRemoveMatch[1], 10);
    const file = await env.DB.prepare("SELECT file_key FROM content_files WHERE content_id = ?")
      .bind(contentId)
      .first();
    if (!file) return fail(404, "not_found", "该课程没有附件。");

    await env.DB.prepare("DELETE FROM content_files WHERE content_id = ?").bind(contentId).run();
    if (env.R2) await env.R2.delete(file.file_key).catch(() => {});

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "content.attachment.remove",
      detail: String(contentId),
    });

    return json({ ok: true });
  }

  /* ---------------- 课程正文配图上传（公开图片） ---------------- */

  if (path === "/api/admin/uploads/image" && method === "POST") {
    if (!originAllowed(request)) return fail(403, "forbidden_origin", "请求来源不被允许。");
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    if (!env.R2) {
      return fail(503, "r2_not_configured", "尚未配置 R2 私有存储，请先按部署说明绑定存储桶。");
    }

    const contentType = request.headers.get("Content-Type") || "";
    if (!contentType.includes("multipart/form-data")) {
      return fail(400, "invalid_body", "请使用文件上传表单提交。");
    }

    let form;
    try {
      form = await request.formData();
    } catch {
      return fail(400, "invalid_body", "上传数据解析失败，请重试。");
    }

    const file = form.get("file");
    if (!file || typeof file === "string" || !file.size) {
      return fail(400, "missing_file", "请选择要上传的图片。");
    }
    if (file.size > 5 * 1024 * 1024) {
      return fail(413, "file_too_large", "图片不能超过 5 MB。");
    }

    const imageTypes = {
      "image/jpeg": "jpg",
      "image/png": "png",
      "image/webp": "webp",
      "image/gif": "gif",
    };
    const ext = imageTypes[file.type];
    if (!ext) {
      return fail(400, "invalid_type", "只支持 JPG、PNG、WebP、GIF 图片。");
    }

    const name = `${Date.now().toString(36)}-${randomHex(6)}.${ext}`;
    const key = `media/${name}`;
    await env.R2.put(key, file.stream(), {
      httpMetadata: {
        contentType: file.type,
        cacheControl: "public, max-age=31536000, immutable",
      },
    });

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "content.image",
      detail: key,
    });

    return json({ ok: true, url: `/media/${name}` });
  }

  /* ---------------- 工具管理 ---------------- */

  if (path === "/api/admin/tools" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const rows = await env.DB.prepare("SELECT * FROM tools ORDER BY sort_order, id").all();
    return json({ ok: true, items: rows.results || [] });
  }

  if (path === "/api/admin/tools" && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const body = await readJson(request);
    if (!body) return fail(400, "invalid_body", "请求格式不正确。");
    const input = normalizeToolInput(body);
    if (input.error) return fail(400, input.error, input.message);

    const now = nowIso();
    try {
      const result = await env.DB.prepare(
        `INSERT INTO tools (name, slug, intro, usage_text, entry_url, access_level, status, sort_order, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(input.name, input.slug, input.intro, input.usageText, input.entryUrl, input.accessLevel, input.status, input.sortOrder, now)
        .run();
      audit(ctx, env.DB, {
        actorType: "admin",
        actorId: auth.admin.id,
        action: "tool.create",
        detail: input.slug,
      });
      return json({ ok: true, id: result.meta.last_row_id });
    } catch (err) {
      if (String(err && err.message).includes("UNIQUE")) {
        return fail(409, "slug_conflict", "工具标识已存在，请换一个。");
      }
      throw err;
    }
  }

  const toolIdMatch = path.match(/^\/api\/admin\/tools\/(\d+)$/);
  if (toolIdMatch && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const toolId = parseInt(toolIdMatch[1], 10);
    const row = await env.DB.prepare("SELECT id, slug FROM tools WHERE id = ?").bind(toolId).first();
    if (!row) return fail(404, "not_found", "工具不存在。");

    const body = await readJson(request);
    if (!body) return fail(400, "invalid_body", "请求格式不正确。");
    const input = normalizeToolInput(body);
    if (input.error) return fail(400, input.error, input.message);

    try {
      await env.DB.prepare(
        `UPDATE tools SET name = ?, slug = ?, intro = ?, usage_text = ?, entry_url = ?,
                          access_level = ?, status = ?, sort_order = ?, updated_at = ?
          WHERE id = ?`
      )
        .bind(
          input.name,
          input.slug,
          input.intro,
          input.usageText,
          input.entryUrl,
          input.accessLevel,
          input.status,
          input.sortOrder,
          nowIso(),
          toolId
        )
        .run();
    } catch (err) {
      if (String(err && err.message).includes("UNIQUE")) {
        return fail(409, "slug_conflict", "工具标识已存在，请换一个。");
      }
      throw err;
    }

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "tool.update",
      detail: input.slug,
    });
    return json({ ok: true, item: { id: toolId, slug: input.slug } });
  }

  const toolStatusMatch = path.match(/^\/api\/admin\/tools\/(\d+)\/status$/);
  if (toolStatusMatch && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const toolId = parseInt(toolStatusMatch[1], 10);
    const body = await readJson(request);
    if (!body) return fail(400, "invalid_body", "请求格式不正确。");
    const status = body.status;
    if (!["draft", "published", "archived"].includes(status)) {
      return fail(400, "invalid_status", "工具状态不正确。");
    }

    const result = await env.DB.prepare("UPDATE tools SET status = ?, updated_at = ? WHERE id = ?")
      .bind(status, nowIso(), toolId)
      .run();
    if (!result.meta.changes) return fail(404, "not_found", "工具不存在。");

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "tool.status",
      detail: `${toolId} ${status}`,
    });
    return json({ ok: true, item: { id: toolId, status } });
  }

  /* ---------------- 资料管理 ---------------- */

  if (path === "/api/admin/resources" && method === "GET") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const rows = await env.DB.prepare(
      `SELECT r.*, c.name AS category_name
         FROM resources r LEFT JOIN content_categories c ON c.id = r.category_id
        ORDER BY r.updated_at DESC, r.id DESC LIMIT 300`
    ).all();
    return json({ ok: true, items: rows.results || [] });
  }

  if (path === "/api/admin/resources" && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const body = await readJson(request);
    if (!body) return fail(400, "invalid_body", "请求格式不正确。");
    const input = normalizeResourceInput(body);
    if (input.error) return fail(400, input.error, input.message);

    const now = nowIso();
    const result = await env.DB.prepare(
      `INSERT INTO resources (title, description, file_key, file_name, file_type, file_size, category_id,
                              access_level, status, version, sort_order, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        input.title,
        input.description,
        input.fileKey,
        input.fileName,
        input.fileType,
        input.fileSize,
        input.categoryId,
        input.accessLevel,
        input.status,
        input.version,
        input.sortOrder,
        now,
        now
      )
      .run();

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "resource.create",
      detail: `${input.fileKey} ${input.title}`,
    });

    return json({ ok: true, item: { id: Number(result.meta.last_row_id), title: input.title } });
  }

  const resourceIdMatch = path.match(/^\/api\/admin\/resources\/(\d+)$/);
  if (resourceIdMatch && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const resourceId = parseInt(resourceIdMatch[1], 10);
    const row = await env.DB.prepare("SELECT * FROM resources WHERE id = ?").bind(resourceId).first();
    if (!row) return fail(404, "not_found", "资料不存在。");

    const body = await readJson(request);
    if (!body) return fail(400, "invalid_body", "请求格式不正确。");
    const input = normalizeResourceInput({ ...row, ...body });
    if (input.error) return fail(400, input.error, input.message);

    await env.DB.prepare(
      `UPDATE resources SET title = ?, description = ?, file_key = ?, file_name = ?, file_type = ?, file_size = ?,
                            category_id = ?, access_level = ?, status = ?, version = ?, sort_order = ?, updated_at = ?
        WHERE id = ?`
    )
      .bind(
        input.title,
        input.description,
        input.fileKey,
        input.fileName,
        input.fileType,
        input.fileSize,
        input.categoryId,
        input.accessLevel,
        input.status,
        input.version,
        input.sortOrder,
        nowIso(),
        resourceId
      )
      .run();

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "resource.update",
      detail: `${input.fileKey} ${input.status}`,
    });

    return json({ ok: true, item: { id: resourceId, status: input.status } });
  }

  const resourceStatusMatch = path.match(/^\/api\/admin\/resources\/(\d+)\/status$/);
  if (resourceStatusMatch && method === "POST") {
    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    const resourceId = parseInt(resourceStatusMatch[1], 10);
    const body = await readJson(request);
    const status = body && body.status;
    if (!["draft", "published", "archived"].includes(status)) {
      return fail(400, "invalid_status", "资料状态不正确。");
    }
    const row = await env.DB.prepare("SELECT id FROM resources WHERE id = ?").bind(resourceId).first();
    if (!row) return fail(404, "not_found", "资料不存在。");

    await env.DB.prepare("UPDATE resources SET status = ?, updated_at = ? WHERE id = ?")
      .bind(status, nowIso(), resourceId)
      .run();

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "resource.status",
      detail: `${resourceId} ${status}`,
    });

    return json({ ok: true, item: { id: resourceId, status } });
  }

  // ---------- 上传资料文件到 R2 私有存储 ----------
  const resourceFileMatch = path.match(/^\/api\/admin\/resources\/(\d+)\/file$/);
  if (resourceFileMatch) {
    if (method !== "POST") return fail(405, "method_not_allowed", "不支持该请求方法。");
    if (!originAllowed(request)) return fail(403, "forbidden_origin", "请求来源不被允许。");

    const auth = await requireAdmin(request, env);
    if (auth.error) return auth.error;
    if (!env.R2) {
      return fail(503, "r2_not_configured", "尚未配置 R2 私有存储，请先按部署说明绑定存储桶。");
    }

    const resourceId = parseInt(resourceFileMatch[1], 10);
    const row = await env.DB.prepare("SELECT id, title FROM resources WHERE id = ?").bind(resourceId).first();
    if (!row) return fail(404, "not_found", "资料不存在。");

    const contentType = request.headers.get("Content-Type") || "";
    if (!contentType.includes("multipart/form-data")) {
      return fail(400, "invalid_body", "请使用文件上传表单提交。");
    }

    let form;
    try {
      form = await request.formData();
    } catch {
      return fail(400, "invalid_body", "上传数据解析失败，请重试。");
    }

    const file = form.get("file");
    if (!file || typeof file === "string" || !file.size) {
      return fail(400, "missing_file", "请选择要上传的文件。");
    }
    if (file.size > 200 * 1024 * 1024) {
      return fail(413, "file_too_large", "单个文件不能超过 200 MB。");
    }

    const originalName = String(file.name || "file");
    const safeName = originalName
      .replace(/[^\w.\- \u4e00-\u9fa5]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(-90) || "file";
    const rawExt = safeName.includes(".") ? safeName.split(".").pop().toLowerCase() : "";
    const ext = /^[a-z0-9]{1,12}$/.test(rawExt) ? rawExt : "bin";
    // R2 对象键只用 ASCII，避免中文路径在后台编辑时校验失败
    const fileKey = `resources/${resourceId}/${Date.now().toString(36)}-${randomHex(4)}.${ext}`;

    await env.R2.put(fileKey, file.stream(), {
      httpMetadata: { contentType: file.type || "application/octet-stream" },
    });

    await env.DB.prepare(
      "UPDATE resources SET file_key = ?, file_name = ?, file_type = ?, file_size = ?, updated_at = ? WHERE id = ?"
    )
      .bind(fileKey, safeName, ext, file.size, nowIso(), resourceId)
      .run();

    audit(ctx, env.DB, {
      actorType: "admin",
      actorId: auth.admin.id,
      action: "resource.upload",
      detail: `${resourceId} ${fileKey}`,
    });

    return json({
      ok: true,
      item: { id: resourceId, file_key: fileKey, file_name: safeName, file_type: ext, file_size: file.size },
    });
  }

  return fail(404, "not_found", "接口不存在。");
}

/* ------------------------------------------------------------------ */
/* 公开图片：课程正文配图（付费资料仍走会员下载，不放这里）             */
/* ------------------------------------------------------------------ */

const MEDIA_MIME = {
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  webp: "image/webp",
  gif: "image/gif",
};

async function handleMedia(request, env, url) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const match = url.pathname.match(/^\/media\/([a-z0-9-]+)\.(jpg|jpeg|png|webp|gif)$/);
  if (!match) return new Response("Not Found", { status: 404 });

  // 先查静态目录 public/media/ 下的文件（本地打包的静态图）。
  // 注意：Pages 对不存在的路径会回退到 index.html 并返回 200，
  // 所以不能只看 assetResp.ok，必须确认返回的确实是图片。
  const assetResp = await env.ASSETS.fetch(request).catch(() => null);
  if (assetResp && assetResp.ok) {
    const assetType = assetResp.headers.get("Content-Type") || "";
    if (assetType.toLowerCase().startsWith("image/")) return assetResp;
  }

  // 再查 R2 上传的媒体文件
  if (!env.R2) return new Response("Not Found", { status: 404, headers: BASE_HEADERS });
  const obj = await env.R2.get(`media/${match[1]}.${match[2]}`);
  if (!obj) return new Response("Not Found", { status: 404, headers: BASE_HEADERS });

  const storedType = (obj.httpMetadata && obj.httpMetadata.contentType) || "";
  const contentType = storedType.toLowerCase().startsWith("image/")
    ? storedType
    : MEDIA_MIME[match[2]] || "application/octet-stream";

  return new Response(request.method === "HEAD" ? null : obj.body, {
    status: 200,
    headers: {
      "Content-Type": contentType,
      "Content-Length": String(obj.size ?? ""),
      "Cache-Control": "public, max-age=31536000, immutable",
      ...BASE_HEADERS,
    },
  });
}

/* ------------------------------------------------------------------ */
/* 课程附件下载：免费课程公开，会员课程先校验会话                      */
/* ------------------------------------------------------------------ */

async function handleContentAttachment(request, env, ctx, slug) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method Not Allowed", { status: 405, headers: BASE_HEADERS });
  }

  const course = await env.DB.prepare(
    "SELECT id, title, access_level FROM contents WHERE slug = ? AND status = 'published'"
  )
    .bind(slug)
    .first();
  if (!course) {
    return statePage({
      title: "附件不存在",
      heading: "课程不存在或尚未发布",
      message: "该课程可能已下架，请返回课程列表查看最新内容。",
      actionHref: "/member/app/courses/",
      actionText: "返回课程列表",
      status: 404,
    });
  }

  let session = { state: "anonymous" };
  if (course.access_level === "member") {
    session = await getMemberSession(request, env);
    if (session.state === "blocked") {
      return statePage({
        title: "会员权限不可用",
        heading: "当前会员权限暂不可用",
        message: "会员状态异常，请联系管理员核对后再试。",
        memberCode: session.member ? session.member.member_code : "",
        actionHref: "/member/",
        actionText: "返回访问码登录",
        status: 403,
      });
    }
    if (session.state !== "active") {
      const next = encodeURIComponent(`/member/app/courses/${slug}`);
      return Response.redirect(`${new URL(request.url).origin}/member/?next=${next}`, 302);
    }
  }

  const file = await env.DB.prepare("SELECT * FROM content_files WHERE content_id = ?").bind(course.id).first();
  if (!file || !env.R2) {
    return statePage({
      title: "附件尚未上传",
      heading: "该课程暂无可下载附件",
      message: "管理员上传附件后会出现在课程页面，请稍后再试。",
      actionHref: `/member/app/courses/${slug}`,
      actionText: "返回课程正文",
      status: 404,
    });
  }

  const object = await env.R2.get(file.file_key);
  if (!object) {
    return statePage({
      title: "附件暂不可用",
      heading: "附件文件不存在",
      message: "文件可能正在更新版本，请稍后再试或联系管理员。",
      actionHref: `/member/app/courses/${slug}`,
      actionText: "返回课程正文",
      status: 404,
    });
  }

  if (session.member) {
    audit(ctx, env.DB, {
      actorType: "member",
      actorId: session.member.id,
      action: "content.attachment",
      detail: `${course.id} ${course.title}`,
    });
  }

  const asciiName = String(file.file_name || "attachment").replace(/[^\x20-\x7e]/g, "_");
  return new Response(request.method === "HEAD" ? null : object.body, {
    status: 200,
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(
        file.file_name || "attachment"
      )}`,
      "Cache-Control": "private, no-store",
      ...BASE_HEADERS,
    },
  });
}

function requestUrl(request) {
  const url = new URL(request.url);
  return url.origin;
}

/* ------------------------------------------------------------------ */
/* 会员工具页：先服务端校验，再返回静态工具页                          */
/* ------------------------------------------------------------------ */

function toolNotFound() {
  return statePage({
    title: "工具不存在",
    heading: "工具不存在或尚未发布",
    message: "该工具可能已下架，请返回工具库查看最新入口。",
    actionHref: "/member/app/tools/",
    actionText: "返回工具库",
    status: 404,
  });
}

async function handleToolPage(request, env, url) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return fail(405, "method_not_allowed", "不支持该请求方法。");
  }

  const match = url.pathname.match(/^\/tools\/([a-z0-9][a-z0-9-]*)(\/index\.html)?\/?$/);
  if (!match) return toolNotFound();
  const slug = match[1];
  if (!url.pathname.endsWith("/") && !match[2]) {
    return Response.redirect(`${url.origin}/tools/${slug}/`, 308);
  }

  const toolRow = await env.DB.prepare(
    "SELECT slug, name, access_level FROM tools WHERE slug = ? AND status = 'published'"
  )
    .bind(slug)
    .first();
  if (!toolRow) return toolNotFound();

  if (toolRow.access_level === "member") {
    const session = await getMemberSession(request, env);
    if (session.state === "blocked") {
      return statePage({
        title: "会员权限不可用",
        heading: "当前会员权限暂不可用",
        message: "会员状态异常，请联系管理员核对后再试。",
        memberCode: session.member ? session.member.member_code : "",
        actionHref: "/member/",
        actionText: "返回访问码登录",
        status: 403,
      });
    }
    if (session.state !== "active") {
      const next = encodeURIComponent(`/tools/${slug}/`);
      return Response.redirect(`${url.origin}/member/?next=${next}`, 302);
    }
  }

  if (!env.ASSETS) return new Response("Not Found", { status: 404 });

  const assetUrl = new URL(request.url);
  assetUrl.pathname = `/tools/${slug}/index.html`;
  const assetResponse = await env.ASSETS.fetch(
    new Request(assetUrl.toString(), { method: request.method, headers: request.headers })
  );
  if (assetResponse.status === 404) return toolNotFound();

  const headers = new Headers(assetResponse.headers);
  headers.set("Cache-Control", "private, no-store");
  for (const [k, v] of Object.entries(BASE_HEADERS)) headers.set(k, v);
  return new Response(assetResponse.body, { status: 200, headers });
}

/* ------------------------------------------------------------------ */
/* 入口                                                                */
/* ------------------------------------------------------------------ */

async function handleRequest(request, env, ctx, url) {
    try {
      if (url.pathname.startsWith("/api/")) {
        return await handleApi(request, env, ctx, url);
      }

      // 统一补斜杠
      if (url.pathname === "/member" || url.pathname === "/admin") {
        return Response.redirect(url.origin + url.pathname + "/", 308);
      }

      // 公开免费内容（仅 access_level = free 且已发布的内容）
      if (url.pathname.startsWith("/library/")) {
        return await handlePublicLibrary(request, env, ctx, url);
      }

      // 会员工具页：服务端校验会员身份与工具发布状态后再返回页面
      if (url.pathname === "/tools" || url.pathname.startsWith("/tools/")) {
        return await handleToolPage(request, env, url);
      }

      // 课程正文配图（公开静态图片，与付费资料分开）
      if (url.pathname.startsWith("/media/")) {
        return await handleMedia(request, env, url);
      }

      // 会员专属区域：服务端先校验会话与会员状态，再渲染内容
      if (url.pathname === "/member/app") {
        return Response.redirect(url.origin + "/member/app/", 308);
      }

      if (url.pathname.startsWith("/member/app/")) {
        const session = await getMemberSession(request, env);
        if (session.state === "blocked") {
          return statePage({
            title: "会员权限不可用",
            heading: "当前会员权限暂不可用",
            message: "会员状态异常，请联系管理员核对后再试。",
            memberCode: session.member ? session.member.member_code : "",
            actionHref: "/member/",
            actionText: "返回访问码登录",
            status: 403,
          });
        }
        if (session.state !== "active") {
          const next = encodeURIComponent(url.pathname + url.search);
          return Response.redirect(`${url.origin}/member/?next=${next}`, 302);
        }
        return await handleMemberApp(request, env, ctx, url, session);
      }

      // 管理员后台：独立鉴权，普通会员无法进入
      if (url.pathname.startsWith("/admin/")) {
        const admin = await getAdminSession(request, env);
        if (!admin) {
          if (url.pathname === "/admin/") {
            const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM admins").first();
            const needsSetup = !(count && Number(count.n) > 0);
            return new Response(adminAuthPage({ needsSetup }), {
              headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...BASE_HEADERS },
            });
          }
          return Response.redirect(url.origin + "/admin/", 302);
        }
        return await handleAdminPage(request, env, url, admin);
      }

      // 课程附件：免费课程对所有人开放，会员课程由服务端校验会话
      const attachmentMatch = url.pathname.match(/^\/courses\/([a-z0-9][a-z0-9-]*)\/attachment\/?$/);
      if (attachmentMatch) {
        return await handleContentAttachment(request, env, ctx, attachmentMatch[1]);
      }

      if (!env.ASSETS) return new Response("Not Found", { status: 404 });
      const res = await env.ASSETS.fetch(request);
      return withBaseHeaders(res);
    } catch (err) {
      console.error("worker_error", err && err.stack ? err.stack : String(err));
      if (url.pathname.startsWith("/api/")) {
        return fail(500, "server_error", MSG.serverError);
      }
      return new Response("服务暂时不可用，请稍后重试。", {
        status: 500,
        headers: { "Content-Type": "text/plain; charset=utf-8", ...BASE_HEADERS },
      });
    }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const response = await handleRequest(request, env, ctx, url);
    try {
      return await applySiteSettings(response, request, env);
    } catch {
      return response;
    }
  },
};

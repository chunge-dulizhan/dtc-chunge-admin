/**
 * 第二轮服务端权限测试（不依赖 Cloudflare 环境）
 * 运行：node tests/worker.test.mjs
 *
 * 用 node:sqlite 模拟 D1，直接调用 public/_worker.js 的 fetch 处理函数，
 * 覆盖：管理员初始化、会员创建、访问码哈希、登录、会话、停用即时失效、限流、CSV 导出。
 */

import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

/* ---------------- D1 模拟 ---------------- */
function makeD1(db) {
  return {
    prepare(sql) {
      const attach = (args) => ({
        bind: (...more) => attach(more),
        first: async () => {
          const row = db.prepare(sql).get(...args);
          return row === undefined ? null : row;
        },
        all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
        run: async () => {
          const r = db.prepare(sql).run(...args);
          return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid) } };
        },
      });
      return attach([]);
    },
  };
}

const db = new DatabaseSync(":memory:");
db.exec(readFileSync(join(root, "db", "schema.sql"), "utf8"));
db.exec(readFileSync(join(root, "db", "seed.sql"), "utf8"));

const pending = [];
const env = {
  DB: makeD1(db),
  // 模拟真实 Pages 静态资源：只对预先存在的文件返回 200，其他返回 404
  ASSETS: {
    fetch: async (req) => {
      const pathname = new URL(req.url).pathname;
      // 预先打包的静态 media 文件不存在（测试里没有放），其他静态路径也一律返回 404
      // 真实 Pages 会扫描 public/ 目录，不存在的返回 404
      if (pathname.startsWith("/media/")) {
        return new Response("Not Found", { status: 404 });
      }
      // 模拟首页等静态页：带 data-copy 标记，便于测试文案替换
      return new Response(
        `<html>static<nav><a href="/"><span data-copy="public.nav.home">首页</span></a><a href="/courses/"><span data-copy="public.nav.courses">免费课程</span></a><a href="/guide/"><span data-copy="public.nav.guide">独立站入门</span></a><a href="/build/"><span data-copy="public.nav.build">建站教程</span></a></nav>` +
          `<h1 data-copy="public.home.hero.title">默认首页标题</h1>` +
          `<p data-copy="public.home.cases.description">默认案例描述</p>` +
          `<h1 data-copy="public.guide.title">独立站入门</h1>` +
          `<p data-copy="public.products.description">默认选品描述</p>` +
          `<h4 data-copy="public.tutorials.cta.title">默认建站引导</h4>` +
          `<a class="btn" href="/member/"><span data-copy="public.marketing.cta.button">会员中心</span></a>` +
          `<h2 data-copy="member.login.title">欢迎进入春哥独立站会员中心</h2>` +
          `<input id="access-code" name="access-code" placeholder="例如 VG8K-29PX-QM7D" data-copy-placeholder="member.login.input.placeholder"></html>`,
        { headers: { "Content-Type": "text/html" } }
      );
    },
  },
  CODE_PEPPER: "test-pepper-do-not-use-in-prod",
};
const ctx = { waitUntil: (p) => pending.push(p) };

const worker = (await import(pathToFileURL(join(root, "public", "_worker.js")).href)).default;

/* ---------------- 请求辅助 ---------------- */
const ORIGIN = "https://test.example.com";
let ipCounter = 0;

function req(path, { method = "GET", body, cookie, ip, headers = {} } = {}) {
  const h = new Headers({ Origin: ORIGIN, "CF-Connecting-IP": ip || `10.0.0.${++ipCounter}`, ...headers });
  if (body !== undefined) h.set("Content-Type", "application/json");
  if (cookie) h.set("Cookie", cookie);
  return new Request(ORIGIN + path, {
    method,
    headers: h,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function call(path, opts) {
  const res = await worker.fetch(req(path, opts), env, ctx);
  const text = await res.text();
  let data = null;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  return { res, data, text };
}

function setCookieToken(res) {
  const raw = res.headers.get("Set-Cookie") || "";
  return raw.split(";")[0];
}

const results = [];
function pass(name) {
  results.push(["PASS", name]);
  console.log("PASS  " + name);
}

/* ---------------- 1. 管理员初始化 ---------------- */
{
  const r = await call("/api/admin/setup", { method: "POST", body: { username: "chunge", password: "Chunge@2026!" } });
  assert.equal(r.res.status, 200, "首次初始化应成功");
  pass("首次部署可创建管理员");

  const again = await call("/api/admin/setup", { method: "POST", body: { username: "hacker", password: "Hacker123456" } });
  assert.equal(again.res.status, 403, "初始化完成后必须关闭入口");
  pass("初始化入口一次性关闭");

  const weak = await call("/api/admin/setup", { method: "POST", body: { username: "x", password: "123" } });
  assert.equal(weak.res.status, 403);
  pass("已初始化后无法再写入管理员");
}

/* ---------------- 2. 管理员登录 ---------------- */
let adminCookie = "";
{
  const bad = await call("/api/admin/login", { method: "POST", body: { username: "chunge", password: "wrong-password" } });
  assert.equal(bad.res.status, 401);
  assert.equal(bad.data.error, "invalid_credentials");
  pass("管理员错误密码被拒绝");

  const ok = await call("/api/admin/login", { method: "POST", body: { username: "chunge", password: "Chunge@2026!" }, ip: "10.9.9.9" });
  assert.equal(ok.res.status, 200);
  adminCookie = setCookieToken(ok.res);
  assert.match(adminCookie, /^chunge_admin=/);
  pass("管理员正确密码可登录");
}

/* ---------------- 3. 添加会员与访问码 ---------------- */
const created = [];
{
  for (const name of ["阿凯", "小雨", "老周"]) {
    const r = await call("/api/admin/members", { method: "POST", body: { name, contact: "微信 " + name, source: "公众号" }, cookie: adminCookie });
    assert.equal(r.res.status, 200, "添加会员失败：" + r.text);
    assert.match(r.data.member.member_code, /^CG\d{4}$/);
    assert.match(r.data.access_code, /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    created.push(r.data);
  }
  assert.deepEqual(created.map((m) => m.member.member_code), ["CG0001", "CG0002", "CG0003"]);
  pass("自动生成 CG0001/CG0002/CG0003 会员编号");

  assert.notEqual(created[0].access_code, created[1].access_code);
  pass("不同会员获得不同访问码");
}

/* 数据库里不得出现明文访问码 */
{
  const rows = db.prepare("SELECT code_hash, code_hint FROM access_codes").all();
  assert.equal(rows.length, 3);
  for (const row of rows) {
    assert.equal(row.code_hash.length, 64, "访问码应以 SHA-256 哈希保存");
  }
  const plain = created.map((m) => m.access_code.replace(/-/g, ""));
  for (const row of rows) {
    for (const p of plain) assert.ok(!row.code_hash.includes(p) && !row.code_hash.includes(p.toLowerCase()));
  }
  pass("数据库中只保存访问码哈希，不含明文");
}

/* ---------------- 4. 会员登录 ---------------- */
let memberCookie = "";
{
  // 大小写与分隔符都应被规范化
  const code = created[0].access_code.toLowerCase().replace(/-/g, "");
  const ok = await call("/api/member/login", { method: "POST", body: { code } });
  assert.equal(ok.res.status, 200, ok.text);
  memberCookie = setCookieToken(ok.res);
  const rawCookie = ok.res.headers.get("Set-Cookie");
  assert.match(rawCookie, /HttpOnly/);
  assert.match(rawCookie, /Secure/);
  assert.match(rawCookie, /SameSite=Lax/);
  assert.match(rawCookie, /Max-Age=2592000/);
  pass("正确访问码可登录，Cookie 为 HttpOnly/Secure/SameSite 且 30 天");

  const wrong = await call("/api/member/login", { method: "POST", body: { code: "ZZZZ-ZZZZ-ZZZZ" } });
  assert.equal(wrong.res.status, 401);
  assert.equal(wrong.data.message, "请检查访问码是否输入正确。");
  assert.notEqual(wrong.data.message, ok.data.message);
  pass("错误访问码被拒绝且提示不泄露信息");

  // 另一个会员的访问码不能复用第一个会话（每个码独立签发会话）
  const other = await call("/api/member/login", { method: "POST", body: { code: created[1].access_code } });
  assert.equal(other.res.status, 200, other.text);
  const otherCookie = setCookieToken(other.res);
  const otherSession = await call("/api/member/session", { cookie: otherCookie });
  assert.equal(otherSession.data.member.member_code, "CG0002");
  pass("不同会员登录后身份各自独立、不会混用");
}

/* ---------------- 5. 刷新页面仍保持登录 ---------------- */
{
  const r = await call("/api/member/session", { cookie: memberCookie });
  assert.equal(r.res.status, 200);
  assert.equal(r.data.member.member_code, "CG0001");
  pass("会话在刷新/再次请求时保持有效");
}

/* ---------------- 6. 会员不能调用管理员接口 ---------------- */
{
  const r = await call("/api/admin/members", { cookie: memberCookie });
  assert.equal(r.res.status, 401);
  pass("会员 Cookie 无法访问管理员接口");

  const noCookie = await call("/api/admin/members");
  assert.equal(noCookie.res.status, 401);
  pass("未登录访客无法访问管理员接口");
}

/* ---------------- 7. 管理员暂停会员 -> 会话立即失效 ---------------- */
{
  const suspend = await call("/api/admin/members/1/status", { method: "POST", body: { status: "paused" }, cookie: adminCookie });
  assert.equal(suspend.res.status, 200);

  const r = await call("/api/member/session", { cookie: memberCookie });
  assert.equal(r.res.status, 401, "暂停时旧会话已被服务端吊销");
  pass("暂停会员后已有会话立即失效");

  const relogin = await call("/api/member/login", { method: "POST", body: { code: created[0].access_code } });
  assert.equal(relogin.res.status, 403);
  assert.equal(relogin.data.error, "member_disabled");
  pass("暂停会员后访问码也无法登录");

  const restore = await call("/api/admin/members/1/status", { method: "POST", body: { status: "active" }, cookie: adminCookie });
  assert.equal(restore.res.status, 200);

  const oldSession = await call("/api/member/session", { cookie: memberCookie });
  assert.equal(oldSession.res.status, 401, "旧会话在暂停时已被吊销");
  pass("恢复会员后旧会话仍然失效，必须重新登录");

  const newLogin = await call("/api/member/login", { method: "POST", body: { code: created[0].access_code } });
  assert.equal(newLogin.res.status, 200);
  memberCookie = setCookieToken(newLogin.res);
  pass("恢复会员后可重新输入访问码进入");
}

/* ---------------- 8. 重新生成访问码 ---------------- */
{
  const rotate = await call("/api/admin/members/1/rotate-code", { method: "POST", cookie: adminCookie });
  assert.equal(rotate.res.status, 200);
  assert.notEqual(rotate.data.access_code, created[0].access_code);

  const oldCode = await call("/api/member/login", { method: "POST", body: { code: created[0].access_code } });
  assert.equal(oldCode.res.status, 401, "旧访问码必须失效");
  pass("管理员重置访问码后旧码失效");

  const newCode = await call("/api/member/login", { method: "POST", body: { code: rotate.data.access_code } });
  assert.equal(newCode.res.status, 200);
  memberCookie = setCookieToken(newCode.res);
  pass("新访问码可正常登录");
}

/* ---------------- 9. 退出登录 ---------------- */
{
  const out = await call("/api/member/logout", { method: "POST", cookie: memberCookie });
  assert.equal(out.res.status, 200);
  assert.match(out.res.headers.get("Set-Cookie"), /Max-Age=0/);

  const after = await call("/api/member/session", { cookie: memberCookie });
  assert.equal(after.res.status, 401);
  pass("退出登录后原会话立即失效");
}

/* ---------------- 10. 登录限流 ---------------- */
{
  const ip = "10.10.10.10";
  const codes = [];
  for (let i = 0; i < 6; i++) {
    const r = await call("/api/member/login", { method: "POST", body: { code: "ABCD-EFGH-JKMN" }, ip });
    codes.push(r.res.status);
  }
  assert.equal(codes[0], 401);
  assert.equal(codes[5], 429, "连续输错应被临时锁定：" + codes.join(","));
  assert.ok((await call("/api/member/login", { method: "POST", body: { code: "ABCD-EFGH-JKMN" }, ip })).res.headers.get("Retry-After"));
  pass("连续输错访问码触发临时限流（401 -> 429）");
}

/* ---------------- 11. 软删除会员 ---------------- */
{
  const del = await call("/api/admin/members/3", { method: "DELETE", cookie: adminCookie });
  assert.equal(del.res.status, 200);

  const login = await call("/api/member/login", { method: "POST", body: { code: created[2].access_code } });
  assert.equal(login.res.status, 401);
  assert.equal(login.data.message, "请检查访问码是否输入正确。");
  pass("删除会员后其访问码立即失效");

  const list = await call("/api/admin/members", { cookie: adminCookie });
  assert.equal(list.data.items.length, 2, "软删除的会员不再出现在列表中");
  pass("删除采用软删除，列表立即不再展示");
}

/* ---------------- 12. CSV 导出 ---------------- */
{
  const r = await worker.fetch(req("/api/admin/members/export", { cookie: adminCookie }), env, ctx);
  const bytes = new Uint8Array(await r.arrayBuffer());
  const text = new TextDecoder().decode(bytes);
  assert.equal(r.status, 200);
  assert.match(r.headers.get("Content-Type"), /text\/csv/);
  assert.match(r.headers.get("Content-Disposition"), /attachment/);
  assert.equal(bytes[0], 0xef, "CSV 需带 BOM，首个字节应为 EF");
  assert.equal(bytes[1], 0xbb);
  assert.equal(bytes[2], 0xbf);
  assert.match(text, /会员编号/);
  assert.match(text, /CG0001/);
  assert.ok(!text.includes(created[0].access_code), "导出不得包含明文访问码");
  pass("CSV 导出可用，且不含明文访问码");
}

/* ---------------- 13. 安全响应头与越权访问 ---------------- */
{
  const r = await worker.fetch(req("/"), { ...env });
  const res = await r;
  assert.equal(res.headers.get("X-Frame-Options"), "DENY");
  assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
  pass("静态页面同样带安全响应头");

  // 跨站 Origin 发起的写操作
  const cross = await worker.fetch(
    new Request(ORIGIN + "/api/admin/members", {
      method: "POST",
      headers: { Origin: "https://evil.example.com", "Content-Type": "application/json", Cookie: adminCookie },
      body: JSON.stringify({ name: "攻击者" }),
    }),
    env,
    ctx
  );
  assert.equal(cross.status, 403);
  pass("跨站 Origin 的管理写操作被拒绝");
}

/* ---------------- 14. 未登录访问会员专属路径 ---------------- */
{
  const res = await worker.fetch(req("/member/app/dashboard"), env, ctx);
  assert.equal(res.status, 302);
  assert.match(res.headers.get("Location"), /\/member\/\?next=/);
  pass("/member/app/ 在未登录时被服务端重定向到访问码页");
}

/* ---------------- 15. 第三轮：公开内容与会员中心权限 ---------------- */
{
  // 未登录访客可以读免费内容
  const free = await call("/library/what-is-dtc");
  assert.equal(free.res.status, 200, "免费内容应公开可读");
  assert.match(free.text, /独立站到底是什么/);
  pass("未登录访客可访问免费公开内容");

  // 会员专属内容不能通过公开路径绕过
  const gated = await call("/library/90-day-roadmap");
  assert.equal(gated.res.status, 302);
  assert.match(gated.res.headers.get("Location"), /\/member\/\?next=/);
  pass("会员专属内容不会通过公开路径泄露");

  const anonApp = await call("/member/app/courses/");
  assert.equal(anonApp.res.status, 302);
  pass("未登录访问会员课程列表会被重定向到访问码页");

  // 新建会员并登录
  const m = await call("/api/admin/members", { method: "POST", body: { name: "测试会员" }, cookie: adminCookie });
  assert.equal(m.res.status, 200, m.text);
  const login = await call("/api/member/login", { method: "POST", body: { code: m.data.access_code } });
  const cookie = setCookieToken(login.res);

  const home = await call("/member/app/", { cookie });
  assert.equal(home.res.status, 200, "会员应能打开会员首页");
  assert.match(home.text, /欢迎回来/);
  assert.match(home.text, /测试会员/);
  assert.match(home.text, /CG0001|CG00/);
  pass("会员登录后可打开会员首页并显示身份信息");

  const detail = await call("/member/app/courses/90-day-roadmap", { cookie });
  assert.equal(detail.res.status, 200);
  assert.match(detail.text, /90 天从 0 到第一单/);
  assert.match(detail.text, /本篇目录/);
  pass("会员可阅读图文课程，服务端生成目录与章节");

  // 草稿内容对会员也不可见
  db.prepare(
    `INSERT INTO contents (title, slug, category_id, content_type, body, access_level, status, sort_order, created_at, updated_at)
     VALUES ('草稿内容', 'secret-draft', (SELECT id FROM content_categories WHERE slug = 'start'), 'article', '## 草稿', 'member', 'draft', 9, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`
  ).run();
  const draft = await call("/member/app/courses/secret-draft", { cookie });
  assert.equal(draft.res.status, 404);
  pass("草稿内容不会展示给会员");

  const resources = await call("/member/app/resources/", { cookie });
  assert.equal(resources.res.status, 200);
  assert.match(resources.text, /运营资料库/);
  pass("会员可打开资料库页面");

  // 管理员暂停后，页面必须立即拒绝
  const suspend = await call(`/api/admin/members/${m.data.member.id}/status`, {
    method: "POST",
    body: { status: "paused" },
    cookie: adminCookie,
  });
  assert.equal(suspend.res.status, 200);

  const blocked = await call("/member/app/", { cookie });
  assert.equal(blocked.res.status, 302, "暂停会员不能继续访问会员内容");
  assert.match(blocked.res.headers.get("Location"), /\/member\//);
  assert.ok(!blocked.text.includes("欢迎回来"));

  const relogin = await call("/api/member/login", { method: "POST", body: { code: m.data.access_code } });
  assert.equal(relogin.res.status, 403);
  assert.equal(relogin.data.error, "member_disabled");
  pass("会员被暂停后已有会话失效且无法重新进入");
}

/* ---------------- 16. 第四轮：后台页面与内容/资料管理 ---------------- */
{
  const adminHome = await call("/admin/", { cookie: adminCookie });
  assert.equal(adminHome.res.status, 200);
  assert.match(adminHome.text, /后台概览/);
  pass("管理员登录后可打开后台首页");

  const anonAdmin = await call("/admin/", {});
  assert.equal(anonAdmin.res.status, 200);
  assert.match(anonAdmin.text, /管理员登录/);

  const anonAdminMembers = await call("/admin/members/", {});
  assert.equal(anonAdminMembers.res.status, 302);
  pass("未登录访问后台子页面会被重定向到登录页");

  // 会员 Cookie 不能进入后台
  const m4 = await call("/api/admin/members", { method: "POST", body: { name: "第四轮会员" }, cookie: adminCookie });
  const m4login = await call("/api/member/login", { method: "POST", body: { code: m4.data.access_code } });
  const m4cookie = setCookieToken(m4login.res);
  const memberTryAdmin = await call("/admin/", { cookie: m4cookie });
  assert.equal(memberTryAdmin.res.status, 200);
  assert.match(memberTryAdmin.text, /管理员登录/);

  const memberApi = await call("/api/admin/contents", { cookie: m4cookie });
  assert.equal(memberApi.res.status, 401);
  pass("普通会员既不能打开后台页面，也不能调用管理员接口");

  // 创建并发布课程，会员立即可见
  const created = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "后台创建的测试课程",
      slug: "admin-round4",
      category_id: 1,
      access_level: "member",
      status: "published",
      body: "## 测试小节\n\n这是后台创建的测试正文，用于验证发布链路。",
    },
  });
  assert.equal(created.res.status, 200, created.text);

  const memberCourse = await call("/member/app/courses/admin-round4", { cookie: m4cookie });
  assert.equal(memberCourse.res.status, 200);
  assert.match(memberCourse.text, /测试小节/);

  await call(`/api/admin/contents/${created.data.item.id}/status`, {
    method: "POST",
    cookie: adminCookie,
    body: { status: "archived" },
  });
  const hiddenCourse = await call("/member/app/courses/admin-round4", { cookie: m4cookie });
  assert.equal(hiddenCourse.res.status, 404);
  pass("后台创建的课程可发布给会员，下架后会员立即看不到");

  // 资料元数据与列表
  const resCreated = await call("/api/admin/resources", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "后台创建的测试资料",
      description: "用于验证资料库链路",
      file_key: "test/demo.pdf",
      file_name: "demo.pdf",
      file_type: "pdf",
      status: "published",
      access_level: "member",
      version: "v1.0",
    },
  });
  assert.equal(resCreated.res.status, 200, resCreated.text);
  const memberRes = await call("/member/app/resources/", { cookie: m4cookie });
  assert.match(memberRes.text, /后台创建的测试资料/);
  pass("后台登记的资料会出现在会员资料库");

  const overview = await call("/api/admin/overview", { cookie: adminCookie });
  assert.equal(overview.res.status, 200);
  assert.ok(overview.data.members.total >= 1);
  pass("后台概览统计接口正常");
}

/* ---------------- 17. 第五轮：会员工具服务端权限与计算 ---------------- */
{
  const t5 = await call("/api/admin/members", { method: "POST", body: { name: "工具测试会员" }, cookie: adminCookie });
  assert.equal(t5.res.status, 200, t5.text);
  const t5login = await call("/api/member/login", { method: "POST", body: { code: t5.data.access_code } });
  const m4cookie = setCookieToken(t5login.res);

  // 未登录不能打开工具页（包括直接访问 index.html）
  for (const path of ["/tools/pricing/", "/tools/pricing/index.html"]) {
    const anon = await call(path);
    assert.equal(anon.res.status, 302, path + " 未登录应被重定向");
    assert.match(anon.res.headers.get("Location"), /\/member\/\?next=/);
  }
  pass("未登录访客无法打开会员工具页");

  // 缺少结尾斜杠时规范化
  const noSlash = await call("/tools/pricing");
  assert.equal(noSlash.res.status, 308);
  assert.match(noSlash.res.headers.get("Location"), /\/tools\/pricing\/$/);
  pass("工具路径缺少结尾斜杠时统一跳转");

  // 不存在或未发布的工具
  const unknown = await call("/tools/not-a-tool/", { cookie: m4cookie });
  assert.equal(unknown.res.status, 404);
  pass("不存在的工具返回 404");

  // 已登录会员可以打开工具页，且响应不允许缓存
  const toolPage = await call("/tools/pricing/", { cookie: m4cookie });
  assert.equal(toolPage.res.status, 200);
  assert.match(toolPage.res.headers.get("Cache-Control") || "", /no-store/);
  assert.equal(toolPage.res.headers.get("X-Frame-Options"), "DENY");
  pass("会员可打开受保护的工具页");

  // 计算接口：未登录被拒绝，已登录可用
  const anonCalc = await call("/api/tools/pricing/calc", { method: "POST", body: {} });
  assert.equal(anonCalc.res.status, 401);
  pass("未登录无法调用工具计算接口");

  const pricingCalc = await call("/api/tools/pricing/calc", {
    method: "POST",
    cookie: m4cookie,
    body: { product_cost: 8.5, shipping_cost: 4.2, ad_cost: 9, fee_rate: 4, target_margin: 35, currency: "USD" },
  });
  assert.equal(pricingCalc.res.status, 200, pricingCalc.text);
  assert.equal(pricingCalc.data.headline.value, "$35.57");
  assert.ok(Array.isArray(pricingCalc.data.items) && pricingCalc.data.items.length >= 4);
  assert.ok(Array.isArray(pricingCalc.data.advice) && pricingCalc.data.advice.length >= 1);
  pass("定价计算器在服务端返回建议售价与成本结构");

  const badInput = await call("/api/tools/pricing/calc", {
    method: "POST",
    cookie: m4cookie,
    body: { product_cost: -1, shipping_cost: 4, ad_cost: 9, fee_rate: 4, target_margin: 35 },
  });
  assert.equal(badInput.res.status, 400);
  assert.equal(badInput.data.error, "invalid_input");
  pass("非法参数被服务端拒绝");

  const adsCalc = await call("/api/tools/ads/calc", {
    method: "POST",
    cookie: m4cookie,
    body: { aov: 45, cvr: 2.5, cpc: 0.9, gross_margin: 45, currency: "USD" },
  });
  assert.equal(adsCalc.res.status, 200, adsCalc.text);
  assert.equal(adsCalc.data.headline.value, "$36.00");
  pass("广告计算器按 CPC 与转化率算出 CPA");

  const profitCalc = await call("/api/tools/profit/calc", {
    method: "POST",
    cookie: m4cookie,
    body: {
      price: 39.9,
      product_cost: 9,
      shipping_cost: 6.5,
      ad_cost: 8,
      fee_rate: 4.5,
      refund_rate: 5,
      other_cost: 1.5,
      currency: "USD",
    },
  });
  assert.equal(profitCalc.res.status, 200, profitCalc.text);
  assert.equal(profitCalc.data.headline.value, "$11.11");
  pass("利润计算器把退款与平台费计入净利");

  const calendarCalc = await call("/api/tools/calendar/calc", {
    method: "POST",
    cookie: m4cookie,
    body: { month: 11 },
  });
  assert.equal(calendarCalc.res.status, 200, calendarCalc.text);
  assert.equal(calendarCalc.data.items.length, 3);
  assert.match(calendarCalc.data.items[1].label, /黑色星期五/);
  pass("节日日历按月返回节日与备货节点");

  const aiCalc = await call("/api/tools/ai-sourcing/calc", {
    method: "POST",
    cookie: m4cookie,
    body: { category: "宠物用品", audience: "美国养猫女性", market: "US", price_band: "25-45" },
  });
  assert.equal(aiCalc.res.status, 200, aiCalc.text);
  assert.match(aiCalc.data.prompt, /品类：宠物用品/);
  assert.match(aiCalc.data.prompt, /目标市场：美国/);
  pass("AI 选品 SOP 生成可复制的服务端提示词");

  // 工具下架后页面与计算接口都立即关闭
  db.prepare("UPDATE tools SET status = 'archived' WHERE slug = 'pricing'").run();
  const archivedPage = await call("/tools/pricing/", { cookie: m4cookie });
  assert.equal(archivedPage.res.status, 404);
  const archivedCalc = await call("/api/tools/pricing/calc", { method: "POST", cookie: m4cookie, body: {} });
  assert.equal(archivedCalc.res.status, 404);
  db.prepare("UPDATE tools SET status = 'published' WHERE slug = 'pricing'").run();
  pass("工具下架后页面与计算接口同时失效");

  // 跨站 Origin 的计算请求被拒绝
  const crossCalc = await worker.fetch(
    new Request(ORIGIN + "/api/tools/pricing/calc", {
      method: "POST",
      headers: { Origin: "https://evil.example.com", "Content-Type": "application/json", Cookie: m4cookie },
      body: JSON.stringify({}),
    }),
    env,
    ctx
  );
  assert.equal(crossCalc.status, 403);
  pass("跨站 Origin 的工具计算请求被拒绝");

  // 会员被暂停后，工具页与计算接口都不可用
  await call("/api/admin/members/" + t5.data.member.id + "/status", {
    method: "POST",
    body: { status: "paused" },
    cookie: adminCookie,
  });
  const blockedTool = await call("/tools/pricing/", { cookie: m4cookie });
  assert.equal(blockedTool.res.status, 302);
  const blockedCalc = await call("/api/tools/pricing/calc", { method: "POST", cookie: m4cookie, body: {} });
  assert.equal(blockedCalc.res.status, 401);
  pass("会员被暂停后工具页与计算接口同步失效");
}

/* ---------------- 18. 第五轮：R2 上传入口鉴权 ---------------- */
{
  const t6 = await call("/api/admin/members", { method: "POST", body: { name: "上传测试会员" }, cookie: adminCookie });
  const t6login = await call("/api/member/login", { method: "POST", body: { code: t6.data.access_code } });
  const memberCookie = setCookieToken(t6login.res);

  const noAuth = await call("/api/admin/resources/1/file", { method: "POST", body: {} });
  assert.equal(noAuth.res.status, 401);
  pass("未登录无法上传资料文件");

  const memberUpload = await call("/api/admin/resources/1/file", { method: "POST", cookie: memberCookie, body: {} });
  assert.equal(memberUpload.res.status, 401);
  pass("会员无法调用资料上传接口");

  const noR2 = await call("/api/admin/resources/1/file", { method: "POST", cookie: adminCookie, body: {} });
  assert.equal(noR2.res.status, 503);
  assert.equal(noR2.data.error, "r2_not_configured");
  pass("未绑定 R2 时上传接口给出明确提示");
}

/* ---------------- 19. 第五轮：后台工具管理 ---------------- */
{
  const noAuth = await call("/api/admin/tools");
  assert.equal(noAuth.res.status, 401);
  pass("未登录无法读取工具管理列表");

  const list = await call("/api/admin/tools", { cookie: adminCookie });
  assert.equal(list.res.status, 200);
  assert.equal(list.data.items.length, 5);
  pass("管理员可读取工具列表");

  const created2 = await call("/api/admin/tools", {
    method: "POST",
    cookie: adminCookie,
    body: {
      name: "物流成本计算器",
      slug: "logistics",
      entry_url: "/tools/logistics/",
      intro: "估算头程与尾程成本",
      usage_text: "填写重量与渠道单价",
      access_level: "member",
      status: "draft",
      sort_order: 90,
    },
  });
  assert.equal(created2.res.status, 200, created2.text);
  pass("管理员可新增工具");

  const dup = await call("/api/admin/tools", {
    method: "POST",
    cookie: adminCookie,
    body: {
      name: "重复工具",
      slug: "logistics",
      entry_url: "/tools/logistics/",
      access_level: "member",
      status: "draft",
    },
  });
  assert.equal(dup.res.status, 409);
  pass("重复工具标识被拒绝");

  const badUrl = await call("/api/admin/tools", {
    method: "POST",
    cookie: adminCookie,
    body: {
      name: "非法入口",
      slug: "bad-entry",
      entry_url: "https://github.example.com/tool",
      access_level: "member",
      status: "draft",
    },
  });
  assert.equal(badUrl.res.status, 400);
  assert.equal(badUrl.data.error, "invalid_entry_url");
  pass("工具入口必须是站内受保护路径");

  const upd = await call("/api/admin/tools/" + created2.data.id, {
    method: "POST",
    cookie: adminCookie,
    body: {
      name: "物流成本计算器",
      slug: "logistics",
      entry_url: "/tools/logistics/",
      intro: "估算头程与尾程成本",
      usage_text: "填写重量与渠道单价",
      access_level: "member",
      status: "published",
      sort_order: 90,
    },
  });
  assert.equal(upd.res.status, 200);
  pass("管理员可编辑并发布工具");
}

/* ---------------- 20. 第五轮：课程配图上传与公开图片路由 ---------------- */
{
  const anon = await call("/api/admin/uploads/image", { method: "POST", body: {} });
  assert.equal(anon.res.status, 401);
  pass("未登录无法上传课程配图");

  const noR2 = await call("/api/admin/uploads/image", { method: "POST", cookie: adminCookie, body: {} });
  assert.equal(noR2.res.status, 503);
  assert.equal(noR2.data.error, "r2_not_configured");
  pass("未绑定 R2 时课程配图上传给出明确提示");

  const media = await call("/media/abc123.png");
  assert.equal(media.res.status, 404);
  const traversal = await call("/media/%2e%2e%2fsecret.png");
  assert.equal(traversal.res.status, 404);
  pass("公开图片路由只接受合法文件名");

  // 回归：真实 Cloudflare Pages 对不存在的路径会回退到 index.html 并返回 200，
  // 这里必须确认 handleMedia 不会把 HTML 页面当作图片返回。
  const htmlFallback = async () =>
    new Response("<html>fallback</html>", {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });

  const fbEnv = { ...env, ASSETS: { fetch: htmlFallback } };
  const fb = await worker.fetch(req("/media/abc123.png"), fbEnv, ctx);
  assert.equal(fb.status, 404);
  assert.ok(!(fb.headers.get("Content-Type") || "").includes("text/html"), "不得把 HTML 回退当图片返回");
  pass("Pages 回退 HTML 时图片路由仍返回 404");

  const pngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const r2Env = {
    ...fbEnv,
    R2: {
      get: async (key) =>
        key === "media/abc123.png"
          ? { body: new Response(pngBytes).body, size: pngBytes.length, httpMetadata: { contentType: "image/png" } }
          : null,
    },
  };
  const img = await worker.fetch(req("/media/abc123.png"), r2Env, ctx);
  assert.equal(img.status, 200);
  assert.equal(img.headers.get("Content-Type"), "image/png");
  assert.equal(img.headers.get("Cache-Control"), "public, max-age=31536000, immutable");
  const bytes = new Uint8Array(await img.arrayBuffer());
  assert.equal(bytes.length, pngBytes.length);
  pass("HTML 回退环境下 R2 图片仍按二进制与正确 MIME 返回");
}

/* ---------------- 21. 第五轮：网站基础设置 ---------------- */
{
  const anon = await call("/api/admin/settings");
  assert.equal(anon.res.status, 401);
  pass("未登录无法读取网站设置");

  const read = await call("/api/admin/settings", { cookie: adminCookie });
  assert.equal(read.res.status, 200);
  assert.equal(read.data.item.brand_name, "独立站春哥");
  pass("管理员可读取网站设置默认值");

  const saved = await call("/api/admin/settings", {
    method: "POST",
    cookie: adminCookie,
    body: {
      brand_name: "春哥独立站实验室",
      tagline: "独立站实战教学与陪跑",
      intro: "帮新手把第一个独立站跑通。",
      wechat: "chun_test_wechat",
      footer_text: "© 2026 春哥独立站实验室｜微信 chun_test_wechat",
    },
  });
  assert.equal(saved.res.status, 200, saved.text);
  pass("管理员可保存网站设置");

  const staticPage = await call("/");
  assert.equal(staticPage.res.status, 200);
  assert.match(staticPage.text, /static/);
  pass("设置生效后没有命中替换的页面仍可完整返回");

  const page = await call("/library/what-is-dtc");
  assert.match(page.text, /春哥独立站实验室/);
  assert.match(page.text, /chun_test_wechat/);
  pass("公开页面按设置替换品牌与微信");

  const tooLong = await call("/api/admin/settings", {
    method: "POST",
    cookie: adminCookie,
    body: { brand_name: "春".repeat(40), wechat: "x", tagline: "y", intro: "z", footer_text: "f" },
  });
  assert.equal(tooLong.res.status, 400);
  assert.equal(tooLong.data.error, "invalid_settings");
  pass("超长品牌名被拒绝");

  const reset = await call("/api/admin/settings", {
    method: "POST",
    cookie: adminCookie,
    body: { brand_name: "", tagline: "", intro: "", wechat: "", footer_text: "" },
  });
  assert.equal(reset.res.status, 200);
  const pageBack = await call("/library/what-is-dtc");
  assert.match(pageBack.text, /独立站春哥/);
  assert.ok(!pageBack.text.includes("春哥独立站实验室"));
  pass("留空可恢复默认文案");
}

/* ---------------- 22. 第五轮：课程附件（R2 私有下载） ---------------- */
{
  const r2Store = new Map();
  const r2Env = {
    ...env,
    R2: {
      async put(key, value) {
        r2Store.set(key, Buffer.from(await new Response(value).arrayBuffer()));
        return { key };
      },
      async get(key) {
        const buf = r2Store.get(key);
        return buf ? { body: buf, size: buf.length } : null;
      },
      async delete(key) {
        r2Store.delete(key);
      },
    },
  };

  async function rcall(path, opts) {
    const res = await worker.fetch(req(path, opts), r2Env, ctx);
    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    return { res, data, text };
  }

  async function upload(path, cookie, content, filename, type) {
    const form = new FormData();
    form.append("file", new File([content], filename, { type }));
    const headers = new Headers({ Origin: ORIGIN, "CF-Connecting-IP": "10.0.0.240" });
    if (cookie) headers.set("Cookie", cookie);
    const res = await worker.fetch(
      new Request(ORIGIN + path, { method: "POST", headers, body: form }),
      r2Env,
      ctx
    );
    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    return { res, data, text };
  }

  const member = await call("/api/admin/members", { method: "POST", body: { name: "附件测试会员" }, cookie: adminCookie });
  const login = await call("/api/member/login", { method: "POST", body: { code: member.data.access_code } });
  const cookie = setCookieToken(login.res);

  const course = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "带附件的会员课程",
      slug: "attach-member-course",
      access_level: "member",
      status: "published",
      body: "## 附件课程\n\n正文",
    },
  });
  assert.equal(course.res.status, 200, course.text);
  const courseId = course.data.item.id;

  const freeCourse = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "带附件的免费课程",
      slug: "attach-free-course",
      access_level: "free",
      status: "published",
      body: "## 免费课程\n\n正文",
    },
  });
  assert.equal(freeCourse.res.status, 200, freeCourse.text);

  const anonUpload = await upload("/api/admin/contents/" + courseId + "/attachment", "", "pdf-body", "sop.pdf", "application/pdf");
  assert.equal(anonUpload.res.status, 401);
  pass("未登录无法上传课程附件");

  const memberUpload = await upload("/api/admin/contents/" + courseId + "/attachment", cookie, "pdf-body", "sop.pdf", "application/pdf");
  assert.equal(memberUpload.res.status, 401);
  pass("会员无法上传课程附件");

  const adminUpload = await upload(
    "/api/admin/contents/" + courseId + "/attachment",
    adminCookie,
    "%PDF-1.4 test attachment",
    "会员 SOP.pdf",
    "application/pdf"
  );
  assert.equal(adminUpload.res.status, 200, adminUpload.text);
  assert.equal(adminUpload.data.item.file_name, "会员 SOP.pdf");
  pass("管理员可上传课程附件到私有存储");

  const noLogin = await rcall("/courses/attach-member-course/attachment");
  assert.equal(noLogin.res.status, 302);
  assert.match(noLogin.res.headers.get("Location") || "", /\/member\/\?next=/);
  pass("未登录下载会员课程附件会被引导登录");

  const download = await rcall("/courses/attach-member-course/attachment", { cookie });
  assert.equal(download.res.status, 200);
  assert.match(download.text, /%PDF-1\.4 test attachment/);
  assert.match(download.res.headers.get("Content-Disposition") || "", /attachment/);
  pass("会员可下载课程附件且不暴露公开地址");

  const freeUpload = await upload(
    "/api/admin/contents/" + freeCourse.data.item.id + "/attachment",
    adminCookie,
    "free-file-body",
    "免费清单.txt",
    "text/plain"
  );
  assert.equal(freeUpload.res.status, 200, freeUpload.text);
  const freeDownload = await rcall("/courses/attach-free-course/attachment");
  assert.equal(freeDownload.res.status, 200);
  assert.match(freeDownload.text, /free-file-body/);
  pass("免费课程附件可被访客下载");

  const coursePage = await rcall("/member/app/courses/attach-member-course", { cookie });
  assert.match(coursePage.text, /课程附件/);
  assert.match(coursePage.text, /\/courses\/attach-member-course\/attachment/);
  pass("课程正文显示附件下载入口");

  const removed = await call("/api/admin/contents/" + courseId + "/attachment/remove", {
    method: "POST",
    cookie: adminCookie,
  });
  assert.equal(removed.res.status, 200);
  const gone = await rcall("/courses/attach-member-course/attachment", { cookie });
  assert.equal(gone.res.status, 404);
  pass("删除附件后下载入口立即失效");

  await call(`/api/admin/contents/${freeCourse.data.item.id}/status`, {
    method: "POST",
    cookie: adminCookie,
    body: { status: "archived" },
  });
  const archived = await rcall("/courses/attach-free-course/attachment");
  assert.equal(archived.res.status, 404);
  pass("课程下架后附件同时失效");
}

/* ---------------- 6. 公开免费课程列表与课程图片 ---------------- */
{
  const login = await call("/api/admin/login", { method: "POST", body: { username: "chunge", password: "Chunge@2026!" } });
  const adminCookie = setCookieToken(login.res);

  const freeBody = "开头文字。\n\n![图片说明](/media/pub-free.png)\n\n结尾文字。";
  const free = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "免费课程测试",
      slug: "public-free-test",
      content_type: "article",
      access_level: "free",
      status: "published",
      sort_order: 0,
      excerpt: "免费课程摘要",
      body: freeBody,
    },
  });
  assert.equal(free.res.status, 200, "免费课程创建应成功");

  const member = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "会员课程测试",
      slug: "public-member-test",
      content_type: "article",
      access_level: "member",
      status: "published",
      sort_order: 0,
      excerpt: "会员课程摘要",
      body: "会员正文",
    },
  });
  assert.equal(member.res.status, 200, "会员课程创建应成功");

  const draft = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "免费草稿测试",
      slug: "public-draft-test",
      content_type: "article",
      access_level: "free",
      status: "draft",
      sort_order: 0,
      body: "草稿正文",
    },
  });
  assert.equal(draft.res.status, 200);

  const list = await call("/courses/");
  assert.equal(list.res.status, 200, "公开课程列表应可访问");
  assert.match(list.text, /免费课程测试/, "已发布的免费课程应出现在公开列表");
  assert.match(list.text, /\/library\/public-free-test\//, "公开列表应链接到课程详情");
  assert.doesNotMatch(list.text, /会员课程测试/, "会员专属课程不得出现在公开列表");
  assert.doesNotMatch(list.text, /免费草稿测试/, "草稿不得出现在公开列表");
  pass("公开课程列表只显示已发布的免费课程");

  const aliasList = await call("/library/");
  assert.equal(aliasList.res.status, 200);
  assert.match(aliasList.text, /免费课程测试/);
  pass("/library/ 与 /courses/ 展示同一份公开课程列表");

  const detail = await call("/library/public-free-test/");
  assert.equal(detail.res.status, 200, "访客应能打开免费课程详情");
  assert.match(detail.text, /<img[^>]*src="\/media\/pub-free.png"/, "正文图片应渲染为 img 标签");
  assert.match(detail.text, /免费/, "免费内容应有免费标识");
  pass("访客可阅读免费课程且正文图片正确渲染");

  const memberDetail = await call("/library/public-member-test/");
  assert.equal(memberDetail.res.status, 302, "访客打开会员课程应跳转登录");
  assert.match(memberDetail.res.headers.get("Location") || "", /\/member\//);
  pass("访客无法打开会员专属课程");

  const alias = await call("/courses/public-free-test/");
  assert.equal(alias.res.status, 302);
  assert.match(alias.res.headers.get("Location") || "", /\/library\/public-free-test\//);
  pass("/courses/<slug>/ 会跳转到公开详情页");
}

/* ---------------- 23. 第四轮：免费课程详情页附件展示 ---------------- */
{
  const r2Store = new Map();
  const r2Env = {
    ...env,
    R2: {
      async put(key, value) {
        r2Store.set(key, Buffer.from(await new Response(value).arrayBuffer()));
        return { key };
      },
      async get(key) {
        const buf = r2Store.get(key);
        return buf ? { body: buf, size: buf.length } : null;
      },
      async delete(key) {
        r2Store.delete(key);
      },
    },
  };

  async function rcall(path, opts) {
    const res = await worker.fetch(req(path, opts), r2Env, ctx);
    const text = await res.text();
    let data = null;
    try { data = JSON.parse(text); } catch { data = text; }
    return { res, data, text };
  }

  async function upload(path, cookie, content, filename, type) {
    const form = new FormData();
    form.append("file", new File([content], filename, { type }));
    const headers = new Headers({ Origin: ORIGIN, "CF-Connecting-IP": "10.0.0.241" });
    if (cookie) headers.set("Cookie", cookie);
    const res = await worker.fetch(new Request(ORIGIN + path, { method: "POST", headers, body: form }), r2Env, ctx);
    const text = await res.text();
    let data = null;
    try { data = JSON.parse(text); } catch { data = text; }
    return { res, data, text };
  }

  const freePdf = await rcall("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "免费 PDF 课程", slug: "free-pdf-course", access_level: "free", status: "published", body: "## 免费 PDF\n\n正文" },
  });
  assert.equal(freePdf.res.status, 200, freePdf.text);
  const freePdfId = freePdf.data.item.id;

  const up = await upload("/api/admin/contents/" + freePdfId + "/attachment", adminCookie, "%PDF-1.4 free", "免费手册.pdf", "application/pdf");
  assert.equal(up.res.status, 200, up.text);

  const page = await rcall("/library/free-pdf-course/");
  assert.equal(page.res.status, 200);
  assert.match(page.text, /免费手册\.pdf/, "免费课程详情页必须显示 PDF 文件名称");
  assert.match(page.text, /\/courses\/free-pdf-course\/attachment/, "免费课程详情页必须显示附件下载入口");
  pass("免费课程详情页展示 PDF 名称与下载入口");

  const dl = await rcall("/courses/free-pdf-course/attachment");
  assert.equal(dl.res.status, 200, "访客应能直接下载免费课程 PDF");
  assert.match(dl.text, /%PDF-1\.4 free/);
  pass("访客免登录可下载免费课程 PDF");
}

/* ---------------- 24. 第四轮：课程/工具/资料删除 ---------------- */
{
  // 未登录删除必须被拒绝
  const noAuth = await call("/api/admin/contents/1/delete", { method: "POST" });
  assert.equal(noAuth.res.status, 401);
  pass("未登录无法调用删除接口");

  // 课程删除
  const content = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "待删除课程", slug: "delete-me-course", access_level: "free", status: "published", body: "正文" },
  });
  assert.equal(content.res.status, 200, content.text);
  const contentId = content.data.item.id;

  const delContent = await call(`/api/admin/contents/${contentId}/delete`, { method: "POST", cookie: adminCookie });
  assert.equal(delContent.res.status, 200, delContent.text);
  const contentList = await call("/api/admin/contents", { cookie: adminCookie });
  assert.ok(!contentList.text.includes("delete-me-course"), "已删除课程不得出现在后台列表");
  const publicList = await call("/courses/");
  assert.doesNotMatch(publicList.text, /待删除课程/, "已删除课程不得出现在公开列表");
  const contentAudit = db.prepare("SELECT id FROM audit_logs WHERE action = 'content.delete' AND detail LIKE '%delete-me-course%'").get();
  assert.ok(contentAudit, "删除课程必须写入审计日志");
  const recreated = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "复用路径课程", slug: "delete-me-course", access_level: "free", status: "draft", body: "正文" },
  });
  assert.equal(recreated.res.status, 200, "删除后原 slug 应可再次使用");
  pass("课程删除：软删除、列表排除、审计记录、slug 可复用");

  // 工具删除
  const tool = await call("/api/admin/tools", {
    method: "POST",
    cookie: adminCookie,
    body: { name: "待删除工具", slug: "delete-me-tool", entry_url: "/tools/delete-me-tool/", access_level: "member", status: "published" },
  });
  assert.equal(tool.res.status, 200, tool.text);
  const toolId = Number(tool.data.id);
  const delTool = await call(`/api/admin/tools/${toolId}/delete`, { method: "POST", cookie: adminCookie });
  assert.equal(delTool.res.status, 200, delTool.text);
  const toolList = await call("/api/admin/tools", { cookie: adminCookie });
  assert.ok(!toolList.text.includes("delete-me-tool"), "已删除工具不得出现在后台列表");
  const toolAudit = db.prepare("SELECT id FROM audit_logs WHERE action = 'tool.delete' AND detail LIKE '%delete-me-tool%'").get();
  assert.ok(toolAudit, "删除工具必须写入审计日志");
  pass("工具删除：软删除、列表排除、审计记录");

  // 资料删除
  const resource = await call("/api/admin/resources", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "待删除资料", file_key: "resources/delete-me/file.pdf", file_name: "file.pdf", file_type: "pdf", access_level: "member", status: "published" },
  });
  assert.equal(resource.res.status, 200, resource.text);
  const resourceId = resource.data.item.id;
  const delResource = await call(`/api/admin/resources/${resourceId}/delete`, { method: "POST", cookie: adminCookie });
  assert.equal(delResource.res.status, 200, delResource.text);
  const resourceList = await call("/api/admin/resources", { cookie: adminCookie });
  assert.ok(!resourceList.text.includes("delete-me"), "已删除资料不得出现在后台列表");
  const resourceAudit = db.prepare("SELECT id FROM audit_logs WHERE action = 'resource.delete' AND detail LIKE '%待删除资料%'").get();
  assert.ok(resourceAudit, "删除资料必须写入审计日志");
  const resourceRow = db.prepare("SELECT status, file_key FROM resources WHERE id = ?").get(resourceId);
  assert.equal(resourceRow.status, "deleted", "资料应为软删除而非物理删除");
  assert.equal(resourceRow.file_key, "resources/delete-me/file.pdf", "删除资料不得清理 R2 文件记录");
  pass("资料删除：软删除、列表排除、审计记录、R2 文件保留");
}

/* ---------------- 25. 第四轮：学员案例管理 ---------------- */
{
  // 后台案例页面
  const adminPage = await call("/admin/cases/", { cookie: adminCookie });
  assert.equal(adminPage.res.status, 200, adminPage.text.slice(0, 200));
  assert.match(adminPage.text, /案例管理/);
  const adminPageAnon = await call("/admin/cases/");
  assert.equal(adminPageAnon.res.status, 302, "访客打开后台案例页必须跳登录");
  pass("后台案例管理页仅管理员可见");

  // 新建草稿：前台不可见
  const draft = await call("/api/admin/cases", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "草稿案例", slug: "draft-case", category: "家居", status: "draft", body: "## 草稿\n\n内容", show_on_home: 1, summary: "草稿摘要" },
  });
  assert.equal(draft.res.status, 200, draft.text);
  const caseId = draft.data.item.id;
  let listPage = await call("/cases/");
  assert.doesNotMatch(listPage.text, /草稿案例/, "草稿案例不得出现在 /cases/");
  let homeApi = await call("/api/public/cases");
  assert.doesNotMatch(homeApi.text, /草稿案例/, "草稿案例不得出现在首页接口");
  const detail404 = await call("/cases/draft-case/");
  assert.equal(detail404.res.status, 404, "草稿案例详情必须 404");
  pass("草稿案例前台不可见");

  // 发布：前台可见
  const pub = await call(`/api/admin/cases/${caseId}/status`, { method: "POST", cookie: adminCookie, body: { status: "published" } });
  assert.equal(pub.res.status, 200, pub.text);
  listPage = await call("/cases/");
  assert.equal(listPage.res.status, 200);
  assert.match(listPage.text, /草稿案例/, "已发布案例必须出现在 /cases/");
  assert.match(listPage.text, /\/cases\/draft-case\//, "案例卡片必须链接到详情页");
  homeApi = await call("/api/public/cases");
  assert.equal(homeApi.res.status, 200);
  assert.match(homeApi.text, /草稿案例/, "show_on_home=1 的已发布案例必须出现在首页接口");
  const detail = await call("/cases/draft-case/");
  assert.equal(detail.res.status, 200, "已发布案例详情必须可访问");
  assert.match(detail.text, /<h2[^>]*>草稿<\/h2>|草稿/, "案例详情必须渲染正文");
  pass("发布案例后前台列表、详情与首页接口同步可见");

  // 编辑：标题同步
  const upd = await call(`/api/admin/cases/${caseId}`, {
    method: "POST",
    cookie: adminCookie,
    body: { title: "改名后的案例", category: "家居收纳" },
  });
  assert.equal(upd.res.status, 200, upd.text);
  const listAfter = await call("/cases/");
  assert.match(listAfter.text, /改名后的案例/, "后台编辑后前台必须同步");
  pass("编辑案例后前台自动同步");

  // 下架：前台立即失效
  await call(`/api/admin/cases/${caseId}/status`, { method: "POST", cookie: adminCookie, body: { status: "archived" } });
  const archivedDetail = await call("/cases/draft-case/");
  assert.equal(archivedDetail.res.status, 404, "下架案例详情必须 404");
  const archivedApi = await call("/api/public/cases");
  assert.doesNotMatch(archivedApi.text, /改名后的案例/, "下架案例不得出现在首页接口");
  pass("下架案例前台立即失效");

  // 删除：软删除 + 审计
  const del = await call(`/api/admin/cases/${caseId}/delete`, { method: "POST", cookie: adminCookie });
  assert.equal(del.res.status, 200, del.text);
  const adminList = await call("/api/admin/cases", { cookie: adminCookie });
  assert.ok(!adminList.text.includes("draft-case"), "已删除案例不得出现在后台列表");
  const caseAudit = db.prepare("SELECT id FROM audit_logs WHERE action = 'case.delete' AND detail LIKE '%draft-case%'").get();
  assert.ok(caseAudit, "删除案例必须写入审计日志");
  const caseRow = db.prepare("SELECT status FROM cases WHERE id = ?").get(caseId);
  assert.equal(caseRow.status, "deleted", "案例应为软删除而非物理删除");
  pass("删除案例：软删除、列表排除、审计记录");

  // 排序与首页开关：show_on_home=0 不出现在首页接口
  const noHome = await call("/api/admin/cases", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "仅列表案例", slug: "list-only-case", status: "published", show_on_home: 0, body: "正文", sort_order: 5 },
  });
  assert.equal(noHome.res.status, 200, noHome.text);
  const homeOnly = await call("/api/public/cases");
  assert.doesNotMatch(homeOnly.text, /仅列表案例/, "show_on_home=0 不得出现在首页接口");
  const allList = await call("/cases/");
  assert.match(allList.text, /仅列表案例/, "show_on_home=0 仍应出现在 /cases/ 列表");
  pass("首页展示开关只影响首页板块，不影响 /cases/ 列表");
}

/* ---------------- 26. 第五轮：案例编辑字段保留 ---------------- */
{
  const created = await call("/api/admin/cases", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "字段保留案例",
      slug: "keep-fields-case",
      category: "家居",
      summary: "原摘要",
      status: "published",
      show_on_home: 1,
      body: "## 第一段\n\n正文内容。\n\n![图](/media/keep.png)\n\n## 第二段\n\n结尾。",
    },
  });
  assert.equal(created.res.status, 200, created.text);
  const keepId = created.data.item.id;

  // 只更新封面：正文及其余字段必须保留
  const coverOnly = await call(`/api/admin/cases/${keepId}`, {
    method: "POST",
    cookie: adminCookie,
    body: { cover_image: "/media/new-cover.png" },
  });
  assert.equal(coverOnly.res.status, 200, coverOnly.text);
  let detail = await call(`/api/admin/cases/${keepId}`, { cookie: adminCookie });
  assert.equal(detail.data.item.body, "## 第一段\n\n正文内容。\n\n![图](/media/keep.png)\n\n## 第二段\n\n结尾。", "只换封面不得改动正文");
  assert.equal(detail.data.item.cover_image, "/media/new-cover.png");
  assert.equal(detail.data.item.title, "字段保留案例", "未提交字段必须保留原值");
  assert.equal(detail.data.item.summary, "原摘要", "未提交字段必须保留原值");
  assert.equal(detail.data.item.category, "家居", "未提交字段必须保留原值");
  pass("案例只更换封面时正文与其他字段完整保留");

  // 只更新标题：正文与封面保留
  await call(`/api/admin/cases/${keepId}`, {
    method: "POST",
    cookie: adminCookie,
    body: { title: "改名保留案例" },
  });
  detail = await call(`/api/admin/cases/${keepId}`, { cookie: adminCookie });
  assert.equal(detail.data.item.title, "改名保留案例");
  assert.match(detail.data.item.body, /第二段/, "只改标题不得改动正文");
  assert.equal(detail.data.item.cover_image, "/media/new-cover.png", "只改标题不得改动封面");
  pass("案例只修改标题时其他字段完整保留");

  // 前台详情仍渲染原正文图片
  const pubDetail = await call("/cases/keep-fields-case/");
  assert.equal(pubDetail.res.status, 200);
  assert.match(pubDetail.text, /\/media\/keep\.png/, "前台详情必须渲染正文图片");
  pass("案例前台详情正文渲染与后台保存一致");

  // 显式提交空正文才允许清空
  await call(`/api/admin/cases/${keepId}`, {
    method: "POST",
    cookie: adminCookie,
    body: { body: "" },
  });
  detail = await call(`/api/admin/cases/${keepId}`, { cookie: adminCookie });
  assert.equal(detail.data.item.body, "", "显式提交空正文才允许清空");
  pass("案例仅在显式提交空正文时才清空");

  // 新建功能不受编辑修复影响
  const fresh = await call("/api/admin/cases", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "新建回归案例", slug: "fresh-case", body: "新建正文" },
  });
  assert.equal(fresh.res.status, 200, fresh.text);
  const freshDetail = await call(`/api/admin/cases/${fresh.data.item.id}`, { cookie: adminCookie });
  assert.equal(freshDetail.data.item.body, "新建正文");
  pass("新建案例功能保持正常");
}

/* ---------------- 27. 第五轮：课程内容前后台一致 ---------------- */
{
  // member 1 的会话在前面测试中已被登出，这里用 member 2（从未被暂停/重置）重新登录
  const m2login = await call("/api/member/login", { method: "POST", body: { code: created[1].access_code } });
  assert.equal(m2login.res.status, 200, m2login.text);
  const m2Cookie = setCookieToken(m2login.res);

  // 未分类已发布课程必须出现在会员课程列表（修复前会被分组渲染漏掉）
  const uncategorized = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "未分类会员课程", slug: "uncat-member-course", access_level: "member", status: "published", body: "正文", category_id: null },
  });
  assert.equal(uncategorized.res.status, 200, uncategorized.text);
  const memberIndex = await call("/member/app/courses/", { cookie: m2Cookie });
  assert.equal(memberIndex.res.status, 200);
  assert.match(memberIndex.text, /未分类会员课程/, "会员课程列表必须显示未分类课程");
  assert.match(memberIndex.text, /未分类/, "会员课程列表必须包含未分类分组");
  pass("会员课程列表显示未分类课程（与后台数据一致）");

  // 后台修改免费课程后，公开前台立即同步（标题、摘要、正文）
  const freeCourse = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "同步前标题", slug: "sync-free-course", access_level: "free", status: "published", excerpt: "原摘要", body: "原正文" },
  });
  assert.equal(freeCourse.res.status, 200, freeCourse.text);
  const freeId = freeCourse.data.item.id;
  const updFree = await call(`/api/admin/contents/${freeId}`, {
    method: "POST",
    cookie: adminCookie,
    body: { title: "同步后标题", excerpt: "同步后摘要", body: "同步后正文" },
  });
  assert.equal(updFree.res.status, 200, updFree.text);
  const freePage = await call("/library/sync-free-course/");
  assert.equal(freePage.res.status, 200);
  assert.match(freePage.text, /同步后标题/, "免费详情页必须显示后台最新标题");
  assert.match(freePage.text, /同步后摘要/, "免费详情页必须显示后台最新摘要");
  assert.match(freePage.text, /同步后正文/, "免费详情页必须显示后台最新正文");
  const freeList = await call("/courses/");
  assert.match(freeList.text, /同步后标题/, "免费列表必须显示后台最新标题");
  pass("免费课程后台保存后前台列表与详情同步");

  // 后台修改会员课程后，会员中心详情同步，访客仍被拦截
  const memberCourse = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "会员同步前", slug: "sync-member-course", access_level: "member", status: "published", body: "会员正文" },
  });
  assert.equal(memberCourse.res.status, 200, memberCourse.text);
  const memberId = memberCourse.data.item.id;
  await call(`/api/admin/contents/${memberId}`, {
    method: "POST",
    cookie: adminCookie,
    body: { title: "会员同步后" },
  });
  const memberPage = await call("/member/app/courses/sync-member-course", { cookie: m2Cookie });
  assert.equal(memberPage.res.status, 200);
  assert.match(memberPage.text, /会员同步后/, "会员详情必须显示后台最新标题");
  assert.match(memberPage.text, /会员正文/, "会员详情必须显示后台正文");
  const guestPage = await call("/member/app/courses/sync-member-course");
  assert.equal(guestPage.res.status, 302, "访客访问会员课程必须跳登录");
  pass("会员课程后台保存后会员中心同步，访客权限未削弱");
}

/* ---------------- 28. 页面文案与导航自定义配置 ---------------- */
{
  // 重新登录一个会员（前面测试中的成员会话已失效）
  const m2login = await call("/api/member/login", { method: "POST", body: { code: created[1].access_code } });
  assert.equal(m2login.res.status, 200, m2login.text);
  const m2Cookie = setCookieToken(m2login.res);

  // 公开接口只返回 public.*，绝不泄露会员/后台专属文案
  const pub = await call("/api/public/copy");
  assert.equal(pub.res.status, 200);
  const pubKeys = Object.keys(pub.data.item);
  assert.ok(pubKeys.every((k) => k.startsWith("public.")), "公开接口只能返回 public.* 配置");
  assert.ok(!pubKeys.some((k) => k.startsWith("member.") || k.startsWith("admin.")), "不得返回会员或后台文案");
  assert.equal(pub.data.item["public.nav.home"], "首页", "未配置时返回默认值");
  pass("公开文案接口只暴露 public.* 并返回默认值");

  // 非管理员不能修改文案
  const anonSave = await call("/api/admin/copy", { method: "POST", body: { "public.nav.home": "x" } });
  assert.equal(anonSave.res.status, 401, "未登录不能修改文案");
  const memberSave = await call("/api/admin/copy", { method: "POST", body: { "public.nav.home": "x" }, cookie: m2Cookie });
  assert.ok([401, 403].includes(memberSave.res.status), "会员不能修改后台文案");
  pass("非管理员不能修改文案配置");

  // 管理员保存文案后，前台 HTML 实际替换 data-copy
  const save = await call("/api/admin/copy", {
    method: "POST",
    cookie: adminCookie,
    body: {
      "public.nav.home": "网站首页",
      "public.nav.courses": "免费学习",
      "public.home.hero.title": "自定义主标题",
      "public.home.cases.description": "自定义案例描述",
      "public.courses.uncategorized": "其它分类",
      "member.nav.courses": "会员课程",
      "member.home.tools.title": "工具台",
      "admin.nav.members": "用户管理",
    },
  });
  assert.equal(save.res.status, 200, save.text);

  const home = await call("/");
  assert.match(home.text, />网站首页</, "首页导航必须显示自定义名称");
  assert.match(home.text, /免费学习/, "首页导航免费课程必须显示自定义名称");
  assert.match(home.text, /自定义主标题/, "首页主标题必须替换为自定义文案");
  assert.match(home.text, /自定义案例描述/, "首页案例描述必须替换");
  pass("管理员保存文案后前台 HTML 实际生效");

  // 未配置的 key 仍使用默认，不出现空白
  assert.match(home.text, />独立站入门</, "未自定义的导航仍显示默认文案");

  // 免费课程页未分类标签生效
  const freeList = await call("/courses/");
  assert.match(freeList.text, /其它分类/, "免费课程页未分类名称可自定义");
  pass("免费课程页文案配置生效，未配置字段保持默认");

  // 会员中心与后台导航文案生效
  const memberHome = await call("/member/app/", { cookie: m2Cookie });
  assert.equal(memberHome.res.status, 200);
  assert.match(memberHome.text, />会员课程</, "会员导航名称可自定义");
  assert.match(memberHome.text, />工具台</, "会员首页板块标题可自定义");

  const adminHome = await call("/admin/", { cookie: adminCookie });
  assert.equal(adminHome.res.status, 200);
  assert.match(adminHome.text, />用户管理</, "后台导航名称可自定义");
  pass("会员中心与后台导航文案配置生效且互不影响");

  // 显式提交空值回退默认（不入库）
  await call("/api/admin/copy", { method: "POST", cookie: adminCookie, body: { "public.nav.home": "" } });
  const home2 = await call("/");
  assert.match(home2.text, />网站首页</, "提交空值不应覆盖已保存的自定义文案");
  pass("空值不会覆盖已保存文案，保留原值");

  // 恢复默认
  const reset = await call("/api/admin/copy/reset", { method: "POST", cookie: adminCookie });
  assert.equal(reset.res.status, 200);
  const home3 = await call("/");
  assert.match(home3.text, />首页</, "恢复默认后导航回到默认文案");
  assert.match(home3.text, />免费课程</, "恢复默认后免费课程回到默认");
  pass("恢复默认文案功能生效");
}

/* ---------------- 29. 第一阶段：全站文案覆盖扩展 ---------------- */
{
  // 重新登录会员，供会员页面断言使用
  const login = await call("/api/member/login", { method: "POST", body: { code: created[1].access_code } });
  assert.equal(login.res.status, 200, login.text);
  const memberCookie = setCookieToken(login.res);

  // 静态栏目页与登录页：服务端 data-copy / data-copy-placeholder 替换
  const saveStatic = await call("/api/admin/copy", {
    method: "POST",
    cookie: adminCookie,
    body: {
      "public.guide.title": "新手入门指南",
      "public.products.description": "爆品选品方法论",
      "public.tutorials.cta.title": "Shopify 建站清单",
      "public.marketing.cta.button": "进入会员",
      "member.login.title": "会员登录入口",
      "member.login.input.placeholder": "请输入 12 位访问码",
    },
  });
  assert.equal(saveStatic.res.status, 200, saveStatic.text);

  // 各栏目页动态渲染，仅展示自身栏目文案
  const guidePage = await call("/guide/");
  assert.match(guidePage.text, />新手入门指南</, "栏目页主标题必须替换");
  const productsPage = await call("/products/");
  assert.match(productsPage.text, /爆品选品方法论/, "选品栏目描述必须替换");
  const buildPage = await call("/build/");
  assert.match(buildPage.text, /Shopify 建站清单/, "建站栏目 CTA 标题必须替换");
  const marketingPage = await call("/marketing/");
  assert.match(marketingPage.text, /进入会员/, "营销栏目 CTA 按钮文字必须替换");
  assert.match(marketingPage.text, /href="\/member\/"/, "修改 CTA 文字不得改变 href");

  const memberLogin = await call("/member/");
  assert.match(memberLogin.text, />会员登录入口</, "会员登录页标题必须替换");
  assert.match(memberLogin.text, /placeholder="请输入 12 位访问码"/, "输入框 placeholder 必须替换");
  pass("各栏目页与会员登录页文案替换（含 placeholder 属性）");

  // 案例列表页
  const caseSave = await call("/api/admin/copy", {
    method: "POST",
    cookie: adminCookie,
    body: {
      "public.cases.title": "成功案例合集",
      "public.cases.description": "学员真实复盘记录",
      "public.cases.list.title": "案例目录",
    },
  });
  assert.equal(caseSave.res.status, 200, caseSave.text);
  const caseList = await call("/cases/");
  assert.match(caseList.text, />成功案例合集</, "案例列表主标题必须替换");
  assert.match(caseList.text, /学员真实复盘记录/, "案例列表描述必须替换");
  assert.match(caseList.text, />案例目录</, "案例列表区域标题必须替换");
  pass("案例列表页文案可修改");

  // 案例详情页（新建一篇已发布案例，确保详情存在）
  const caseCreate = await call("/api/admin/cases", {
    method: "POST",
    cookie: adminCookie,
    body: { title: "文案测试案例", slug: "copy-test-case", category: "测试", status: "published", body: "## 正文\n\n内容", summary: "摘要" },
  });
  assert.ok([200, 201].includes(caseCreate.res.status), caseCreate.text);
  await call("/api/admin/copy", {
    method: "POST",
    cookie: adminCookie,
    body: {
      "public.cases.detail.back": "返回列表",
      "public.cases.detail.cta.title": "加入会员解锁",
      "public.cases.detail.cta.description": "全部课程与工具",
      "public.cases.detail.cta.button": "立即咨询",
    },
  });
  const caseDetail = await call("/cases/copy-test-case/");
  assert.equal(caseDetail.res.status, 200, caseDetail.text);
  assert.match(caseDetail.text, />返回列表</, "案例详情返回按钮必须替换");
  assert.match(caseDetail.text, />加入会员解锁</, "案例详情 CTA 标题必须替换");
  assert.match(caseDetail.text, /全部课程与工具/, "案例详情 CTA 描述必须替换");
  assert.match(caseDetail.text, />立即咨询</, "案例详情 CTA 按钮必须替换");
  assert.match(caseDetail.text, /href="\/member\/"/, "案例 CTA 修改文案不改变 href");
  pass("案例详情页 CTA 可修改且不改变链接");

  // 会员课程页
  await call("/api/admin/copy", {
    method: "POST",
    cookie: adminCookie,
    body: {
      "member.courses.title": "实战课程中心",
      "member.courses.description": "按模块循序学习",
      "member.courses.list.title": "课程总览",
      "member.courses.detail.back": "回到课程",
    },
  });
  const mCourses = await call("/member/app/courses/", { cookie: memberCookie });
  assert.equal(mCourses.res.status, 200, mCourses.text);
  assert.match(mCourses.text, />实战课程中心</, "会员课程页标题必须替换");
  assert.match(mCourses.text, /按模块循序学习/, "会员课程页描述必须替换");
  assert.match(mCourses.text, />课程总览</, "会员课程列表标题必须替换");

  const mCourseDetail = await call("/member/app/courses/" + (mCourses.text.match(/\/member\/app\/courses\/([a-z0-9-]+)\//) || [])[1] + "/", {
    cookie: memberCookie,
  });
  if (mCourseDetail.res.status === 200) {
    assert.match(mCourseDetail.text, />回到课程</, "会员课程详情返回按钮必须替换");
  }
  pass("会员课程列表与详情页文案可修改");

  // 会员工具 / SOP / 资料 / 更新 页面
  await call("/api/admin/copy", {
    method: "POST",
    cookie: adminCookie,
    body: {
      "member.tools.title": "工具工作台",
      "member.tools.description": "在线测算一站式",
      "member.tools.section.title": "工具清单",
      "member.resources.title": "资料下载区",
      "member.resources.description": "模板与清单",
      "member.resources.download.button": "获取资料",
      "member.updates.title": "更新动态",
      "member.updates.description": "最近上新记录",
      "member.updates.section.title": "最新变动",
    },
  });
  const mTools = await call("/member/app/tools/", { cookie: memberCookie });
  assert.equal(mTools.res.status, 200, mTools.text);
  assert.match(mTools.text, />工具工作台</, "会员工具库标题必须替换");
  assert.match(mTools.text, /在线测算一站式/, "会员工具库描述必须替换");
  assert.match(mTools.text, />工具清单</, "工具库列表标题必须替换");

  const mRes = await call("/member/app/resources/", { cookie: memberCookie });
  assert.equal(mRes.res.status, 200, mRes.text);
  assert.match(mRes.text, />资料下载区</, "运营资料库标题必须替换");
  assert.match(mRes.text, /模板与清单/, "运营资料库描述必须替换");

  const mUpdates = await call("/member/app/updates/", { cookie: memberCookie });
  assert.equal(mUpdates.res.status, 200, mUpdates.text);
  assert.match(mUpdates.text, />更新动态</, "更新内容标题必须替换");
  assert.match(mUpdates.text, /最近上新记录/, "更新内容描述必须替换");
  assert.match(mUpdates.text, />最新变动</, "更新内容列表标题必须替换");
  pass("会员工具库 / 运营资料库 / 更新内容文案可修改");

  // SOP 使用 member.sop.* 命名空间
  await call("/api/admin/copy", {
    method: "POST",
    cookie: adminCookie,
    body: { "member.sop.title": "AI 工作流", "member.sop.description": "固化可复用步骤" },
  });
  const mSop = await call("/member/app/sop/", { cookie: memberCookie });
  assert.equal(mSop.res.status, 200, mSop.text);
  assert.match(mSop.text, />AI 工作流</, "AI 实操 SOP 标题必须替换");
  assert.match(mSop.text, /固化可复用步骤/, "AI 实操 SOP 描述必须替换");
  pass("AI 实操 SOP 文案可修改");

  // 管理员后台页面标题与描述
  await call("/api/admin/copy", {
    method: "POST",
    cookie: adminCookie,
    body: {
      "admin.pages.members.title": "用户中心",
      "admin.pages.members.description": "全部会员都在这里",
    },
  });
  const adminMembers = await call("/admin/members/", { cookie: adminCookie });
  assert.equal(adminMembers.res.status, 200, adminMembers.text);
  assert.match(adminMembers.text, />用户中心</, "后台页面标题必须替换");
  assert.match(adminMembers.text, /全部会员都在这里/, "后台页面描述必须替换");
  pass("管理员后台页面标题与描述可修改");

  // 新增配置项完整性：无重复 key，且全部纳入分组
  const adminCopyAll = await call("/api/admin/copy", { cookie: adminCookie });
  assert.equal(adminCopyAll.res.status, 200);
  const allKeys = Object.keys(adminCopyAll.data.item);
  assert.equal(new Set(allKeys).size, allKeys.length, "配置 key 不得重复");
  assert.ok(allKeys.length >= 100, `新增覆盖后配置项应超过 100 项，当前 ${allKeys.length}`);
  assert.ok(allKeys.some((k) => k.startsWith("public.cases.")), "必须包含案例配置");
  assert.ok(allKeys.some((k) => k.startsWith("member.login.")), "必须包含会员登录页配置");
  assert.ok(allKeys.some((k) => k.startsWith("admin.pages.")), "必须包含后台页面配置");
  pass("新增配置项完整且无重复 key");

  // 恢复默认后，新增页面文案回到默认
  const resetAll = await call("/api/admin/copy/reset", { method: "POST", cookie: adminCookie });
  assert.equal(resetAll.res.status, 200);
  const caseListDefault = await call("/cases/");
  assert.match(caseListDefault.text, />学员案例</, "恢复默认后案例列表标题回默认");
  const mToolsDefault = await call("/member/app/tools/", { cookie: memberCookie });
  assert.match(mToolsDefault.text, />网页工具库</, "恢复默认后会员工具库标题回默认");
  pass("恢复默认后新增页面文案正确回退");
}

/* ---------------- 30. 导航点击不被复制逻辑拦截 ---------------- */
{
  const siteJs = readFileSync(join(root, "public", "assets", "js", "site.js"), "utf8");
  assert.ok(!/closest\("\[data-copy\]"\)/.test(siteJs), "site.js 不得再把 data-copy 当作复制对象");
  assert.match(siteJs, /data-copy-text/, "site.js 复制逻辑必须绑定 data-copy-text");
  const memberJs = readFileSync(join(root, "public", "assets", "js", "member.js"), "utf8");
  assert.ok(!/querySelectorAll\("\[data-copy\]"\)/.test(memberJs), "member.js 不得监听 data-copy 导航元素");
  assert.match(memberJs, /data-copy-text/, "member.js 复制逻辑必须绑定 data-copy-text");
  pass("导航复制逻辑已隔离到 data-copy-text 专用按钮");

  // 导航元素带文案配置键，但仍保留原始 href
  const homeNav = await call("/");
  assert.match(homeNav.text, /<a[^>]*href="\/"[^>]*>[^<]*<span data-copy="public.nav.home">/, "首页导航链接必须保留 href");
  assert.match(homeNav.text, /data-copy="public.nav.build"/, "建站教程导航带配置键");
  assert.match(homeNav.text, /href="\/build\/"/, "建站教程导航 href 保持 /build/");
  pass("导航链接保留 href 且仅文字可配置");

  // Worker 服务端渲染页（/cases/）同样使用可配置导航，链接地址不变
  const renderedNav = await call("/cases/");
  assert.match(
    renderedNav.text,
    /<a href="\/build\/"><span data-copy="public.nav.build">建站教程<\/span><\/a>/,
    "服务端渲染页导航必须带文案配置键并保留原 href"
  );
  pass("服务端渲染页导航文案可配置且链接不变");
}

/* ---------------- 31. 第三轮：会员编码生成规则 ---------------- */
{
  const mk = (name) => call("/api/admin/members", { method: "POST", body: { name }, cookie: adminCookie });

  const a = await mk("编码测试A");
  const b = await mk("编码测试B");
  assert.equal(a.res.status, 200, a.text);
  assert.equal(b.res.status, 200, b.text);
  const codeA = a.data.member.member_code;
  const codeB = b.data.member.member_code;
  assert.match(codeA, /^CG\d{4}$/);
  assert.match(codeB, /^CG\d{4}$/);
  assert.ok(codeA !== codeB, "新会员不得重复编码");
  pass("新建会员按当前有效记录生成 CG 编码");

  // 删除会员：原编码归档，member_code 改为唯一墓碑值释放编号
  const delA = await call("/api/admin/members/" + a.data.member.id, { method: "DELETE", cookie: adminCookie });
  assert.equal(delA.res.status, 200, delA.text);
  const rowA = db.prepare(
    "SELECT member_code, archived_member_code, deleted_at, status FROM members WHERE id = ?"
  ).get(a.data.member.id);
  assert.equal(rowA.archived_member_code, codeA, "删除时必须归档原编码");
  assert.match(rowA.member_code, /^DEL-/, "墓碑编码不得占用原编号");
  assert.notEqual(rowA.member_code, codeA);
  assert.equal(rowA.status, "disabled");
  assert.ok(rowA.deleted_at, "会员必须为软删除");
  pass("删除会员时归档原编码并释放 CG 编号");

  const auditDel = db.prepare("SELECT detail FROM audit_logs WHERE action = 'member.delete' AND detail = ?").get(codeA);
  assert.ok(auditDel, "审计日志必须保留删除会员的原编码");
  pass("删除会员的审计日志保留原编号");

  const c = await mk("编码测试C");
  assert.equal(c.res.status, 200, c.text);
  assert.equal(c.data.member.member_code, codeA, "删除后新建应优先复用被释放的编号");
  pass("删除会员后新建会员复用被释放的 CG 编码");

  // 删除 CG0001 后应重新生成 CG0001
  const row1 = db.prepare("SELECT id FROM members WHERE member_code = 'CG0001' AND deleted_at IS NULL").get();
  assert.ok(row1, "测试前置：应存在 CG0001 有效会员");
  await call("/api/admin/members/" + row1.id, { method: "DELETE", cookie: adminCookie });
  const d = await mk("编码测试D");
  assert.equal(d.res.status, 200, d.text);
  assert.equal(d.data.member.member_code, "CG0001", "存在缺口时应补最小缺口");
  pass("删除 CG0001 后新建会员重新使用 CG0001");

  // 历史 CH 编码不参与 CG 序号计算
  db.prepare(
    "INSERT INTO members (member_code, name, status, member_type, created_at, updated_at) VALUES ('CH0008', '历史 CH 会员', 'active', 'lifetime', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')"
  ).run();
  const usedNums = new Set(
    db
      .prepare("SELECT member_code FROM members WHERE deleted_at IS NULL AND member_code LIKE 'CG%'")
      .all()
      .map((r) => parseInt(r.member_code.slice(2), 10))
  );
  let expectN = 1;
  while (usedNums.has(expectN)) expectN++;
  const expectCode = "CG" + String(expectN).padStart(4, "0");
  const e = await mk("编码测试E");
  assert.equal(e.res.status, 200, e.text);
  assert.equal(e.data.member.member_code, expectCode);
  pass("历史 CH 编码不参与 CG 序号计算");

  // 并发创建：不得产生重复编码
  const many = await Promise.all(Array.from({ length: 6 }, (_, i) => mk("并发会员" + i)));
  const codes = many.map((r) => (r.data && r.data.member ? r.data.member.member_code : "ERR:" + r.res.status));
  assert.equal(new Set(codes).size, 6, "并发创建出现重复编码：" + codes.join(","));
  assert.ok(codes.every((x) => /^CG\d{4}$/.test(x)), "并发编码格式异常：" + codes.join(","));
  pass("并发创建会员不产生重复编码");
}

/* ---------------- 32. 第三轮：课程封面与章节插图 ---------------- */
{
  const login = await call("/api/member/login", { method: "POST", body: { code: created[1].access_code } });
  assert.equal(login.res.status, 200, login.text);
  const cookie = setCookieToken(login.res);

  // 后台课程表单必须提供封面上传/更换/清除控件
  const adminContentPage = await call("/admin/content/", { cookie: adminCookie });
  assert.equal(adminContentPage.res.status, 200);
  for (const id of ["content-cover-file", "content-cover-upload", "content-cover-remove", "content-cover-preview", "content-body-preview"]) {
    assert.match(adminContentPage.text, new RegExp('id="' + id + '"'), "课程表单缺少 " + id);
  }
  pass("课程表单提供封面上传、更换、清除与正文图片预览控件");

  // 封面：创建 -> 回填 -> 更换 -> 清除
  const coverCourse = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "封面往返测试",
      slug: "cover-roundtrip",
      access_level: "free",
      status: "published",
      cover_image: "/media/cover-a.png",
      body: "## 封面课程\n\n正文",
    },
  });
  assert.equal(coverCourse.res.status, 200, coverCourse.text);
  const coverId = coverCourse.data.item.id;

  const adminDetail = await call("/api/admin/contents/" + coverId, { cookie: adminCookie });
  assert.equal(adminDetail.data.item.cover_image, "/media/cover-a.png", "再次打开编辑必须返回已保存封面");

  let publicPage = await call("/library/cover-roundtrip/");
  assert.equal(publicPage.res.status, 200);
  assert.match(publicPage.text, /class="m-cover"/, "公开详情页必须显示封面");
  assert.match(publicPage.text, /\/media\/cover-a\.png/);

  await call("/api/admin/contents/" + coverId, {
    method: "POST",
    cookie: adminCookie,
    body: { title: "封面往返测试", cover_image: "/media/cover-b.png" },
  });
  publicPage = await call("/library/cover-roundtrip/");
  assert.match(publicPage.text, /\/media\/cover-b\.png/, "更换封面后前台必须同步");
  assert.doesNotMatch(publicPage.text, /\/media\/cover-a\.png/);

  await call("/api/admin/contents/" + coverId, {
    method: "POST",
    cookie: adminCookie,
    body: { title: "封面往返测试", cover_image: "" },
  });
  publicPage = await call("/library/cover-roundtrip/");
  assert.doesNotMatch(publicPage.text, /class="m-cover"/, "清除封面后前台不再显示封面");
  pass("课程封面可保存、回填、更换与清除");

  // 章节：三章分别插入图片，保存后逐章独立
  const chapterCourse = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "三章插图课程",
      slug: "chapter-images",
      content_type: "chapter",
      access_level: "member",
      status: "published",
      body: "",
      chapters: [
        { title: "第一章 认识", body: "开头段落\n\n![第一章图](/media/ch1.png)\n\n结尾段落", sort_order: 0 },
        { title: "第二章 选品", body: "开头段落\n\n![第二章图](/media/ch2.png)\n\n结尾段落", sort_order: 1 },
        { title: "第三章 投放", body: "开头段落\n\n![第三章图](/media/ch3.png)\n\n结尾段落", sort_order: 2 },
      ],
    },
  });
  assert.equal(chapterCourse.res.status, 200, chapterCourse.text);
  const chapterId = chapterCourse.data.item.id;

  const adminChapters = await call("/api/admin/contents/" + chapterId, { cookie: adminCookie });
  assert.equal(adminChapters.data.item.chapters.length, 3);
  assert.match(adminChapters.data.item.chapters[0].body, /ch1\.png/, "图片必须随章节正文保存");
  assert.match(adminChapters.data.item.chapters[2].body, /ch3\.png/, "图片必须随章节正文保存");
  pass("章节正文插入的图片可保存，再次编辑仍然存在");

  const detail = await call("/member/app/courses/chapter-images", { cookie });
  assert.equal(detail.res.status, 200, detail.text.slice(0, 200));
  const text = detail.text;

  assert.match(text, /id="chapter-nav"/, "章节目录必须有独立容器");
  assert.equal((text.match(/id="chapter-panel-\d"/g) || []).length, 3, "每章必须有独立正文面板");
  for (let i = 0; i < 3; i++) {
    assert.match(text, new RegExp('href="#chapter-panel-' + i + '"'), "目录必须指向第 " + (i + 1) + " 章面板");
  }
  pass("章节目录与正文面板使用独立 ID，一一对应");

  // 每章图片互不覆盖
  const p0 = text.slice(text.indexOf('id="chapter-panel-0"'), text.indexOf('id="chapter-panel-1"'));
  const p1 = text.slice(text.indexOf('id="chapter-panel-1"'), text.indexOf('id="chapter-panel-2"'));
  const p2 = text.slice(text.indexOf('id="chapter-panel-2"'));
  assert.match(p0, /\/media\/ch1\.png/);
  assert.doesNotMatch(p0, /ch2\.png|ch3\.png/);
  assert.match(p1, /\/media\/ch2\.png/);
  assert.doesNotMatch(p1, /ch1\.png|ch3\.png/);
  assert.match(p2, /\/media\/ch3\.png/);
  assert.doesNotMatch(p2, /ch1\.png|ch2\.png/);
  assert.match(p0, /第一章 认识/);
  assert.match(p1, /第二章 选品/);
  assert.match(p2, /第三章 投放/);
  pass("三章图片与标题各自独立，互不覆盖");

  // 统一章节切换脚本：滚动目标为正文面板，而非目录
  assert.match(text, /<button id="ch-prev"[^>]*disabled>/, "第一章必须禁用上一章");
  const nextBtn = text.match(/<button id="ch-next"[^>]*>/);
  assert.ok(nextBtn && !/disabled/.test(nextBtn[0]), "三章课程最后一章外的下一章应可用");
  assert.match(text, /scrollToPanel/, "必须使用统一的章节切换函数");
  assert.doesNotMatch(text, /scrollIntoView/, "不得再用 scrollIntoView 跳到目录锚点");
  assert.match(text, /aria-current="true"/, "目录当前选中项必须有 aria-current 标记");
  assert.match(text, /classList\.toggle\('is-current'/, "切换时必须同步目录与正文激活状态");
  pass("章节切换脚本指向正文面板且首章禁用上一章");

  // 单章节课程：下一章禁用
  const single = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "单章课程",
      slug: "single-chapter",
      content_type: "chapter",
      access_level: "member",
      status: "published",
      chapters: [{ title: "唯一章节", body: "正文", sort_order: 0 }],
    },
  });
  assert.equal(single.res.status, 200, single.text);
  const singlePage = await call("/member/app/courses/single-chapter", { cookie });
  assert.match(singlePage.text, /<button id="ch-next"[^>]*disabled>/, "最后一章必须禁用下一章");
  pass("单章节课程禁用上一章与下一章");

  // 公开详情页同样渲染章节面板（免费章节课程）
  const freeChapter = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "免费章节课程",
      slug: "free-chapter",
      content_type: "chapter",
      access_level: "free",
      status: "published",
      chapters: [
        { title: "免费第一章", body: "正文", sort_order: 0 },
        { title: "免费第二章", body: "正文", sort_order: 1 },
      ],
    },
  });
  assert.equal(freeChapter.res.status, 200, freeChapter.text);
  const freeChapterPage = await call("/library/free-chapter/");
  assert.equal(freeChapterPage.res.status, 200);
  assert.equal((freeChapterPage.text.match(/id="chapter-panel-\d"/g) || []).length, 2);
  assert.match(freeChapterPage.text, /id="chapter-nav"/);
  pass("公开免费章节课程详情页正常显示章节面板");
}

/* ---------------- 33. 第三轮：课程列表固定按分类分组与分类管理独立入口 ---------------- */
{
  const adminContent = await call("/admin/content/", { cookie: adminCookie });
  assert.equal(adminContent.res.status, 200);
  assert.doesNotMatch(adminContent.text, /href="\/admin\/categories\/"/, "第二阶段起课程管理页不得再出现分类管理入口链接");
  assert.doesNotMatch(adminContent.text, /content-group-toggle/, "不得再有“按分类分组”勾选框");
  assert.doesNotMatch(adminContent.text, /category-panel/, "不得再有分类管理展开面板");
  assert.doesNotMatch(adminContent.text, /按分类分组/, "不得再有分组切换文案");
  pass("课程管理页移除分组勾选框与分类展开面板");

  const categoriesPage = await call("/admin/categories/", { cookie: adminCookie });
  assert.equal(categoriesPage.res.status, 200, categoriesPage.text.slice(0, 200));
  assert.match(categoriesPage.text, /id="cat-create"/);
  assert.match(categoriesPage.text, /id="category-rows"/);
  assert.match(categoriesPage.text, /href="\/admin\/content\/"/);
  pass("课程分类管理为独立页面且 CRUD 入口可用");

  const anonCat = await call("/api/admin/categories");
  assert.equal(anonCat.res.status, 401);
  const anonCatPage = await call("/admin/categories/");
  assert.equal(anonCatPage.res.status, 302);
  pass("未登录无法访问分类管理页面与接口");

  // 新增 -> 修改 -> 删除（无关联课程）
  const cat = await call("/api/admin/categories", {
    method: "POST",
    cookie: adminCookie,
    body: { name: "测试分类", slug: "round3-cat", type: "course", sort_order: 88, status: "active" },
  });
  assert.equal(cat.res.status, 200, cat.text);
  const catId = cat.data.item.id;
  let catList = await call("/api/admin/categories", { cookie: adminCookie });
  assert.ok(catList.data.items.some((c) => c.slug === "round3-cat"), "新增分类必须出现在列表");

  const upd = await call("/api/admin/categories/" + catId, {
    method: "POST",
    cookie: adminCookie,
    body: { name: "测试分类改名", slug: "round3-cat", type: "course", sort_order: 77, status: "active" },
  });
  assert.equal(upd.res.status, 200, upd.text);
  catList = await call("/api/admin/categories", { cookie: adminCookie });
  const updated = catList.data.items.find((c) => c.slug === "round3-cat");
  assert.equal(updated.name, "测试分类改名");
  assert.equal(updated.sort_order, 77, "分类排序必须可调整");

  const delCat = await call("/api/admin/categories/" + catId, { method: "DELETE", cookie: adminCookie });
  assert.equal(delCat.res.status, 200, delCat.text);
  catList = await call("/api/admin/categories", { cookie: adminCookie });
  assert.ok(!catList.data.items.some((c) => c.slug === "round3-cat"), "无关联课程的分类可直接删除");
  pass("分类管理：新增、修改、调整排序、删除无关联分类均可用");

  // 有关联课程：先拦截，再迁移到未分类后删除
  const cat2 = await call("/api/admin/categories", {
    method: "POST",
    cookie: adminCookie,
    body: { name: "待迁移分类", slug: "round3-cat-migrate", type: "course", sort_order: 66, status: "active" },
  });
  assert.equal(cat2.res.status, 200, cat2.text);
  const cat2Id = cat2.data.item.id;

  const courseInCat = await call("/api/admin/contents", {
    method: "POST",
    cookie: adminCookie,
    body: {
      title: "分类迁移课程",
      slug: "round3-migrate-course",
      category_id: cat2Id,
      access_level: "free",
      status: "published",
      body: "正文",
    },
  });
  assert.equal(courseInCat.res.status, 200, courseInCat.text);

  const blocked = await call("/api/admin/categories/" + cat2Id, { method: "DELETE", cookie: adminCookie });
  assert.equal(blocked.res.status, 409);
  assert.equal(blocked.data.error, "category_in_use");

  const migrated = await call("/api/admin/categories/" + cat2Id + "/migrate", {
    method: "POST",
    cookie: adminCookie,
    body: { target_category_id: null },
  });
  assert.equal(migrated.res.status, 200, migrated.text);
  const courseRow = db.prepare("SELECT category_id, status FROM contents WHERE slug = 'round3-migrate-course'").get();
  assert.equal(courseRow.category_id, null, "迁移后课程应归入未分类");
  assert.equal(courseRow.status, "published", "迁移不得影响课程状态");
  catList = await call("/api/admin/categories", { cookie: adminCookie });
  assert.ok(!catList.data.items.some((c) => c.slug === "round3-cat-migrate"), "迁移后分类应被删除");
  pass("有关联课程的分类先拦截删除，迁移后课程保留且可删除");

  // 课程列表接口返回分类信息，前端据此固定分组
  const items = (await call("/api/admin/contents", { cookie: adminCookie })).data.items;
  const withCat = items.find((c) => c.category_id && c.category_name);
  assert.ok(withCat, "课程列表必须返回所属分类名称");
  assert.ok("category_sort_order" in withCat, "课程列表必须返回分类排序字段");
  assert.ok(items.some((c) => !c.category_id), "未分类课程应存在并单独分组");

  const adminJs = readFileSync(join(root, "public", "assets", "js", "admin.js"), "utf8");
  assert.ok(!/content-group-toggle/.test(adminJs), "admin.js 不得再读取分组开关");
  assert.match(adminJs, /a-group-row/, "课程列表必须渲染分类分组行");
  assert.match(adminJs, /门课程/, "每个分类必须显示该分类课程数量");
  assert.match(adminJs, /category_sort_order/, "分组排序必须遵循后台 sort_order");
  pass("课程列表固定按分类分组并显示分类名称与课程数量");
}

/* ---------------- 34. 第二阶段：后台精简为 7 个可见板块 ---------------- */
{
  const adminHome = await call("/admin/", { cookie: adminCookie });
  assert.equal(adminHome.res.status, 200);
  const navMatch = adminHome.text.match(/<nav class="a-nav"[^>]*>([\s\S]*?)<\/nav>/);
  assert.ok(navMatch, "后台页面必须包含导航");
  const navHtml = navMatch[1];
  const navLinks = navHtml.match(/<a class="/g) || [];
  assert.equal(navLinks.length, 7, "后台导航必须恰好 7 个板块");
  for (const label of ["概览", "会员管理", "课程管理", "工具管理", "案例管理", "网站设置", "操作日志"]) {
    assert.ok(navHtml.includes(label), `导航必须包含「${label}」`);
  }
  assert.ok(!navHtml.includes("/admin/categories/"), "导航不得包含课程分类入口");
  assert.ok(!navHtml.includes("/admin/resources/"), "导航不得包含资料管理入口");
  assert.ok(!adminHome.text.includes('href="/admin/resources/"'), "概览页不得保留资料管理快捷入口");
  pass("后台导航精简为 7 个板块：无课程分类与资料管理入口");

  // 隐藏入口但保留页面路由与 API，直接访问仍可用（保护分类数据与资料下载链路）
  for (const p of ["/admin/categories/", "/admin/resources/"]) {
    const hiddenPage = await call(p, { cookie: adminCookie });
    assert.equal(hiddenPage.res.status, 200, `${p} 隐藏后必须仍可直接访问`);
  }
  const catApi = await call("/api/admin/categories", { cookie: adminCookie });
  assert.equal(catApi.res.status, 200, "分类接口必须保留");
  const resApi = await call("/api/admin/resources", { cookie: adminCookie });
  assert.equal(resApi.res.status, 200, "资料接口必须保留");
  pass("课程分类与资料管理的页面路由及 API 全部保留可用");

  // 课程表单包含前台可见性提示，且前端联动逻辑存在
  const contentPage = await call("/admin/content/", { cookie: adminCookie });
  assert.match(contentPage.text, /id="content-visibility-hint"/, "课程表单必须包含前台可见性提示元素");
  const adminJsPhase2 = readFileSync(join(root, "public", "assets", "js", "admin.js"), "utf8");
  assert.match(adminJsPhase2, /syncContentVisibilityHint/, "admin.js 必须包含可见性提示联动逻辑");
  pass("课程表单提供免费公开/VIP 权限的前台可见性提示");
}

await Promise.all(pending);

console.log(`\n共 ${results.length} 项服务端测试全部通过。`);

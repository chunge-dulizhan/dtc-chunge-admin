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
      return new Response("<html>static</html>", { headers: { "Content-Type": "text/html" } });
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
    assert.match(r.data.member.member_code, /^CH\d{3}$/);
    assert.match(r.data.access_code, /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    created.push(r.data);
  }
  assert.deepEqual(created.map((m) => m.member.member_code), ["CH001", "CH002", "CH003"]);
  pass("自动生成 CH001/CH002/CH003 会员编号");

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
  assert.equal(otherSession.data.member.member_code, "CH002");
  pass("不同会员登录后身份各自独立、不会混用");
}

/* ---------------- 5. 刷新页面仍保持登录 ---------------- */
{
  const r = await call("/api/member/session", { cookie: memberCookie });
  assert.equal(r.res.status, 200);
  assert.equal(r.data.member.member_code, "CH001");
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
  assert.match(text, /CH001/);
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
  assert.match(home.text, /CH001|CH00/);
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

await Promise.all(pending);

console.log(`\n共 ${results.length} 项服务端测试全部通过。`);

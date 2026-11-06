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
  ASSETS: { fetch: async () => new Response("<html>static</html>", { headers: { "Content-Type": "text/html" } }) },
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
}

await Promise.all(pending);

console.log(`\n共 ${results.length} 项服务端测试全部通过。`);

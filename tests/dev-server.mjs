/**
 * 本地开发预览服务器（仅用于本地调试，不参与 Cloudflare 部署）
 * 运行：node tests/dev-server.mjs   然后打开 http://127.0.0.1:8788
 *
 * 作用：用 node:sqlite 模拟 D1、用本机文件系统模拟 Pages 静态资源，
 * 这样在没有 Cloudflare 账号时也能完整走一遍真实登录、权限与会话流程。
 */

import http from "node:http";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, existsSync, statSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, normalize, extname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const publicDir = join(root, "public");
const dbFile = join(process.env.TEMP || ".", "chunge-dev.sqlite");
const port = Number(process.env.PORT || 8788);

const db = new DatabaseSync(dbFile);
db.exec(readFileSync(join(root, "db", "schema.sql"), "utf8"));

// 演示数据（可重复执行，不会重复插入）
const seedFile = join(root, "db", "seed.sql");
if (existsSync(seedFile)) db.exec(readFileSync(seedFile, "utf8"));

function makeD1(handle) {
  return {
    prepare(sql) {
      const attach = (args) => ({
        bind: (...more) => attach(more),
        first: async () => {
          const row = handle.prepare(sql).get(...args);
          return row === undefined ? null : row;
        },
        all: async () => ({ results: handle.prepare(sql).all(...args), success: true, meta: {} }),
        run: async () => {
          const r = handle.prepare(sql).run(...args);
          return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid) } };
        },
      });
      return attach([]);
    },
  };
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".pdf": "application/pdf",
};

function serveAsset(request) {
  const url = new URL(request.url);
  let pathname = decodeURIComponent(url.pathname);
  if (pathname.endsWith("/")) pathname += "index.html";
  const safe = normalize(pathname).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(publicDir, safe);
  if (!existsSync(filePath) || !statSync(filePath).isFile()) {
    return new Promise((resolve) => resolve(new Response("Not Found", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } })));
  }
  const body = readFileSync(filePath);
  return Promise.resolve(
    new Response(body, { status: 200, headers: { "Content-Type": MIME[extname(filePath).toLowerCase()] || "application/octet-stream" } })
  );
}

// 本地 R2 模拟：把对象写到临时目录，用于联调上传与私有下载
const r2Dir = join(process.env.TEMP || ".", "chunge-r2");

const mockR2 = {
  async put(key, value) {
    const filePath = join(r2Dir, key);
    mkdirSync(dirname(filePath), { recursive: true });
    const buf = Buffer.from(await new Response(value).arrayBuffer());
    writeFileSync(filePath, buf);
    return { key, size: buf.length };
  },
  async get(key) {
    const filePath = join(r2Dir, key);
    if (!existsSync(filePath)) return null;
    const buf = readFileSync(filePath);
    return { body: new Response(buf).body, size: buf.length };
  },
};

const env = {
  DB: makeD1(db),
  ASSETS: { fetch: serveAsset },
  R2: mockR2,
  CODE_PEPPER: process.env.CODE_PEPPER || "local-dev-pepper-change-me",
  ADMIN_SETUP_TOKEN: process.env.ADMIN_SETUP_TOKEN || "",
};

const worker = (await import(pathToFileURL(join(publicDir, "_worker.js")).href)).default;

function toRequest(req) {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    headers.set(key, Array.isArray(value) ? value.join(", ") : value);
  }
  headers.set("CF-Connecting-IP", "127.0.0.1");
  const method = req.method || "GET";
  if (method === "GET" || method === "HEAD") return new Request(url, { method, headers });

  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      resolve(new Request(url, { method, headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
  });
}

http
  .createServer(async (req, res) => {
    try {
      const request = await toRequest(req);
      const ctx = { waitUntil: () => {} };
      const response = await worker.fetch(request, env, ctx);
      res.statusCode = response.status;
      const setCookies = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [];
      for (const [key, value] of response.headers.entries()) {
        if (key.toLowerCase() === "set-cookie") continue;
        res.setHeader(key, value);
      }
      if (setCookies.length) res.setHeader("Set-Cookie", setCookies);
      else {
        const single = response.headers.get("set-cookie");
        if (single) res.setHeader("Set-Cookie", single);
      }
      const buf = Buffer.from(await response.arrayBuffer());
      res.end(buf);
    } catch (err) {
      console.error(err);
      res.statusCode = 500;
      res.end("Internal Error");
    }
  })
  .listen(port, () => {
    console.log(`dev server: http://127.0.0.1:${port}  (db: ${dbFile})`);
  });

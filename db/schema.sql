-- 独立站春哥 · 会员中心数据库结构（Cloudflare D1 / SQLite）
-- 使用方式：wrangler d1 execute chunge-db --file=db/schema.sql --remote

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------
-- 会员
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS members (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  member_code  TEXT    NOT NULL UNIQUE,              -- 会员编号，如 CH001
  name         TEXT    NOT NULL,
  contact      TEXT,                                  -- 联系方式（选填）
  wechat_note  TEXT,                                  -- 微信备注（选填）
  source       TEXT,                                  -- 会员来源（选填）
  notes        TEXT,                                  -- 管理员备注（选填）
  status       TEXT    NOT NULL DEFAULT 'active',     -- active | paused | disabled
  member_type  TEXT    NOT NULL DEFAULT 'lifetime',   -- 永久会员
  created_at   TEXT    NOT NULL,
  updated_at   TEXT    NOT NULL,
  last_login_at TEXT,
  deleted_at   TEXT                                   -- 软删除时间
);
CREATE INDEX IF NOT EXISTS idx_members_status ON members(status);
CREATE INDEX IF NOT EXISTS idx_members_deleted ON members(deleted_at);

-- ------------------------------------------------------------
-- 访问码（只保存哈希，不保存明文）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_codes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id   INTEGER NOT NULL REFERENCES members(id),
  code_hash   TEXT    NOT NULL UNIQUE,               -- SHA-256(pepper + 规范化访问码)
  code_hint   TEXT,                                  -- 仅用于后台辨识，如 VG8K-••••-••••
  status      TEXT    NOT NULL DEFAULT 'active',     -- active | revoked
  created_at  TEXT    NOT NULL,
  revoked_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_codes_member ON access_codes(member_id);

-- ------------------------------------------------------------
-- 会员登录会话
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id   INTEGER NOT NULL REFERENCES members(id),
  token_hash  TEXT    NOT NULL UNIQUE,               -- 会话令牌的 SHA-256
  expires_at  TEXT    NOT NULL,
  created_at  TEXT    NOT NULL,
  last_seen_at TEXT   NOT NULL,
  ip_hash     TEXT,
  user_agent  TEXT,
  revoked_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_member ON sessions(member_id);

-- ------------------------------------------------------------
-- 管理员
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admins (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,                    -- PBKDF2-SHA256 迭代 210000
  status        TEXT    NOT NULL DEFAULT 'active',   -- active | disabled
  created_at    TEXT    NOT NULL,
  last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id    INTEGER NOT NULL REFERENCES admins(id),
  token_hash  TEXT    NOT NULL UNIQUE,
  expires_at  TEXT    NOT NULL,
  created_at  TEXT    NOT NULL,
  last_seen_at TEXT    NOT NULL,
  ip_hash     TEXT,
  revoked_at  TEXT
);

-- ------------------------------------------------------------
-- 内容分类
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS content_categories (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT    NOT NULL,
  slug        TEXT    NOT NULL UNIQUE,
  type        TEXT    NOT NULL DEFAULT 'course',      -- course | resource | tool
  description TEXT,
  sort_order  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT    NOT NULL
);

-- ------------------------------------------------------------
-- 课程 / 图文内容
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contents (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  title        TEXT    NOT NULL,
  slug         TEXT    NOT NULL,
  category_id  INTEGER REFERENCES content_categories(id),
  content_type TEXT    NOT NULL DEFAULT 'article',    -- article | chapter
  excerpt      TEXT,
  body         TEXT    NOT NULL DEFAULT '',           -- Markdown
  access_level TEXT    NOT NULL DEFAULT 'member',     -- free | member
  status       TEXT    NOT NULL DEFAULT 'draft',      -- draft | published | archived
  sort_order   INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT    NOT NULL,
  updated_at   TEXT    NOT NULL,
  published_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_contents_slug ON contents(slug);
CREATE INDEX IF NOT EXISTS idx_contents_category ON contents(category_id);
CREATE INDEX IF NOT EXISTS idx_contents_status ON contents(status);

-- ------------------------------------------------------------
-- 附件 / 资料（文件本体在 R2 私有存储）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS resources (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  title        TEXT    NOT NULL,
  description  TEXT,
  file_key     TEXT    NOT NULL,                      -- R2 object key
  file_name    TEXT    NOT NULL,
  file_type    TEXT,                                  -- pdf | xlsx | docx | image | zip
  file_size    INTEGER,
  category_id  INTEGER REFERENCES content_categories(id),
  access_level TEXT    NOT NULL DEFAULT 'member',     -- free | member
  status       TEXT    NOT NULL DEFAULT 'draft',      -- draft | published | archived
  version      TEXT,
  sort_order   INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT    NOT NULL,
  updated_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_resources_status ON resources(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_resources_file_key ON resources(file_key);

-- ------------------------------------------------------------
-- 网页工具
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tools (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT    NOT NULL,
  slug         TEXT    NOT NULL UNIQUE,
  intro        TEXT,
  usage_text   TEXT,
  entry_url    TEXT    NOT NULL,                      -- 站内受保护路径，如 /tools/pricing/
  access_level TEXT    NOT NULL DEFAULT 'member',     -- free | member
  status       TEXT    NOT NULL DEFAULT 'draft',      -- draft | published | archived
  sort_order   INTEGER NOT NULL DEFAULT 0,
  updated_at   TEXT    NOT NULL
);

-- ------------------------------------------------------------
-- 网站基础设置（键值存储，未写入时使用代码内默认值）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- ------------------------------------------------------------
-- 课程附件（文件本体在 R2 私有存储，每篇课程一个附件）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS content_files (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  content_id INTEGER NOT NULL UNIQUE REFERENCES contents(id),
  file_key   TEXT    NOT NULL,                      -- R2 object key
  file_name  TEXT    NOT NULL,
  file_type  TEXT,
  file_size  INTEGER,
  created_at TEXT    NOT NULL,
  updated_at TEXT    NOT NULL
);

-- ------------------------------------------------------------
-- 安全操作日志
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT    NOT NULL,                        -- member | admin | system
  actor_id   INTEGER,
  action     TEXT    NOT NULL,
  detail     TEXT,
  ip_hash    TEXT,
  created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

-- ------------------------------------------------------------
-- 登录限流
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_attempts (
  attempt_key   TEXT PRIMARY KEY,                     -- 如 ip:<hash> 或 code:<hash前缀>
  failures      INTEGER NOT NULL DEFAULT 0,
  window_start  TEXT    NOT NULL,
  locked_until  TEXT
);

-- ------------------------------------------------------------
-- 学员案例（首页与 /cases/ 共用这一套数据）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cases (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  title         TEXT    NOT NULL,
  slug          TEXT    NOT NULL UNIQUE,
  cover_image   TEXT,                                  -- /media/ 开头的站内图片地址
  summary       TEXT,
  body          TEXT    NOT NULL DEFAULT '',           -- Markdown
  category      TEXT,
  external_link TEXT,                                  -- 选填外部链接
  status        TEXT    NOT NULL DEFAULT 'draft',      -- draft | published | archived | deleted
  sort_order    INTEGER NOT NULL DEFAULT 0,
  show_on_home  INTEGER NOT NULL DEFAULT 0,            -- 1 = 在首页学员案例板块展示
  created_at    TEXT    NOT NULL,
  updated_at    TEXT    NOT NULL,
  published_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);

-- ------------------------------------------------------------
-- 初始内容分类（10 个课程模块 + 资料分类）
-- ------------------------------------------------------------
INSERT OR IGNORE INTO content_categories (name, slug, type, description, sort_order, created_at) VALUES
  ('独立站创业入门', 'start', 'course', '从 0 认识独立站与变现逻辑', 1, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('市场与产品验证', 'validate', 'course', '选品、测品与需求验证', 2, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('产品定位与品牌', 'brand', 'course', '定位、视觉与信任体系', 3, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('Shopify 网站搭建', 'build', 'course', '建站、主题与转化优化', 4, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('数据追踪与分析', 'tracking', 'course', '像素、事件与数据看板', 5, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('Facebook / Instagram 广告', 'ads', 'course', '投放结构、素材与优化', 6, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('社媒内容营销', 'social', 'course', '自然流量内容与账号运营', 7, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('SEO 与自然流量', 'seo', 'course', '站内 SEO 与内容获客', 8, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('物流、支付与客服', 'ops', 'course', '履约、收款与售后', 9, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('复盘与持续增长', 'growth', 'course', '数据复盘与规模化', 10, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('实操 SOP 与模板', 'sop', 'resource', '可直接照着做的流程与表格', 20, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  ('提示词与 AI 工具包', 'prompt', 'resource', 'AI 实操提示词合集', 21, strftime('%Y-%m-%dT%H:%M:%fZ','now'));

-- 第二阶段增量迁移（仅对已有生产数据库执行；新建库由 schema.sql 直接建表）
-- 幂等说明：SQLite/D1 不支持 ADD COLUMN IF NOT EXISTS，本脚本应只执行一次。

-- contents 表新增字段
ALTER TABLE contents ADD COLUMN nav_category TEXT;
ALTER TABLE contents ADD COLUMN content_format TEXT NOT NULL DEFAULT 'markdown';
ALTER TABLE contents ADD COLUMN cover_image TEXT;
CREATE INDEX IF NOT EXISTS idx_contents_nav_category ON contents(nav_category);

-- 内容分类新增启用状态
ALTER TABLE content_categories ADD COLUMN status TEXT NOT NULL DEFAULT 'active';

-- 案例正文格式
ALTER TABLE cases ADD COLUMN content_format TEXT NOT NULL DEFAULT 'markdown';

-- 章节课章节表
CREATE TABLE IF NOT EXISTS content_chapters (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  content_id INTEGER NOT NULL REFERENCES contents(id) ON DELETE CASCADE,
  title      TEXT    NOT NULL,
  body       TEXT    NOT NULL DEFAULT '',
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_content_chapters_content ON content_chapters(content_id, sort_order);

-- ------------------------------------------------------------
-- 003 会员编码释放（三期修复）
-- 目标：软删除会员时释放其会员编码，使新会员可复用最小可用序号；
--       历史编号归档到 archived_member_code，不删除、不改写历史记录。
-- 说明：只做增量 ALTER / 数据回填，不重建表、不批量修改有效会员编码。
-- ------------------------------------------------------------

-- 1) 新增归档列（保留删除前的原始会员编号）
ALTER TABLE members ADD COLUMN archived_member_code TEXT;

-- 2) 回填历史已删除会员：把原编号归档，并把 member_code 改为不占用序号的墓碑值
--    仅处理仍是 CG/CH 正常格式的历史删除记录，避免重复执行造成二次改写
UPDATE members
   SET archived_member_code = member_code,
       member_code = 'DEL-' || member_code || '-' || id,
       updated_at = updated_at
 WHERE deleted_at IS NOT NULL
   AND archived_member_code IS NULL
   AND member_code NOT LIKE 'DEL-%';

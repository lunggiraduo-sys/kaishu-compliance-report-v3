-- ════════════════════════════════════════════════════════════
-- 凯叔讲故事廉洁举报平台 - Supabase 数据库初始化脚本
-- 在 Supabase Dashboard → SQL Editor 中运行此脚本
-- ════════════════════════════════════════════════════════════

-- 1. 应用数据表（存储整个 JSON 数据库为单行）
CREATE TABLE IF NOT EXISTS app_data (
  id TEXT PRIMARY KEY DEFAULT 'main',
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. 附件表（存储文件 base64 数据）
CREATE TABLE IF NOT EXISTS app_attachments (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  original_name TEXT,
  mime TEXT,
  size INT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. 启用行级安全（RLS）
ALTER TABLE app_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_attachments ENABLE ROW LEVEL SECURITY;

-- 4. 删除旧策略（如果存在）
DROP POLICY IF EXISTS "allow_all_app_data" ON app_data;
DROP POLICY IF EXISTS "allow_all_attachments" ON app_attachments;

-- 5. 创建策略：允许后端 anon key 完全访问
-- （后端自行处理认证，数据库层面开放即可）
CREATE POLICY "allow_all_app_data" ON app_data
  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "allow_all_attachments" ON app_attachments
  FOR ALL USING (true) WITH CHECK (true);

-- 完成
SELECT '数据库初始化完成' AS result;

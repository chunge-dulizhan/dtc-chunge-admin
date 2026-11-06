# 独立站春哥 · 公开知识库与付费会员中心

面向「独立站春哥」的公开知识库 + 付费会员中心 + 管理员后台。访客无需注册即可浏览免费内容；付费会员凭管理员发放的独立访问码进入会员中心，永久访问课程、网页工具与实操资料。

技术栈固定为 Cloudflare Pages（Advanced Mode + `_worker.js`）、Cloudflare Workers 运行时、D1、R2。不使用 Supabase、不接入在线支付、不开放注册、不依赖 VPS。

---

## 一、项目结构

```
.
├─ public/                       # Cloudflare Pages 静态资源 + Worker 入口
│  ├─ _worker.js                 # 全站入口：路由、会话、权限、服务端渲染、工具计算
│  ├─ index.html                 # 公开首页
│  ├─ library/                   # 免费知识库入口页
│  ├─ member/index.html          # 会员访问码登录页
│  ├─ tools/                     # 5 个会员工具页（静态页面，由 Worker 鉴权后放行）
│  │  ├─ pricing/index.html
│  │  ├─ ads/index.html
│  │  ├─ profit/index.html
│  │  ├─ calendar/index.html
│  │  └─ ai-sourcing/index.html
│  └─ assets/css|js              # 页面样式与交互脚本
├─ db/
│  ├─ schema.sql                 # D1 建表语句
│  └─ seed.sql                   # 可选演示数据（10 篇课程、5 份资料、5 个工具）
├─ tests/
│  ├─ worker.test.mjs            # 84 项服务端权限与功能测试
│  └─ dev-server.mjs             # 本地开发服务器（模拟 D1 与 R2）
├─ wrangler.toml                 # D1 / R2 绑定配置
└─ README.md
```

### 路由一览

| 路径 | 说明 | 权限 |
| --- | --- | --- |
| `/`、`/library/*` | 公开首页与免费内容 | 所有人 |
| `/member/` | 访问码登录页 | 所有人 |
| `/member/app/*` | 会员中心、课程、工具库、资料库 | 正常会员 |
| `/admin/*` | 管理后台页面 | 管理员 |
| `/tools/<slug>/` | 工具页面 | 按工具权限，服务端校验 |
| `/media/*` | 课程配图等公开图片（来自 R2 `media/`） | 所有人（只允许图片文件名） |
| `/courses/<slug>/attachment` | 课程附件下载 | 免费课程公开，会员课程校验会话 |
| `/api/tools/<slug>/calc` | 工具计算接口 | 每次请求校验会员 |
| `/api/member/*` | 登录、会话、退出 | 按接口 |
| `/api/admin/*` | 后台接口 | 管理员 Cookie |

> 会员中心与后台页面由 Worker 服务端渲染；所有权限判断都在服务端执行，前端隐藏按钮不作为安全边界。

---

## 二、本地运行与测试

要求 Node.js 22.5 以上（使用 `node:sqlite` 模拟 D1）。

```powershell
# 1. 跑服务端测试（无需 Cloudflare 账号）
node tests/worker.test.mjs

# 2. 本地预览（默认 http://127.0.0.1:8788）
node tests/dev-server.mjs
```

本地数据库位于 `%TEMP%\chunge-dev.sqlite`，启动时自动执行 `db/schema.sql` 与 `db/seed.sql`；删除该文件即可重置。本地 R2 文件保存在 `%TEMP%\chunge-r2`。

本地首次打开 `http://127.0.0.1:8788/admin/` 会进入管理员初始化页，创建第一个管理员后入口自动关闭。

---

## 三、部署到 Cloudflare（从零开始）

### 1. 准备账号与工具

- Cloudflare 账号（免费额度足够 200 名会员规模）。
- GitHub 账号（用于存放源码与 Pages 自动部署）。
- 本机安装 Node.js 22 以上。

### 2. 创建 D1 数据库

方式 A（命令行，推荐）：

```powershell
npx wrangler login
npx wrangler d1 create chunge-db
```

命令会输出 `database_id`。把它填入 `wrangler.toml`：

```toml
[[d1_databases]]
binding = "DB"
database_name = "chunge-db"
database_id = "这里替换成你的 database_id"
```

方式 B（控制台）：Workers & Pages → D1 → Create database，名称填 `chunge-db`，创建后复制 Database ID。

### 3. 初始化表结构

```powershell
# 正式库
npx wrangler d1 execute chunge-db --remote --file=db/schema.sql

# 可选：导入演示课程 / 资料 / 工具（正式运营时可以不执行）
npx wrangler d1 execute chunge-db --remote --file=db/seed.sql
```

### 4. 创建 R2 私有存储桶

```powershell
npx wrangler r2 bucket create chunge-private-files
```

- 不要为这个桶开启公开访问或绑定公开域名。
- 付费文件只通过 Worker 校验会员后下载。

### 5. 创建 Pages 项目

方式 A（连接 GitHub，推荐长期使用）：

1. Cloudflare 控制台 → Workers & Pages → Create → Pages → Connect to Git。
2. 选择仓库 `chunge-member-center`。
3. Framework preset 选 None，Build command 留空，Build output directory 填 `public`。
4. 保存并部署。

方式 B（本机直接上传）：

```powershell
npx wrangler pages deploy public --project-name=chunge-member-center
```

> 关于 Workers：本项目不单独创建一个 Worker 服务。`public/_worker.js` 会随 Pages 一起发布，运行在 Cloudflare Workers 运行时（Pages Functions / Advanced Mode）。这是第一版最省成本、最少维护的形态；如果未来需要独立 Worker、定时任务或更复杂的后端，可以把 `_worker.js` 拆出来单独部署，但当前不需要，也不建议增加这层复杂度。

### 6. 配置绑定（D1 / R2）

在 Pages 项目 → Settings → Bindings（或 Functions → Bindings）中添加：

| 类型 | 变量名 | 目标 |
| --- | --- | --- |
| D1 database | `DB` | `chunge-db` |
| R2 bucket | `R2` | `chunge-private-files` |

变量名必须与代码一致（`DB`、`R2`），大小写敏感。配置完成后重新部署一次。

### 7. 配置环境变量与密钥

在 Pages 项目 → Settings → Environment variables（Production）中添加：

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `CODE_PEPPER` | 是 | 访问码哈希用的服务端密钥，建议 32 字节以上随机字符串 |
| `ADMIN_SETUP_TOKEN` | 否 | 一次性管理员初始化令牌；设置后初始化时必须填写 |

生成随机密钥：

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

也可以用命令行写入：

```powershell
npx wrangler pages secret put CODE_PEPPER --project-name=chunge-member-center
```

> `CODE_PEPPER` 一旦更换，已发放的访问码将全部失效，只能逐个重置。请妥善保存并备份。

### 8. 创建第一个管理员

1. 打开 `https://你的域名/admin/`。
2. 系统检测到没有任何管理员时，会显示「初始化管理员账号」。
3. 账号：3-20 位字母、数字或下划线；密码至少 10 位。
4. 若配置了 `ADMIN_SETUP_TOKEN`，需同时填写令牌。
5. 创建成功后初始化入口自动关闭，后续只能通过登录页进入。

### 9. 绑定域名

1. Pages 项目 → Custom domains → Set up a custom domain。
2. 输入已购买的域名（如 `chunge.com`）。
3. 按提示在域名 DNS 添加 CNAME 记录；Cloudflare 托管的域名通常一键完成。
4. 等待状态变为 Active，再用 HTTPS 访问。

---

## 四、日常运营操作

### 添加会员与发放访问码

1. 后台 → 会员管理 → 添加会员。
2. 填写姓名/昵称，联系方式、来源、备注均可选。
3. 点击生成后，系统自动分配会员编号（CH001、CH002……）与 12 位访问码。
4. **访问码明文只显示一次**，请立即复制发给会员；数据库只保存哈希，之后无法再次查看。
5. 会员丢失访问码时，在会员列表点「重置访问码」，旧码立即失效。

会员状态说明：

- 正常：可登录、可访问会员内容。
- 已暂停 / 已停用：服务端立即吊销其全部会话，无法继续访问。
- 删除：软删除，会员与访问码立即失效，列表不再展示。

### 管理课程

后台 → 课程管理 → 新建课程：

- 填写标题、访问路径（slug，如 `meta-ads-cold-start`）。
- 选择分类、权限（免费公开 / 会员专属）、状态（草稿 / 发布 / 下架）。
- 正文使用 Markdown：标题、段落、列表、引用、表格、代码块、图片、链接。
- 配图直接在弹窗的「正文配图」区上传：选择图片 → 点击「上传并插入」，系统把文件存入 R2 的 `media/` 目录，并自动在正文光标处插入 `![图片说明](/media/xxx.png)`。
- 配图属于公开资源（不含付费信息），`/media/` 无需登录即可访问，便于搜索引擎与页面缓存；付费文件仍走私有下载，不会出现在 `/media/`。
- 也可以手工把图片放到 `public/assets/img/`，再用 Markdown 引用。
- 「课程附件」区可上传 PDF / Excel / Word / 压缩包等文件（≤200 MB），存入 R2 私有目录 `courses/<课程ID>/`；先保存课程，再重新打开编辑弹窗上传。
- 附件下载地址为 `/courses/<slug>/attachment`：免费课程访客可直接下载，会员课程必须登录且会员状态正常。
- 发布后会员立即可见；改为下架后会员立即无法访问，附件同时失效。

### 网站基础设置

后台 → 网站设置，可修改：品牌名称、网站定位、网站简介、带教咨询微信、页脚版权与联系方式。

- 设置保存在 D1 `settings` 表，未填写的字段自动使用代码内默认文案。
- 保存后约 1 分钟对全站生效（Worker 实例内有 60 秒缓存），静态页与会员中心文案都会同步替换。
- 留空并保存即可恢复默认文案；该页面只改文案，不影响权限、路由与数据结构。

### 上传付费资料

1. 后台 → 资料管理 → 添加资料，先保存元数据（此时可填占位 R2 路径）。
2. 重新打开该资料的「编辑」弹窗，选择文件，点击「上传并保存」。
3. 上传成功后自动回填 R2 路径、文件名、类型与大小，并保存到 D1。
4. 状态改为「发布」后，会员资料库出现下载入口。
5. 下载时 Worker 会校验会员状态，再从 R2 读取文件，不暴露公开地址。

### 管理网页工具

后台 → 工具管理：

- 可编辑工具名称、介绍、使用说明、入口、权限、排序与状态。
- 入口必须是站内受保护路径，例如 `/tools/pricing/`；不允许填外部地址。
- 下架工具后，工具页与计算接口同时失效。
- 新增带服务端计算的工具，需要开发者在 `public/tools/<slug>/index.html` 增加页面，并在 `public/_worker.js` 增加对应计算函数（参考现有 5 个工具）。

### 旧 GitHub Pages 工具的迁移要求

不能仅用 iframe 嵌入旧工具就当作「会员专属」：

1. 把工具页面迁到 `public/tools/<slug>/`。
2. 把核心计算逻辑迁到 `_worker.js` 的 `/api/tools/<slug>/calc`，每次请求校验会员。
3. 关闭旧 GitHub Pages 入口，或明确标注为「未受保护」，不放入会员工具库。

只有 Worker 先校验、再返回页面与结果，才算真正受保护。

---

## 五、数据库备份与恢复

### 备份

```powershell
# 导出结构与数据
npx wrangler d1 export chunge-db --remote --output=backup-d1-20261106.sql
```

建议每月至少备份一次，并把文件保存到本地或私有云盘。`backup-*.sql` 已在 `.gitignore` 中排除，不要提交到公开仓库。

### 恢复

安全做法是恢复到新库：

```powershell
npx wrangler d1 create chunge-db-restore
npx wrangler d1 execute chunge-db-restore --remote --file=backup-d1-20261106.sql
```

然后把 Pages 的 `DB` 绑定切到新库并重新部署。确认数据无误后再删除旧库。

### R2 文件备份

D1 只保存文件元数据，文件本体在 R2。请定期使用 Cloudflare 控制台下载关键文件，或用 rclone（S3 兼容接口）同步整个 `chunge-private-files` 桶到本地/其他存储。

---

## 六、安全设计说明

- 访问码：12 位随机字符（去掉易混字符），使用 `SHA-256("chunge:" + CODE_PEPPER + ":" + 规范化码)` 保存；数据库不含明文。
- 会话：会员 Cookie 为 `HttpOnly + Secure + SameSite=Lax`，有效期 30 天；每次请求回查 D1，会员暂停/停用/删除立即失效。
- 管理员：独立 Cookie 会话（12 小时），密码 PBKDF2 哈希保存；管理员接口每次校验；会员 Cookie 无法调用。
- 限流：同一 IP + 访问码连续输错 5 次后锁定 10 分钟。
- 权限：免费/会员/草稿/上下架全部服务端判断；未登录访问会员内容 302 到访问码页。
- 文件：R2 桶保持私有；下载由 Worker 校验后返回，不提供公开直链。
- 工具：页面与计算接口双重校验；下架即失效。
- 错误提示：统一文案，不泄露访问码是否存在、数据库结构或服务器信息。

> 注意：把源码放到 GitHub 只是版本管理，公开仓库不等于权限保护。真正的访问控制由 Cloudflare Worker 与 D1 完成。建议仓库设为 Private，但不要把「仓库私有」当作会员内容保护手段。

---

## 七、验收对照

| 验收项 | 结果 |
| --- | --- |
| 未登录可浏览免费知识库 | 已通过（服务端测试） |
| 未登录不能查看会员课程 | 已通过 |
| 管理员可添加会员 | 已通过 |
| 每个会员获得独立访问码 | 已通过 |
| 不同会员访问码不能混用 | 已通过 |
| 正确访问码可登录 | 已通过 |
| 错误访问码不能登录且提示不泄露信息 | 已通过 |
| 刷新后登录状态保持 | 已通过 |
| 有效期内无需重复输入 | 已通过 |
| 退出登录后不能继续访问 | 已通过 |
| 暂停会员后立即失去访问 | 已通过 |
| 恢复会员后可重新登录 | 已通过 |
| 会员不能进入后台 | 已通过 |
| 普通用户不能调用管理员接口 | 已通过 |
| 付费附件不能公开直链下载 | 已通过（R2 私有 + Worker 下载） |
| 旧工具不能绕过会员验证 | 已通过（工具页与计算接口双重校验） |
| 前端无管理员密钥/数据库凭证 | 已通过（检索 public 目录无硬编码密钥） |
| 电脑与手机端正常 | 电脑端已浏览器实测；移动端样式按 390px 断点适配，上线前建议真机复查 |
| 数据库可导出备份 | 见「数据库备份与恢复」 |
| 出错提示不泄露内部信息 | 已通过（统一错误文案） |

服务端自动化测试共 84 项，全部通过：

```powershell
node tests/worker.test.mjs
```

---

## 八、提交到 GitHub

```powershell
git init
git add .
git commit -m "feat: 独立站春哥知识库与付费会员中心"
git branch -M main
git remote add origin https://github.com/你的账号/chunge-member-center.git
git push -u origin main
```

推送前请确认：

- 没有把 `wrangler.toml` 里的真实 `database_id` 当成密钥（它本身不敏感，但建议仓库私有）。
- 没有提交 `.dev.vars`、`*.sqlite`、备份 SQL、管理员密码或 `CODE_PEPPER`。
- 仓库名建议使用 `chunge-member-center`。

---

## 九、常见问题

**会员说访问码登录不了？**
先在后台看会员状态是否为「正常」，再确认访问码是否被重置过。连续输错会触发 10 分钟临时锁定。

**会员登录后刷新又回到登录页？**
确认正式环境使用 HTTPS（Cookie 带 `Secure`，HTTP 下浏览器不会保存）；同时检查 Pages 是否配置了 `CODE_PEPPER`。

**后台打开是初始化页？**
说明 `admins` 表为空。创建第一个管理员后入口自动关闭。若误删管理员，可在 D1 控制台清空 `admins` 表后重新初始化（仅限紧急操作）。

**上传资料提示未配置 R2？**
Pages 项目没有绑定变量名为 `R2` 的存储桶，按「配置绑定」重新添加并重新部署。

**工具页打不开或 404？**
确认后台工具状态为「发布」，入口为 `/tools/<slug>/`，且 `public/tools/<slug>/index.html` 存在。

**课程正文里的图片不显示？**
在课程弹窗里用「正文配图」上传后，正文会自动插入 `/media/xxx.png` 形式的地址；若手工填写，请确认路径以 `/media/` 开头且文件已上传成功（提示未配置 R2 时先绑定 `R2` 桶）。

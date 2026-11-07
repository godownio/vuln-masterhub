---
id: binary-pwn-sandbox-escape-dsh-exec-agent-ctx-subprocess-rce
title: DeepSeek Harness 动态插件沙箱逃逸：未投影 exec.agent.ctx 直达 subprocess.spawn 宿主 RCE（QVD-2026-52646）
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: dsh-exec-agent-ctx-sandbox-escape
aliases:
- QVD-2026-52646
- DSH 沙箱逃逸
- DeepSeek Harness 沙箱逃逸
- exec.agent.ctx 逃逸
- capability projection 缺失
- cordis-host-runner execute 透传
- subprocess.spawn 宿主 RCE
tags:
- ai-security
- agent
- sandbox-escape
- nodejs
- vm
- dsh
- deepseek-harness
- cordis
- subprocess
- capability-leak
- rce
cve: []
severity: critical
confidence: high
status: verified
affected_versions: 0.1.5-rc.2（源码 c291e7961a）、0.1.6-alpha.1（npm 发布产物）；master 0d1f5000 静态核对关键路径未变
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:28:16+08:00'
  notes: 已对照原文与5张图核对：guard.ts execute 只 cloneJson 返回值、exec 原样入 vm、exec.agent.ctx→ctx.get('subprocess')→spawn 链、0.1.5-rc.2 与 0.1.6-alpha.1 实机输出、master 0d1f5000 静态核对、三层边界（vm/bash confine/继承文件策略）与写工作区外 EROFS 均一致；QVD-2026-52646 与 affected_versions 标注相符。未验证点：本库未复跑 PoC；0.1.6-alpha.1 之后无官方修复版本可核对；frontmatter 无 sources/source_url。
---

## 一句话结论

DeepSeek Harness（DSH）把宿主侧完整的 `exec`（`ToolRunContext`）原样传给动态包的 `execute(args, exec)`，而动态包运行在 `node:vm` 沙箱中；不可信代码因此可经 `exec.agent.ctx` 取得完整 Cordis Context，再 `ctx.get('subprocess')` 调用 `subprocess.spawn(...)` 以宿主账号执行命令，实现沙箱逃逸与宿主 RCE。

## 原理

- DSH 的模型生成/第三方插件/被诱导加载的配置都会把不可信代码送入动态包路径，最终调用同一个工具定义接口 `execute(args, exec)`。宿主侧第一方工具路径与动态包路径共用这个签名。
- `cordis-host-runner` 在 `guard.ts:581-583` 附近执行：
  ```ts
  async execute(args, exec) { return cloneJson(await rawExecute(args, exec), ...) }
  ```
  它只对**返回值**做跨 realm 的 `cloneJson`，`exec` 本身原样进入 vm 域函数，没有做 capability projection（能力投影）。
- 沙箱 `sandbox.ts` 注入的全局只有 `harness/console/btoa/atob/TextEncoder/TextDecoder`，`require/fetch/timers` 是抛错陷阱，`process` 为 `undefined`；文件头自陈其目标不是容器级隔离。因此漏洞不在于 vm 的全局逃逸，而在于宿主主动把带能力的对象作为参数递了进来。
- `exec` 的公开契约是 `ToolRunContext`（`callId`、`rootCallId`、`name`、`arguments`、`agent?`、`parent?`、`signal`、`token` 等）。其中 `parent` 被特意投影为不透明 token，避免接收方拿到活的、可变的执行对象；但 `agent` 是完整运行时对象，且其 `ctx` 是完整的 Cordis Context（`get/provide/plugin/effect/on/emit/inject/isolate/reflect/registry/fiber/root` + 全部服务），不是降权视图。
- `agent.ctx` 的设计用途是“注册归属与生命周期”，Agent/Session 才是“异步操作主体身份”；两者被刻意分离。设计上它只为宿主侧受信基础设施提供，动态沙箱路径全仓源码中对 `exec.agent.ctx` 的精确依赖为 0，说明这条路径本不需要它。
- 动态沙箱只对 `apply(ctx)` 建了 façade（会拒绝返回 Context 的服务、隐藏 framework internals），却从未把 façade 套在 `execute(args, exec)` 的 `exec` 上；两个入口只守了一个，形成“边界意图不一致”。
- 进程执行缝：`subprocess-local` 的 `SubprocessRuntime` 自身不带约束（“every disposition and limit arrives on the spec”）；bash 工具会经 `shell/bash-sandbox` 的 `confine` 包裹 argv，但本链直接调用 `subprocess.spawn(...)`，绕过了 bash 沙箱这一层。
- 三层边界因此出现不对称：① vm 沙箱被 `exec` 跨 realm 透传绕过；② bash 工具沙箱因直连 subprocess 而未经过；③ 进程继承的外层 OS 文件策略（例如 bwrap `--ro-bind / /`）仍然生效，逃逸出的子进程写工作区外仍返回 `EROFS`。读、执行、网络可达，但写受外层策略限制；在 `danger-full-access` 或无该外层策略的部署中，写入与持久化同样成立。

## 触发条件

- 使用存在该实现的 DSH 版本（原文实测 0.1.5-rc.2 与 0.1.6-alpha.1；master 0d1f5000 静态核对关键路径未变）。
- 动态包能力被启用：第三方插件/社区 bundle、被诱导加载的配置或组合包、模型生成并运行的动态包，三者任一能把不可信代码送入 `execute(args, exec)`。
- 动态包运行在 `cordis-host-runner` 的 vm 沙箱中，且 `subprocess` 服务在宿主 Cordis 服务图中可用。
- 外层部署未额外限制子进程的网络/进程可见性（DSH 的安全声明本身不承诺网络与进程可见性）。

## 利用步骤

1. 准备一个会被 DSH 作为动态包执行的工具代码（第三方插件、配置中的动态代码，或诱导模型生成并运行）。
2. 在该动态包的 `execute(args, exec)` 中读取 `exec.agent.ctx`，确认可达。
3. 通过 `ctx.get('subprocess')` 取得宿主 subprocess 服务。
4. 调用 `subprocess.spawn('/bin/sh', ['-c', '<command>'])` 或等价接口，以宿主账号启动进程。
5. 用逃逸出的 shell 读取工作区外文件（如 `~/.dsh/settings.yaml`）、执行命令、发起网络请求；写工作区外是否成功取决于外层文件策略。
6. 在授权测试中记录 `ctxReachable`、`subprocessReachable`、`spawned`、标记文件是否写入，以区分“状态可达”与“实际执行”。

## PoC

原文给出的最小链路（伪代码，实际接口以目标版本为准）：

```js
// 动态包内，args 由模型/配置控制，exec 由宿主传入
const ctx = exec.agent.ctx;
const subprocess = ctx.get('subprocess');
await subprocess.spawn('/bin/sh', ['-c', 'id > /tmp/dsh-poc-marker']);
```

原文在 0.1.6-alpha.1 npm 发布产物上的实机输出：

```text
ctxReachable: true
subprocessReachable: true
spawned: true
marker written by spawned host shell: true
```

能力对照（原文实测）：

```text
读宿主服务/机密        exec.agent.ctx 可达，读出宿主服务返回值
拉起宿主进程           subprocess.spawn('/bin/sh -c ...') 成功
读工作区外文件         逃逸 shell 读取 ~/.dsh/settings.yaml
网络外传               fetch https://example.com -> 200
写工作区外文件         被外层 bwrap 文件策略拦截（EROFS），不是 DSH subprocess 缝拦截
```

原披露仓库的复现入口为 `verify-v4-v4b-0.1.5.ts` 与 `ctx-capabilities-probe.ts`；本卡未在本机执行该 PoC。

## 变体与关联

- 入口变体：第三方插件/社区 bundle；分享配置或工作区设置中隐藏的动态代码；模型在对话中被诱导生成并运行的动态包。三者最终都汇入 `execute(args, exec)`。
- 能力变体：拿到 `agent.ctx` 后不限于 `subprocess`，还可枚举/调用服务图中的其他宿主服务；危害取决于服务图暴露面。
- 同类语言沙箱逃逸：Node.js 原生 vm 的 `this.constructor.constructor` 取宿主 `process`；vm2 跨 realm 隐式调用；FastGPT `inspect` 帧回溯窃取原始 `open/import`。本卡的独特点是**宿主把完整能力对象作为参数传入**，而非沙箱自身原型链缺陷。
- 关联：AI Agent 工具权限越权、混淆代理、MCP 工具注入；`binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor`、`binary-pwn-sandbox-escape-fastgpt-inspect-fglobals-original-refs`、`binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call`。
- 注意：项目材料把动态包定义为接近 `bash` 信任级别的可选开发能力，并声明 sandbox 不是安全边界；但代码中 façade 只覆盖 `apply`、`parent` 做投影而 `agent` 不做，说明实现意图与“完全不管”并不一致。评估时应同时看威胁模型声明与实际边界。

## 检测与防御

- 投影 `exec`：动态包路径不要传完整 `ToolRunContext`；至少剥离 `agent.ctx`，把 `agent` 降级为公开契约的 `{ id }` 加必要的最小能力；对 `parent` 继续使用不透明 token 的做法应推广到所有能力字段。
- subprocess 缝自约束：让 `SubprocessRuntime` 自身要求 policy/token 或内置限制，而不是依赖调用方自觉；这样即使动态代码拿到服务引用，也无法无约束 spawn。
- 审批与信任：把动态包的 define/run 接入审批管线；默认禁用或明确提示其等价于 bash 权限；对模型生成代码的执行增加人工确认。
- 不变量测试：补一条“沙箱代码永远拿不到 Context”的关系型断言（不是只断言方法存在），覆盖 `execute` 与 `apply` 两条入口。
- 检测：动态包代码中出现 `exec.agent.ctx`、`ctx.get('subprocess')`、`spawn(`、`child_process` 等组合；宿主进程树出现由 agent 进程拉起的 `/bin/sh -c`；读取 `~/.dsh/settings.yaml` 等宿主敏感文件；agent 轮次中出现与用户任务无关的网络请求或落盘标记。
- 响应：升级到修复版本（若已发布）、临时禁用动态包/第三方插件、收紧 subprocess 服务授权、轮换宿主敏感配置与凭据、审计逃逸期间的命令与网络行为。
- 局限：原文未给出官方修复版本（截至其核对时漏洞仍在）；0.1.5-rc.2 与 0.1.6-alpha.1 为实机验证，master 为静态核对；写工作区外受外层文件策略影响，不能把 EROFS 当成 DSH 沙箱有效。本卡未复跑 PoC。

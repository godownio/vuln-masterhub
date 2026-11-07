---
id: web-java-component-onlyoffice-runtime-config-hot-reload-downgrade
title: ONLYOFFICE runtime.json 热加载与配置合并导致安全开关静默降级
type: scenario
domain: web
path: web/java/component
technique: onlyoffice-runtime-config-hot-reload-downgrade
aliases:
- ONLYOFFICE runtime.json 热加载
- Document Server 配置合并降级
- runtimeConfig 覆盖 token.enable
- 安全配置可写域
- moduleReloader NODE_CONFIG 替换
tags:
- onlyoffice
- nodejs
- config-injection
- hot-reload
- auth-downgrade
- jwt
- trust-boundary
- converter
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V23
  verified_at: '2026-11-05T02:44:24+08:00'
  notes: 已对照原文核对；production-linux.json 默认 runtimeConfig.filePath、200ms 去抖热加载、deepMergeObjects 合并顺序（base→runtime→tenant）、加固 browser=true 被 runtime 覆盖回 false 的 harness 结果、moduleReloader NODE_CONFIG 第二条通道，均与正文一致。卡内已明确：写 runtime.json 的生产可达性、x2tPath spawn 链与 RCE 均未端到端验证，属条件链，confidence medium 合理。
---

## 一句话结论

ONLYOFFICE 生产配置默认把 `runtimeConfig.filePath` 指向应用可写域内的 `Data/runtime.json`，该文件被 200ms 去抖热加载并与基础配置深合并；只要攻击者能写这个文件，就能把已加固部署的 `token.enable.browser` 静默改回 false（或改 `FileConverter.converter.*Path/args`），实现鉴权降级并可能影响转换器进程。

## 原理

- `Common/config/production-linux.json` 默认 `runtimeConfig.filePath = /var/www/onlyoffice/documentserver/../Data/runtime.json`（归一化后 `Data/runtime.json`）；`default.json` 中为空字符串。热加载能力出厂即开启，不需要额外打开。
- `runtimeConfigManager.getConfigFromFile` 直接 `fs.readFile` + `JSON.parse`；监听的是**目录**（`fs.watch(dir)`），回调只比较文件名、不比较事件类型，因此 `runtime.json` **首次创建**也会触发；200ms 去抖后删除 `nodeCache`、`cleanRuntimeConfigCache()` 并重新 `getConfig`。
- `operationContext` 的合并顺序是 `deepMergeObjects({}, moduleReloader.getBaseConfig(), runtimeConfig, tenantConfig)`：基础配置（含 `local.json` 中运维配置的 JWT）→ runtime → tenant，右侧覆盖左侧。runtime 层可以逐 key 覆盖 `token.enable.browser`，把加固值 true 改回 false；`deepMergeObjects` 是逐 key 深合并，不会整对象替换。
- 第二条通道：`moduleReloader.requireConfigWithRuntime` 在 DocService/FileConverter 进程启动时读取 `runtime.json`，合并进 `process.env.NODE_CONFIG` 并 `reloadNpmModule('config')` 替换全局 `config` 单例。这条通道覆盖所有 `config.get(...)` 直读（包括 `converter.js` 的 `x2tPath`/`docbuilderPath`/`args` fallback），不受 per-request `configCache` 遮蔽；两条通道必须一起处理。
- `converter.js` 用 `resolveConverterPath(ctx.getCfg('FileConverter.converter.x2tPath', ...))` 得到执行路径，`resolveConverterPath` 对相对路径锚定到 `FileConverter/`，但**绝对路径原样返回**；随后 `spawnAsync(processPath, childArgs)`。若 runtime 配置可写，可把执行路径指向攻击者文件（源码可达性，原文未端到端验证）。
- `deepMergeObjects` 未过滤 `__proto__` / `constructor` / `prototype`，`JSON.parse` 出来的同名自有属性会被 `for...in` 走到，存在原型污染面。
- 文章用 harness 加载真实配置与 `deepMergeObjects` 验证：加固 base（browser=true/inbox=true）+ runtime（browser=false/inbox=false）合并结果为 false；outbox 未被触碰，证明是逐 key 合并。HTTP 写文件与 RCE 未端到端验证，故置信度 medium。

## 触发条件

- `runtimeConfig.filePath` 非空（生产 Linux 打包默认成立），且该路径位于攻击者可写域（例如通过 storage 路径穿越任意文件写、其他文件写漏洞、错误的目录权限）。
- DS 的 DocService/FileConverter 进程能读取该文件；目录 watcher 正常（`fs.watch` 或退化轮询）。
- 目标为已加固部署（`token.enable.browser=true` 在 `local.json`）时，runtime 覆盖才会产生“从安全到不安全”的降级；默认部署本来就是 false，影响面不同。
- runtime 配置没有 key 白名单/schema，`FileConverter.converter.*`、`token.enable.*`、`log.*` 均可进入合并。

## 利用步骤

1. 读取部署配置，确认 `runtimeConfig.filePath`、`token.enable.browser`/`request.inbox` 当前值，以及 `local.json` 权限。
2. 获得对 `runtime.json` 的写权限（文件写原语或其他途径）；文件不存在也可，create 事件会触发。
3. 写入包含目标 key 的 JSON；热加载后下一次创建 `operationContext` 即带上 runtime 层。
4. 验证 `token.enable.browser` 是否变为 false（例如 `/downloadas` 不再要求 JWT）。
5. 若同时改 `FileConverter.converter.x2tPath`/`args`，需等待进程重启（启动通道 B）并触发转换；该步是源码可达性推断，原文未验证。

## PoC

仅展示配置合并形状，不提供完整可用配置：

```json
{"token":{"enable":{"browser":false}}}
```

harness 对真实 `deepMergeObjects` 的验证结果：

```text
base(加固)   browser=true inbox=true
runtime      browser=false inbox=false
merged       browser=false inbox=false outbox=true
```

说明：runtime 层只覆盖指定 key，`outbox` 保持原值；`tenantConfig` 在多租户下排在 runtime 之后，可再覆盖回去（次序为源码事实，多租户形态未实测）。

## 变体与关联

- 变体：通道 A 热合并（`operationContext.js`）只影响 `ctx.getCfg` 读法；通道 B 启动期替换全局 `config` 单例，影响所有 `config.get` 直读。只堵一条等于只堵一半。
- 变体：`runtimeConfig.filePath` 指针是启动期固化的，热改 runtime.json 不能把指针搬到别处；防守方 FIM 盯一个文件即可。
- 变体：`deepMergeObjects`/`config.util.extendDeep` 无原型键过滤，可进一步做原型污染（原文只到可达性判断）。
- 关联：[[web-java-component-onlyoffice-storage-key-path-traversal-file-write]]（写入 `runtime.json` 的路径原语）、[[code-analysis-vuln-discovery-storage-boundary-audit-pattern]]。
- 边界：原文没有真实 DS 实例、没有 HTTP 请求、没有验证 RCE；写 runtime.json 的可行性取决于挂载/权限/文件系统，属 C 级推断。

## 检测与防御

- 安全敏感 key（`services.CoAuthoring.token.enable.*`、JWT secret、`runtimeConfig.filePath`、`FileConverter.converter.*Path/args`、`log.*`）只从只读基线 `getBaseConfig()` 读取，合并后再把这些 key 逐项钉回基线。
- `runtimeConfigManager.getConfig` 在 `JSON.parse` 后、进 cache 前按允许前缀过滤（如仅允许 `features.*`、`log.options.level`），拒绝安全/执行相关 key。
- `runtime.json` 所在目录对应用进程只读挂载；配置更新走独立鉴权的运维接口（`saveConfig`/`replaceConfig`）并留审计记录。
- `deepMergeObjects` 跳过 `__proto__`/`constructor`/`prototype`。
- FIM/auditd 监控 `Data/runtime.json`、`log4js/production.json` 的写入/创建；监控 `handleConfigFileChange reloading config` 日志且无对应变更单。
- 进程派生告警：`x2t`/`docbuilder` 的可执行路径必须位于安装根下，出现异常绝对路径即告警。
- 两条通道一起修：既处理 `operationContext` 的合并，也限制 `moduleReloader` 写入 `NODE_CONFIG` 的 key。

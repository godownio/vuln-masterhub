---
id: web-generic-file-inclusion-go-newreplacer-dotdot-doublewrite-bypass
title: Go strings.NewReplacer 单次替换 ../ 为空：URL 路径用双写 ....// 还原出 ../ 穿越读取 users.json
type: scenario
domain: web
path: web/generic/file-inclusion
technique: go-newreplacer-dotdot-doublewrite-traversal
tags:
- go
- path-traversal
- filter-bypass
- double-write
- file-inclusion
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:27:19+08:00'
  notes: 已对照原文核对：strings.NewReplacer(../ -> 空) 单次替换、....// 还原 ../、http.ServeFile 读上级 users.json、截图里 r.URL.Path=/../users.json 求值为 /users.json 均与原文一致。未验证点：未本地起环境实测穿越（原文仅在 IDE 中对表达式求值）；原文无 Go 受影响版本，故未设 affected_versions。原理段对匹配起点描述略含糊（实际命中从第 3 个字符起，结论 ....// -> ../ 正确）。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-go-newreplacer-dotdot-doublewrite-bypass/
draft: false
kb_aliases:
- strings.NewReplacer 单次替换绕过
- ../ 双写 路径穿越
- Go http.ServeFile 目录穿越
- '....// 绕过'
- 单次 Replace 不递归
- users.json 穿越读取
---

## 一句话结论

当 Go 服务用 `strings.NewReplacer("../", "")` 过滤 URL 路径时，该调用只做**一次**非递归替换，所以 `....//`（或 `..././`）被替换后正好还原成 `../`，仍可穿越目录；把请求路径拼成 `....//users.json` 就能读到 Web 根目录之外保存用户名口令的 `users.json`。

## 原理

- **`NewReplacer.Replace` 是一次性的**：`strings.NewReplacer("../", "")` 从左到右扫描输入，命中 `../` 就替换为空并**继续从替换点之后**扫描，不会对替换产生的文本重新匹配。以 `....//` 为例：扫描到第 2 个字符起就是 `../`，被整段吃掉，剩下 `.` 与 `//`，拼起来正是 `../`；同理 `..././` 替换后也是 `../`（而 `...././` 只会得到 `.../`，不成立）。
- **为什么能穿越**：过滤后的字符串被直接当作文件路径使用（原文是 `http.ServeFile`/拼接路径读取），而 `../` 在文件系统语义下就是上跳一级。过滤只针对字面量 `../`，对「替换后重新出现的 `../`」无效，于是穿越能力被恢复。
- **为什么双写能稳定命中**：把每个 `../` 写成 `....//`（或 `..././`）后，单次替换吃掉一个 `../`，剩下的碎片重新拼成 `../`；再多级穿越把每一级都这样写即可。
- **前提是过滤发生在读取之前**：如果代码先对路径做 `filepath.Clean`/白名单校验再读取，或使用 `os.Root`、`http.Dir`（其内部对 `..` 有处理）就不会成立；原文的 `PathReplacer.Replace(r.URL.Path)` 只是裸替换，没有二次校验。

## 触发条件

- 服务端对 URL 路径或文件名做「把 `../` 替换为空/删除」的一次性过滤，且过滤结果直接用于文件定位（读取或写入）。
- 过滤逻辑不递归、不重复执行（`strings.NewReplacer`、单次 `strings.Replace`、`ReplaceAll` 但只调用一次都属此类）。
- 目标文件位于 Web 根目录的上级或同级可预测路径（如与本程序同目录的 `users.json`、配置文件、源码）。
- 攻击者知道或能猜出目标文件名。

## 利用步骤

1. 阅读源码/差异确认过滤实现为一次性替换：`var PathReplacer = strings.NewReplacer("../", "")`，使用处 `path := PathReplacer.Replace(r.URL.Path)`。
2. 本地起环境或用调试器验证：请求 `/../users.json` 时替换后得到 `/users.json`（被剥掉穿越），确认单次替换会把 `../` 整个吃掉。
3. 改成双写：请求 `/....//users.json`，替换后变成 `/../users.json`，实际读取到上级目录的 `users.json`。
4. 按需增加层级：多级穿越把每一段都写成 `....//`，例如 `....//....//etc/passwd`。
5. 拿到敏感文件（本场景 `users.json` 内含其他账号口令）后登录，读取登录后页面中的 flag。

## PoC

```http
GET /....//users.json HTTP/1.1
Host: target
```

替换过程（`NewReplacer` 单次扫描）：

```text
输入   /....//users.json
命中   ....//  中的 ../ （前三个字符 . . /）
替换后 /../users.json          -> 读取上级目录 users.json
```

本地调试时可直接观察（原文在 IDE 里对 `r.URL.Path` 求值，`/../users.json` 经 Replace 后只剩 `/users.json`，证明 `../` 被整段删除，因此需要双写）：

```text
r.URL.Path = "/../users.json"
path        = "/users.json"        // ../ 被替换为空
```

返回内容（原文截图）为保存账号口令的 JSON：

```json
{"skat": "<redacted-password>"}
```

PoC 未在本机执行。

## 变体与关联

- **双写形态**：`....//`、`..././`、`..%2f`（若先解码再替换则 `%2f` 可能在替换后才成为 `/`）、大小写/多重编码组合；核心是让「替换后的结果」重新构成 `../`。
- **写场景同理**：若过滤用于上传文件名或写入路径，同样的双写可把文件写到目标之外（参见关联的上传文件名卡）。
- **更强过滤的绕过**：只删 `..` 不删 `/` 时用 `..././`；只检查一次 `strings.Contains(path, "../")` 而使用未过滤的原串时无需双写；先 `Clean` 再替换则基本无解，应换其它入口。
- **关联**：[[web-generic-file-upload-single-replace-dotdot-bypass]]（同一「单次 replace 不递归」原理在上传文件名场景的 `..././` 变体）、[[web-generic-file-inclusion-double-encoded-alternating-dotdot-traversal]]（双重编码 + 交替 `./../` 绕过连续匹配黑名单）、[[web-generic-sqli-keyword-double-write-bypass]]（同为「单次替换为空 → 双写还原」的通用思路）。
- **边界**：过滤改为递归/循环替换、或读取前做了 `filepath.Clean` + 存在性校验、或文件路径通过 `os.Root`/`http.Dir` 限制时无效；目标文件不在可穿越范围内时也拿不到。

## 检测与防御

- **修复**：不要用字符串替换做路径安全；应把请求路径按 `/` 分段后拒绝任何 `..` 段，或只允许白名单文件名，并用 `filepath.Clean` 后再次校验结果位于允许根目录内（Go 1.24+ 可用 `os.Root`/`http.Dir` 的受限访问）。
- **检测信号**：URL 路径中出现 `....//`、`..././`、连续 `/./`、编码后的 `%2e%2e%2f` 等变形；同一客户端短时间内请求大量非常规路径并返回 200；访问日志中路径穿越后紧跟敏感文件名（`users.json`、`config`、`*.env`）。
- **加固**：静态文件服务使用框架提供的受限目录（`http.FileServer(http.Dir(...))` 会拒绝含 `..` 的路径），敏感文件不要放在 Web 根同级的可预测位置。

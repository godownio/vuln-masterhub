---
id: web-python-framework-h3blog-gencode-field-code-injection-rce
title: h3blog 后台代码生成字段注入：把元数据写进生成的 Python 视图源码，访问生成接口触发 os.system RCE
type: scenario
domain: web
path: web/python/framework
technique: h3blog-gencode-metadata-python-source-injection-rce
aliases:
- h3blog 代码生成 RCE
- gencode 代码注入
- Flask 代码生成器 RCE
- 元数据注入 Python 源码
- 生成视图代码执行
- os.system 注入
tags:
- python
- flask
- h3blog
- code-generation
- source-injection
- rce
- admin-panel
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:23+08:00'
  notes: 已对照原文核对（36 图）；字段描述注入后访问 /admin/cms/vipprice/export 实测弹 calc；未复现。
---

## 一句话结论

h3blog 的后台“代码生成”功能把 `GenModel` 的模板、路径、字段描述等元数据直接拼进生成的 Python/HTML 源码：在字段描述中填入 `1"]+os.system('calc')#` 后，生成文件的 `title = ["1"]+os.system('calc')#...` 会在导入/执行时调用 `os.system`；访问生成的 `/admin/cms/vipprice/export` 等接口即可执行任意命令（原文弹出计算器）。该功能需要后台权限，但可与后台 XSS/弱口令/鉴权缺陷组合。

## 原理

- **代码生成 = 字符串模板拼接**：`app/admin/views/sys/gencode.py` 的 `gencode()` 根据 `GenModel` 记录生成视图文件：先 `os.path.join(basedir, 'app', 'admin', 'views', gm.view_path)` 建目录，再按模板生成 `.py`/`.html`，把模型字段的 `content` 内容写入文件（`open(py_path, 'w')` / `open(file_path, 'w')`）。
- **元数据未转义进入源码**：字段描述、标题、模型名等会被直接插入生成的 Python 源码字符串/列表字面量。攻击者把字段描述设置为 `1"]+os.system('calc')#`，生成的代码类似：
  ```python
  title = ["1"]+os.system('calc')#", "机构id", "名称", ...]
  ```
  `#` 注释掉后续内容，`os.system('calc')` 在模块导入/执行时运行；生成的视图被 Flask 路由加载时即触发。
- **生成文件可访问**：非 api 模型生成到 `app/admin/views/cms/`，对应路由如 `/admin/cms/vipprice/export`；生成成功后访问该路由，Flask 导入模块执行顶层语句，命令执行。
- **为什么是“代码注入”而不是 SSTI**：注入点不是模板渲染，而是代码生成器把数据写进 `.py` 源码；执行发生在 Python 解释器导入阶段，因此不受 Jinja 自动转义保护。
- **权限前提**：代码生成菜单属于后台管理功能，正常需要管理员登录；但原文同时发现后台鉴权实现缺陷（`is_admin()` 恒真、登录/日志处 XSS），攻击者可通过弱口令、XSS 窃取/滥用管理员上下文或鉴权绕过进入后台，再把后台功能升级为 RCE。

## 触发条件

- 攻击者能访问后台代码生成功能（管理员账号、弱口令、后台 XSS 会话滥用或鉴权缺陷）。
- 目标 h3blog 版本包含 `app/admin/views/sys/gencode.py` 的代码生成功能，且生成目录可写、生成文件会被 Flask 作为视图加载。
- 能创建/编辑代码生成配置（模型、字段描述、模板路径、view 路径等），并执行“生成代码”。
- 生成的接口可访问（同源后台路由），且进程有执行系统命令的权限。

## 利用步骤

1. 登录后台，进入“代码生成”/系统工具，新增一个代码生成配置：选择模型、模板、生成模块名（如 `vipprice`）、view 路径（如 `cms`）。
2. 在“字段信息”中把某个字段描述改为注入 payload：`1"]+os.system('calc')#`（Windows 弹计算器；Linux 可用 `id`/`touch /tmp/pwned` 验证）。
3. 保存配置并点击“生成代码”；生成器把 payload 写入 `app/admin/views/cms/vipprice.py` 的列表/字符串字面量。
4. 访问生成的路由（如 `/admin/cms/vipprice/export`），Flask 导入生成的模块，顶层 `os.system` 执行。
5. 若命令无回显，改用写文件、DNS/HTTP 外带或反弹 shell；根据生成模板选择可执行位置（Python 顶层语句、HTML 模板中的服务端表达式等）。

## PoC

字段描述 payload（原文）：

```text
1"]+os.system('calc')#
```

生成的代码形态（原文截图）：

```python
title = ["1"]+os.system('calc')#", "机构id", "名称", "支付金额", "天数", "{{123}}", "排序"]
```

访问：

```http
GET /admin/cms/vipprice/export HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<admin session>
```

响应返回 500（`can only concatenate list (not "int") to list`），同时 `calc` 已弹出，证明 `os.system` 在报错前执行。

## 变体与关联

- 注入字段：字段描述、字段名、模型名、模块名、模板路径、view 路径、上级菜单名等任何进入生成源码/模板的元数据。
- 生成类型：api 模型生成 `.py`，非 api 模型生成 `.py` + `.html`；HTML 模板中若拼接用户数据，可能形成 SSTI/客户端 XSS。
- 权限链：后台弱口令（原文默认 `admin:123456`）、`is_admin()` 恒真、`@login_required` 的 admin 蓝图校验缺陷、后台存储型 XSS 都可能成为进入后台的前置。
- 关联 [[web-generic-xss-h3blog-username-xff-log-stored-xss]]（后台 XSS 可作为进入代码生成功能的跳板）、[[web-python-framework-h3blog-download-path-traversal-file-read-delete]]（未授权读取 `.env`/配置获取密钥）。
- 同类模式：低代码/脚手架/代码生成器把用户可控元数据写入源码或模板，导致源码注入；与 Jinja SSTI 的区别是执行发生在生成文件的导入阶段。

## 检测与防御

- 不要用字符串拼接生成可执行源码；使用安全的代码生成模板 + 转义/白名单（字段名限制为标识符，描述用 `repr()`/JSON 序列化后嵌入，或改为运行时读取配置）。
- 代码生成功能仅对受信管理员开放，强制强密码/MFA，禁用默认口令；生成操作加二次确认与审计。
- 生成目录与 Flask 视图目录分离，生成文件不自动加载；对生成内容做静态检查（禁止 `os.system`、`subprocess`、`eval` 等）。
- 修复后台鉴权：`is_admin()` 不应恒真，严格校验 `user_type`/权限；后台 XSS 输出编码，避免管理员会话被滥用。
- 监控代码生成操作与生成文件中的危险函数；对 `/admin/cms/*/export` 等生成路由的异常访问与子进程创建告警。
- 最小权限运行 Web 进程，限制其写代码目录与执行系统命令的能力。

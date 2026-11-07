---
id: web-python-deserialization-pyyaml-python-name-identity-bypass
title: PyYAML python/name 引用模块 SECRET_PIN：绕过 is 身份比较登录
type: scenario
domain: web
path: web/python/deserialization
technique: pyyaml-python-name-identity-bypass
tags:
- web
- python
- pyyaml
- yaml
- deserialization
- identity
- auth-bypass
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:05:25+08:00'
  notes: 已对照原文与17张图核对：yaml.FullLoader、user_pin is SECRET_PIN、payload 与成功回显一致；未在目标本机执行。
url: /docs/web/python/deserialization/web-python-deserialization-pyyaml-python-name-identity-bypass/
draft: false
kb_aliases:
- yaml !!python/name
- SECRET_PIN is 比较
- PyYAML 身份比较绕过
- FullLoader 对象引用
- is_is_n0t_3qual3qual
---

## 一句话结论

应用用 `yaml.load(..., Loader=yaml.FullLoader)` 解析用户提交的 YAML，并用 `user_pin is SECRET_PIN` 做身份/相等校验时，攻击者提交 `pin_code: !!python/name:__main__.SECRET_PIN` 就能让解析结果直接引用服务端内存中的同一个 `SECRET_PIN` 对象，使 `is` 判定通过并登录为 admin。

## 原理

- **`is` 比较的是对象身份**：Python 的 `is` 等价于比较 `id(a) == id(b)`，不比较值。两个内容相同的字符串/整数，只要不是同一个对象，`is` 就可能为 False；反过来，只要能拿到同一个对象的引用，`is` 必然为 True。
- **`!!python/name:` 是 PyYAML 的对象引用标签**：`!!python/name:module.attribute` 不会新建值，而是 import 对应模块并取出该属性对象。它返回的是模块里已经存在的那个对象本身，因此与模块级变量 `SECRET_PIN` 是同一引用。
- **FullLoader 仍支持该标签**：PyYAML 从 5.1 起引入 `FullLoader`，它阻止 `!!python/object/apply` 等任意函数调用，但仍支持 `!!python/name:` 与 `!!python/module:` 这类“取对象”标签；只有 `SafeLoader` / `safe_load` 会以 `ConstructorError` 拒绝。很多开发者误以为 FullLoader 就是安全加载器，从而保留了这条对象引用能力。
- **成立条件**：`SECRET_PIN` 必须是模块级可 import 的属性，且模块路径与运行方式匹配。原文应用直接运行，`SECRET_PIN` 在 `__main__` 中，因此用 `__main__.SECRET_PIN`；若应用以 `app.py` / `server.py` 启动，则应改为 `app.SECRET_PIN` / `server.SECRET_PIN`。
- **为什么能绕过登录**：代码先检查 `user == 'admin'`（普通的字符串值比较），再检查 `user_pin is SECRET_PIN`。攻击者把 `username` 写成 `admin` 即可通过第一项；第二项因为拿到同一对象而恒真，最终进入返回 flag 的分支。

## 触发条件

- 用户可控输入进入 `yaml.load` / `yaml.unsafe_load` / `yaml.load(..., Loader=yaml.FullLoader)`，且未改用 `SafeLoader`。
- 关键校验使用 `is`（或 `is not`）比较用户输入与服务端模块级对象，而不是 `==` / `hmac.compare_digest`。
- 目标模块可被 import，且 `SECRET_PIN` 是模块级变量（不一定是字符串，任意对象均可）。
- 用户名等前置条件可用普通值满足（如 `username: admin`）。

## 利用步骤

1. 确认 YAML 解析面：提交合法 YAML 配置，观察是否被解析；提交含 `!!python/name:` 的 YAML，若报 `ConstructorError` 说明用了 SafeLoader，若正常解析则 FullLoader/UnsafeLoader 可用。
2. 确定 `SECRET_PIN` 所在模块：直接运行的 Flask 应用通常为 `__main__`；以模块方式启动时看启动命令与 `SECRET_PIN` 的定义文件（如 `app`、`server`、`config`）。
3. 提交 `username: admin` 与 `pin_code: !!python/name:<module>.SECRET_PIN`。
4. 观察响应是否进入 admin 成功分支并返回 flag；若模块名不对，依次尝试 `app`、`server`、`config`、`main` 等。
5. 变体：若 `GUEST_PIN` 分支同样可登录，也可用 `!!python/name:<module>.GUEST_PIN`；若代码用 `is None` 判空，`!!python/name:builtins.None` 也能提供 `None` 引用（不过 YAML 的 `null` 本身已是 None）。

## PoC

最小 YAML：

```yaml
username: admin
pin_code: !!python/name:__main__.SECRET_PIN
```

表单提交时需要对 `!`、`/`、换行做 URL 编码，例如：

```text
settings=username%3A+admin%0Apin_code%3A+%21%21python%2Fname%3A__main__.SECRET_PIN
```

本地验证 PyYAML 行为（未在目标上执行）：

```python
import yaml

SECRET = "1234"
doc = "pin: !!python/name:__main__.SECRET"
print(yaml.load(doc, Loader=yaml.FullLoader)["pin"] is SECRET)  # True
try:
    yaml.safe_load(doc)
except yaml.constructor.ConstructorError as e:
    print("safe_load rejected:", e)
```

## 变体与关联

- **模块路径变体**：`__main__`、`app`、`server`、`config`；也可引用其他模块中的常量/单例对象。
- **校验位置变体**：登录 PIN、邀请码、API key、下载令牌等任何用 `is` 比较用户输入的地方；若比较的是对象属性（如 `user.token is current_token`）同样成立。
- **加载器变体**：`yaml.Loader`、`yaml.UnsafeLoader`、`yaml.FullLoader` 都支持 `python/name`；`yaml.SafeLoader` 不支持。
- **关联**：[[web-python-deserialization-pyyaml-fullconstructor-bypass-object-new]]（FullConstructor 构造链）、[[web-python-deser-pyyaml-tag-directive-waf-bypass-linecache]]（%TAG 绕过 WAF 读文件）、[[ctf-reverse-python-str-eq-monkey-patch-comparison-log]]（Python 比较逻辑逆向）。
- **边界**：若代码改用 `==`，同一对象当然也相等，此绕过失效；但这说明 `is` 本身就是错误用法。若 YAML 解析发生在独立 worker/容器且 `SECRET_PIN` 不在该进程的模块中，引用会失败。

## 检测与防御

- **代码审计**：搜索 `yaml.load`、`Loader=yaml.FullLoader`、`yaml.unsafe_load`；搜索 `is` 与用户输入/密钥比较的写法，统一改成 `==` 或 `hmac.compare_digest`（密钥/口令优先用常量时间比较）。
- **加载器**：对不可信输入一律用 `yaml.safe_load`；如确需 FullLoader，先做 schema 校验并拒绝 `!!python/` 标签。
- **WAF/日志**：拦截请求体中的 `!!python/name`、`!!python/object`、`!!python/module`；记录 YAML 解析失败与异常标签事件。
- **运行隔离**：不要在被暴露的 Web 进程里让敏感对象以可 import 的模块级变量形式存在；把密钥放到不可达的配置服务/密钥管理系统，降低对象引用被利用的价值。
- **检测信号**：登录请求中出现 YAML 配置字段、`pin_code` 非普通标量、`!!python` 字面量，或 admin 登录成功但密码字段与实际值无关。

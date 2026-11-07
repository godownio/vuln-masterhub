---
id: code-analysis-vuln-discovery-python-adjacent-string-concat
title: Python 安全规则列表漏逗号导致隐式字符串拼接
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery/pattern
technique: implicit-string-literal-concatenation
aliases:
- 隐式字符串拼接
- 漏逗号
- adjacent string literal
- 黑名单规则合并
tags:
- python
- code-audit
- regex
- blacklist
- string-concatenation
- security-control
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-B
  verified_at: '2026-11-04T18:43:40+08:00'
  notes: 已对照原文核对：隐式字符串拼接原理、审计步骤与 PoC 正确；未在本机运行 tokenize 脚本（未验证点：未执行检测脚本）
---

## 一句话结论

在 Python 的规则列表里，两个相邻字符串字面量之间漏写逗号不会报错，解释器会在编译期把它们拼接成一个字符串，导致规则数量减少、正则语义改变，原本要拦截的路径可能全部放行。

## 原理

- Python 词法规则允许相邻字符串字面量自动拼接：`"abc" "def"` 等价于 `"abcdef"`。这是为多行长字符串设计的特性。
- 在列表中写成：
  ```python
  rules = [
      r"/lab(?:/.*)?"
      r"/api/terminals(?:/.*)?",
      r"/api/shutdown(?:/.*)?",
  ]
  ```
  第一条与第二条之间没有逗号，最终列表只有两个元素，第一个是 `/lab(?:/.*)?/api/terminals(?:/.*)?`。
- 若规则是带路径前缀/锚点的正则，合并后的表达式往往要求一个路径同时满足两个互斥条件，实际请求两边都不匹配，防护静默失效。
- 语法合法、导入成功、程序照常运行，只有规则数量和语义发生了变化；普通单元测试若不逐条验证规则，很难发现。
- 同类问题也会出现在 SQL 片段列表、命令白名单、WAF 规则、文件扩展名黑名单等任何“多行字符串 + 列表”的写法中。

## 触发条件

- 安全规则以列表/元组形式维护，元素跨多行书写且未使用尾逗号；
- 代码审查只看“规则是否存在”，没有断言实际元素数量；
- 没有针对每条规则的正向/反向测试（应拦截的样本、应放行的样本）；
- 隐式拼接没有被 lint 规则或 CI 检查覆盖。

## 审计步骤

1. 搜索安全相关列表：`BLOCKED_PATTERNS`、`DENY_LIST`、`ALLOW_LIST`、`WAF_RULES`、SQL 关键字过滤、扩展名黑名单等；
2. 在运行时打印 `len(rules)` 与每个元素的 `repr`，与代码中“看起来有几条”对比；
3. 对每条规则用已知敏感路径/输入做匹配测试，确认它真的能命中；
4. 用 `tokenize` 扫描相邻 `STRING` token，定位漏逗号的位置；
5. 对比版本 diff：安全规则文件的单字符改动常被忽略，却可能改变整条防护。

## PoC

```python
rules = [
    r"/admin(?:/.*)?"
    r"/backup(?:/.*)?",
    r"/debug(?:/.*)?",
]
print(len(rules))       # 2，而不是 3
print(rules[0])         # /admin(?:/.*)?/backup(?:/.*)?
```

```python
import io, tokenize

def find_adjacent_strings(src: str):
    toks = [
        t for t in tokenize.generate_tokens(io.StringIO(src).readline)
        if t.type not in (tokenize.NL, tokenize.NEWLINE,
                          tokenize.INDENT, tokenize.DEDENT,
                          tokenize.ENCODING, tokenize.ENDMARKER)
    ]
    for a, b in zip(toks, toks[1:]):
        if a.type == tokenize.STRING and b.type == tokenize.STRING:
            print("adjacent strings:", a.start, b.start)

find_adjacent_strings(open("block_handler.py", encoding="utf-8").read())
```

检测脚本会同时报告合法的多行字符串拼接，需要结合上下文人工确认；安全规则列表中的命中应优先修复。

## 变体与关联

- 变体：相邻字面量出现在函数实参、字典值、SQL 条件拼接、正则分段书写中；f-string 与普通字符串相邻；元组中漏逗号导致类型变化（`("a")` 不是元组）。
- 关联：[[web-python-framework-mercury-blocklist-comma-terminal]]（该模式导致真实产品终端与 JupyterLab 防护失效）；[[web-python-framework-mercury-unauth-jupyter-kernel-rce]]（同产品的另一条未授权执行路径）。
- 注意：不同 linter 对隐式拼接的默认告警策略不同，不能假设装了 linter 就一定能发现。

## 检测与防御

- **写法**：列表元素一律加尾逗号；一条规则一行；需要拼接时显式使用 `+` 或 `"".join([...])`，让意图可见。
- **测试**：为每条安全规则编写正反用例；启动时断言 `len(rules)` 等于预期值；逐条 `re.compile` 并对已知敏感输入做匹配自检。
- **CI**：加入隐式字符串拼接检查（tokenize 脚本或 lint 规则），安全规则目录强制评审。
- **代码审查**：diff 中出现“只改了一个标点”的防护文件要重点看；版本升级时对比规则数量与匹配结果。
- **运行时兜底**：关键访问控制不要只依赖一张正则表，改为默认拒绝 + 明确白名单，降低单条规则失效的影响。

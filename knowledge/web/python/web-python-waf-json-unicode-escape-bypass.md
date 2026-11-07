---
id: web-python-waf-json-unicode-escape-bypass
title: JSON Unicode 转义绕过前置 WAF：检查原文、json.loads 后还原敏感字符串
type: scenario
domain: web
path: web/python
technique: json-unicode-escape-waf-bypass
aliases:
- JSON Unicode 转义绕过
- os 绕过 WAF
- json.loads 前后表示不一致
- 前置 WAF 绕过
- Python JSON 解析绕过
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- python
- json
- unicode
- waf-bypass
- encoding
- eval
cve: []
verification:
  verified_by: verifier-V6
  verified_at: '2026-11-05T00:36:59+08:00'
  notes: 已对照原文与图7核对：WAF原文检查返回False，json.loads 后恢复 __import__('os').system('whoami')。核对中修正了卡片两处文字/示例：转义示例改为 \u006F\u0073、发送的JSON原文示例改为字面 \u006F\u0073。未验证点：未实际执行下游 eval；该卡为有条件场景（业务需在 json.loads 后 eval）。原文无版本区间，未设versions。
---

## 一句话结论

当 WAF 在 JSON 解析**之前**对原始请求体做关键字匹配，而业务在解析后把字段值交给 `eval`/`exec` 时，把敏感字符串写成 JSON 的 `\uXXXX` 转义（如 `\u006F\u0073` 表示 `os`）即可让原文不含 `os`，`json.loads` 解码后却恢复成 `os`，从而绕过检测并执行代码。

## 原理

- JSON 字符串支持 `\uXXXX` 形式的 Unicode 转义。`json.loads` 会把 `os` 解码为字符 `o`、`s`，最终字段值包含 `os`。
- WAF 若工作在 HTTP 报文/JSON 解析之前的文本层，看到的是字面的 6 个字符 `o`，其中没有 `os` 子串，基于关键字/正则的规则不会命中。
- 业务代码在解析后拿到的是已解码的字符串；若该字符串被拼进 `eval`/`exec` 或模板，就会执行攻击者代码。
- 本质仍是“检查的表示”与“实际使用的表示”不一致：与 Python 标识符 NFKC 归一化、URL 解码、Base64 解码等属于同一类解析层差异；绕过是否成立取决于 WAF 的检测阶段与业务的使用阶段。
- 该手法对大小写、字母组合均可使用：`\u006F\u0073`、`OS`（`\u004F\u0053`）等任意敏感词都可逐字符转义；也可混合普通字符与转义，规避正则对连续转义的识别。

## 触发条件

1. 请求体为 JSON，且 WAF/网关在 JSON 解析前做字符串关键字检测。
2. 业务在 `json.loads` 之后，把某个字段值用于 `eval`/`exec`、命令拼接、模板渲染等危险操作。
3. WAF 未对 JSON 做递归解码/规范化后再检测，也未在解析后的字段值上做二次检测。
4. 下游代码没有对字段值做语法/AST 白名单校验。

## 利用步骤

1. 确认接口接受 JSON，并定位字段被 `eval`/`exec`/模板使用的路径。
2. 先提交明文 payload（如 `__import__('os').system('id')`）观察是否被拦截。
3. 把敏感子串替换为 `\uXXXX` 转义，保持 JSON 合法。
4. 发送请求；WAF 原文检测不命中，`json.loads` 解码后业务执行。
5. 如需进一步规避，混合大小写转义、拆分字符串或叠加 Base64 等编码层。

## PoC

```python
import json

def waf(check_str):
    return "os" in check_str          # 解析前只查原文

# 原始请求体（Python 源码中 \\u 表示字面反斜杠，JSON 中即 \uXXXX）
a = '{"payload": "__import__(\'\\u006F\\u0073\').system(\'whoami\')"}'
print(a)
print(waf(a))          # False，未命中

b = json.loads(a)
print(b)
# {'payload': "__import__('os').system('whoami')"}

# 若业务随后执行：
# eval(b['payload'])   # 等价于 __import__('os').system('whoami')
```

发送的 JSON 原文（其中 `os` 为字面转义序列）：

```json
{"payload": "__import__('\u006F\u0073').system('whoami')"}
```

`json.loads` 解码后：

```json
{"payload": "__import__('os').system('whoami')"}
```

## 变体与关联

- 全大写转义 `OS`、混合普通字符与转义、把整个命令都转义，均可规避只匹配小写/连续模式的正则。
- 同类“解析前后表示不一致”绕过：Python 标识符 NFKC 归一化（见独立卡片）、URL 编码/双重 URL 编码、Base64/十六进制解码后再 eval、零宽字符清理。
- 若 WAF 在 JSON 解析后检查字段值，该手法失效；此时可尝试 JSON 重复键、类型混淆（数组/对象 vs 字符串）等解析差异。
- 不限于 Python：任何在 JSON 解析前做文本检测、解析后使用字段值的语言/框架都可能受影响。

## 检测与防御

- WAF 应先完成 JSON 解析/转义解码，再对解码后的字段值做关键字、语法与 AST 检测；对原始报文检测只能作为辅助。
- 对 JSON 中的 `\uXXXX` 递归解码后再匹配，并限制嵌套深度/转义层数，防止无限解码绕过。
- 业务侧禁止把不可信字段交给 `eval`/`exec`；使用 AST 白名单、沙箱或专用表达式引擎。
- 记录并告警“原文无敏感词、解析后出现危险函数”的差异；对同一请求的原始与解码表示做一致性检查。
- 对代码执行入口做参数类型/长度/字符集校验，拒绝包含 `__import__`、`system`、括号调用等结构的输入（在解码后判断）。

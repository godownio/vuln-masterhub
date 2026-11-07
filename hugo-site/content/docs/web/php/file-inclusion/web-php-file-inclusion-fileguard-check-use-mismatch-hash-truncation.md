---
id: web-php-file-inclusion-fileguard-check-use-mismatch-hash-truncation
title: PHP include 白名单校验与执行变量不一致：FileGuard 只校验
type: scenario
domain: web
path: web/php/file-inclusion
technique: include-whitelist-check-derived-copy-vs-raw-param
tags:
- php
- file-inclusion
- lfi
- whitelist
- path-traversal
- check-use-mismatch
- url-decode
- ctf
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:54:15+08:00'
  notes: '已对照原文「MiniSite」与图09-11核对：FileGuard::checkFile 先直接比对 ，再用 substr(,0,strpos(.''#'',''#'')) 与 rawurldecode 后的副本  比对，从不写回 ；路由 include [''f''] 使用原始值；原文 payload ?f=source.php%23/../about.php 穿越成功，最终 ?f=source.php%23/../../../../sssseeeeccccrrrrreeeetttt 读取 secret，卡片与原文一致，并已按原文把 # 在 include 中的解析标为依赖目标环境（confidence medium）。未复跑；无 CVE/版本；frontmatter 无 sources/source_url。'
url: /docs/web/php/file-inclusion/web-php-file-inclusion-fileguard-check-use-mismatch-hash-truncation/
draft: false
kb_aliases:
- FileGuard 绕过
- MiniSite
- include 校验变量不一致
- null
- rawurldecode 白名单绕过
- PHP include 路径穿越
- source.php#/../
---

## 一句话结论

MiniSite 的 `FileGuard::checkFile()` 对传入参数做 `#` 截断和 `rawurldecode()` 后只校验派生出的 `$_page` 副本，而真正执行的是 `include $_REQUEST['f']` 的原始值；攻击者提交 `f=source.php%23/../../...`，让校验副本变成白名单里的 `source.php`，原始值则带着 `#`/`../` 进入 include，最终包含 Web 根目录之外的 secret 文件。

## 原理

- **校验与执行看不同的值**：`checkFile(&$page)` 内部先 `if (in_array($page, $whitelist, true))`，再做 `$_page = substr($page, 0, strpos($page.'#', '#'))` 并校验 `$_page`，最后 `$_page = rawurldecode($page)` 再截断校验。三次校验用的都是局部变量 `$_page`，从未把截断/解码后的结果写回 `$page`；而路由层 `include $_REQUEST['f']` 使用的仍是原始请求参数。
- **`#` 截断制造“校验副本”**：请求 `f=source.php%23/../about.php` 时，PHP 的 GET/POST 解码会把 `%23` 还原成 `#`，`$page` 为 `source.php#/../about.php`；`strpos($page.'#','#')` 找到 `#`，`substr` 得到 `source.php`，命中白名单，校验通过。`rawurldecode` 那一层对已解码的 `#` 没有额外作用，但同样会在 `#` 处截断。
- **执行时仍用原始值**：`include $_REQUEST['f']` 拿到的是 `source.php#/../about.php`（或 `source.php#/../../../../sssseeeeccccrrrrreeeetttt`）。在题目环境中，include 的路径解析让 `#` 后的 `../` 参与目录跳转，从而从当前目录逐级上跳；而白名单只看到了 `source.php`。该行为依赖 PHP/文件系统对 `#` 与相对路径的具体处理，需按目标环境验证；核心缺陷是“校验值 ≠ 执行值”，不依赖某一个字符的特殊语义。
- **为什么能成立**：白名单函数把“检查”与“使用”拆成了两个不同的字符串表示，且没有在最终 include 前再次用同一个规范化后的值/真实路径做校验；这是典型的 check-use mismatch（TOCTOU 的纯字符串版本）。
- **影响**：包含 Web 根之外的文件（本题为 `/sssseeeeccccrrrrreeeetttt`）可直接读取 flag；若可包含日志/上传文件，还可进一步 RCE。

## 触发条件

- 应用用 `include`/`require` 加载用户可控的文件名，且白名单检查函数对参数做了截断、解码、规范化等派生处理。
- 检查函数只校验派生副本，最终 include 使用原始参数（或反过来，检查原始、执行派生），两者表示不一致。
- 目标环境允许 `#`、`..`、编码字符等进入最终路径，且进程对目标文件有读权限。
- 攻击者知道白名单中的某个文件名（如 `source.php`）作为“前缀”。

## 利用步骤

1. 读取 `source.php`/源码，确认 `FileGuard::checkFile()` 的截断与解码逻辑，以及路由层 `include` 的参数名（`f`）。
2. 构造 `f=source.php%23/../about.php`，验证白名单通过且 include 走到了上级目录的 `about.php`。
3. 逐级增加 `../`，指向目标文件：`f=source.php%23/../../../../sssseeeeccccrrrrreeeetttt`。
4. 请求该 URL，读取 flag 或任意可读文件。
5. 若 `#` 被环境过滤，尝试 `%00`、`?`、`;`、双重编码、`rawurldecode` 差异等其它“截断/表示差异”变体。

## PoC

```http
GET /?f=source.php%23/../about.php HTTP/1.1
Host: <target>
```

```http
GET /?f=source.php%23/../../../../sssseeeeccccrrrrreeeetttt HTTP/1.1
Host: <target>
```

预期：第一条能包含上级目录的 `about.php`，第二条包含 Web 根之外的 secret 文件并返回 flag。原文未在本库环境复跑；`#` 在 include 中的具体解析需按目标 PHP/文件系统验证。

## 变体与关联

- **表示差异变体**：`#`、`?`、NUL、分号、双重 URL 编码、`rawurldecode`/`urldecode` 次数差异、大小写/Unicode 规范化；核心是让“检查用的字符串”与“执行用的字符串”不同。
- **引用变体**：检查函数按引用接收参数但只改局部副本（本题 `&$page` + `$_page`），或先检查后把变量重新赋值；审计时重点看 `include` 前的最后一次赋值。
- **关联卡片**：[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（先黑名单后解码的 `%2e%2e%2f` 绕过，属于“检查时未解码”）、[[web-php-file-inclusion-wordpress-page-template-path-traversal]]（先过滤后解码的双重编码模板穿越）。

## 检测与防御

- **统一表示**：白名单检查与 include 必须使用同一个规范化后的变量；检查后立即把该变量赋回执行变量，或直接返回规范化路径。
- **真实路径校验**：`realpath()` 后校验结果是否位于允许目录前缀内；不要只比对文件名/字符串。
- **白名单**：只允许固定的文件名，不接受 `#`、`?`、`..`、编码字符；对 `rawurldecode`/`urldecode` 后的值做完整规范化再校验。
- **最小权限**：Web 进程只能读 Web 根与必要目录；secret/flag 放在进程不可读的位置。
- **检测**：请求参数中出现 `%23`、`%00`、多层 `../`、`rawurldecode` 后仍含路径分隔符；include 错误日志中出现白名单文件名之外的路径；同一参数在校验与执行阶段长度/内容不一致。

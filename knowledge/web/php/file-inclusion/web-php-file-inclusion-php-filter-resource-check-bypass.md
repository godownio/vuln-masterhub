---
id: web-php-file-inclusion-php-filter-resource-check-bypass
title: php://filter 只校验 resource 值不校验完整 wrapper：resource=index.php 通过检查后包含整个 filter URL 读源码
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-filter-resource-check-scope-bypass
aliases:
- php://filter resource 检查绕过
- LFI resource 参数校验绕过
- php filter 读源码
- 伪协议 include 绕过
tags:
- php
- lfi
- php-filter
- file-inclusion
- blacklist-bypass
- source-disclosure
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:19:41+08:00'
  notes: 已对照原文核对：index.php 源码中的 php:// 分支、resource 检查与 include() 一致；原文未给出具体请求/响应，PoC 按源码重构，属同目录源码读取，保留。
---

## 一句话结论

当代码检测到参数以 `php://` 开头后，只用正则取出 `resource=([^&]+)` 的值并对该值检查 `/`、`\`、`..`，随后却 `include($requestedPage)` 包含**完整**的 `php://filter/...` 字符串时，检查范围与真正使用的位置不一致：把文件名放在 `resource=` 里（如 `resource=index.php`，不含斜杠/点），filter 前缀里的 `/` 不会进入被检查的 `$resource`，即可通过检查并用 `php://filter/convert.base64-encode` 读取同目录源码。

## 原理

- `php://filter` 是 PHP 的流包装器，`include`/`file_get_contents` 都支持；典型用法 `php://filter/convert.base64-encode/resource=index.php` 会在读取 `index.php` 时把内容 Base64 编码，避免 PHP 源码被 `include` 当代码执行，也便于把源码打印出来。
- 有缺陷的校验逻辑通常长这样：
  ```php
  if (strpos($requestedPage, 'php://') === 0) {
      if (preg_match('/resource=([^&]+)/', $requestedPage, $m)) {
          $resource = urldecode($m[1]);
          if (strpos($resource,'/')!==false || strpos($resource,'\\')!==false || strpos($resource,'..')!==false) die;
          include($requestedPage);   // 使用的是完整字符串，不是 $resource
      }
  }
  ```
  开发者以为“检查了 resource 就安全”，但真正传给 `include` 的是带有 `/` 的 `php://filter/convert.base64-encode/resource=index.php`；`$resource` 只是 `index.php`，自然不含 `/`、`\`、`..`。
- 为什么能读源码：`convert.base64-encode` 把 `index.php` 的内容编码后作为 include 的“输出”打印（或作为页面内容显示），攻击者拿到 Base64 再解码即可得到源码；如果代码把 include 结果写入响应，Base64 文本通常直接可见。
- 该缺陷属于“检查对象与实际使用对象不一致”（check/use mismatch）：只校验子串 `resource`，不校验 wrapper 前缀、filter 链或其他参数；即使 `$resource` 被严格限制为无斜杠文件名，攻击者仍可读取同目录任意文件（如 `index.php`、`config.php`）。
- 若要读取其他目录文件，`resource` 中的 `/` 和 `..` 会被拦；可尝试同目录已知文件名、`resource=flag.php`、URL 编码/过滤器链等变体，或寻找 `resource` 之外的可控 wrapper（如 `php://filter/read=.../resource=...` 的嵌套写法）。本文只验证了同目录 `index.php`。

## 触发条件

- 存在 `include`/`file_get_contents` 等文件包含 sink，参数以 `php://` 开头时进入特殊分支。
- 代码用正则提取 `resource=` 值并对该值做黑名单检查，但最终包含的是完整 `$requestedPage`。
- 目标允许 `php://filter`（默认允许；不受 `allow_url_include` 影响，`php://filter` 是本地 wrapper）。
- 目标文件位于同目录或路径中不含被检查字符；响应能带回 include 的输出/Base64。

## 利用步骤

1. 确认 `page`/`file` 参数进入 `include`，且直接传 `php://filter/...` 不报“远程 URL 不允许”。
2. 构造 `php://filter/convert.base64-encode/resource=<同目录文件名>`，例如 `resource=index.php`；确保 `resource` 值不含 `/`、`\`、`..`。
3. 发送请求，观察响应中是否出现长 Base64 文本；若有，提取并 Base64 解码，得到源码。
4. 对 `config.php`、`flag.php`、`common.php` 等同目录文件重复；若只回显部分内容，改用 `convert.base64-encode|convert.base64-encode` 或分段读取过滤器。
5. 若 `resource` 检查也拦住了目标文件名（如含点号但 `..` 只拦连续两个点，单点通常允许），尝试 `resource=index.php` 正常；若目标在子目录，需要寻找其他绕过（编码、过滤器链、软链接、日志包含等）。

## PoC

```http
GET /index.php?page=php://filter/convert.base64-encode/resource=index.php HTTP/1.1
Host: target
```

```text
响应中出现类似：
PD9waHAgc2Vzc2lvbl9zdGFydCgpOyAKZGVmaW5lKCdQQUdFX1dFQ0hBVCcsICd4aWFveGkucGhwJyk7...
Base64 解码后得到 index.php 源码。
```

说明：PoC 按原文代码路径与 `php://filter` 用法重写，未在原文目标上复跑；`resource` 的文件名需替换为目标同目录实际文件。

## 变体与关联

- **过滤器链**：`php://filter/read=convert.base64-encode/resource=index.php`、`convert.iconv.*` 等可改变输出编码或绕过关键字检查；见 [[web-php-file-inclusion-php-filter-insert-bypass]]。
- **无文件包含 RCE**：`php://filter` chain 从空流生成任意字节，配合 `include` 实现无文件 RCE；见 [[web-php-file-inclusion-filter-chain-fileless-rce]]。
- **XXE + php://filter**：XXE 读内网文件时同样可用 filter 链；见 [[web-generic-xxe-php-filter-ssrf-internal-lfi-chain]]。
- **边界**：代码改为对完整 `$requestedPage` 做 `realpath`/白名单、禁止 `php://` wrapper、或 `include` 前 `str_replace` 掉 wrapper 时，本链不成立；`resource` 含 `/`/`..` 会被本卡的检查拦住，需要另找绕过。

## 检测与防御

- 防御：不要用“检查 resource 子串”的方式；对完整请求路径做严格白名单（固定页面名数组），拒绝任何 `php://`/`phar://`/`file://` wrapper；需要读文件时用映射表，不把用户输入拼进 `include`。
- 代码审计：检查所有 `include`/`require`/`file_get_contents` 的 check/use 是否一致；正则捕获的子串检查不能代表完整参数。
- 检测：请求参数出现 `php://filter`、`convert.base64-encode`、`resource=`；响应出现大段 Base64；同一来源枚举同目录 PHP 文件。
- 响应：发现源码泄露后轮换配置中的密钥/数据库口令，排查是否进一步利用源码中的其他漏洞。

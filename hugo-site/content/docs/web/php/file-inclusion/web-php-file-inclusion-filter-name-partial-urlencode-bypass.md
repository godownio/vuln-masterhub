---
id: web-php-file-inclusion-filter-name-partial-urlencode-bypass
title: LFI 黑名单扫原始串、`php://filter` 包含时再解码一次：只把关键字里一个字符写成 `%25XX` 即可穿过长篇黑名单
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-filter-name-partial-double-encode-bypass
tags:
- web
- php
- lfi
- php-filter
- blacklist-bypass
- double-encoding
- filter-chain
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:50:55+08:00'
  notes: 已对照原文核对；原文黑名单正则、二次解码 payload（conv%2565rt/bas%256564-encode）与 guest.php 源码一致，与 filter-chain-cp037-double-urlencode（整串双重编码+CP037 隐藏关键字）不是同一链；本次核对未读取图片，二次解码是否仅靠 php://filter 包装器完成（而非应用又解码一次）属推断，RCE/filter chain 生成部分未在正文验证
url: /docs/web/php/file-inclusion/web-php-file-inclusion-filter-name-partial-urlencode-bypass/
draft: false
kb_aliases:
- 关键字单字符编码绕过
- 百分号双写编码绕过文件包含黑名单
- php://filter 二次解码
- filter 名 URL 编码绕过
- 黑名单绕过 filter chain
- signal 任意文件读取
---

## 一句话结论

当 LFI 的黑名单是一长串子串（`string|iconv|base|rot|data|text|decode|convert|proc|_` 等）并且直接对 `$_GET['path']` 取值后的字符串做 `preg_match` 时，不需要构造复杂编码链：只把每个待用关键字里的**一个字符**替换成 `%25` + 该字符的十六进制（`convert` → `conv%2565rt`、`base64` → `bas%256564-encode`），黑名单看到的是 `conv%65rt`（不含 `convert`）从而放行，而 `include` 进入 `php://filter` 时包装器再解码一次还原成 `convert`，黑名单就此失效。

## 原理

- **两次解码，两个观察者**：`$_GET` 取参时 PHP 已做一次 URL 解码，黑名单正则看到的是这一层的字符串；`php://filter` 包装器在解析 filter 名时还会做一次百分号解码。让「黑名单看到的」与「包装器看到的」不同即可。
- **为什么只改一个字符就够**：黑名单是子串匹配，`conv%65rt` 里不存在连续的 `convert` 字样，因此不命中；而包装器解码后恰好还原出 `convert`。只改一个字符而非整串，payload 短、`%25` 数量少，不容易撞上「多处编码/异常百分号」之类的附加规则。
- **为什么必须写成 `%25XX`**：请求里若直接写 `%65`，PHP 取参时就解码成 `e`，黑名单照样命中。写成 `%2565`，取参后剩 `%65`；包装器再解码才得到 `e`——这是「双重编码但只落在单个字符上」。
- **黑名单里的 `_` 也要绕**：本例黑名单含 `\_`，而 filter chain 里常用的 `UCS-4LE`、`ISO_8859-2` 等转换名带下划线，同样对该字符做一次 `%25` 编码即可；若链里必须出现字面 `_`，则改用不带下划线的等价转换对。
- **用途是两步**：先用 `convert.base64-encode` 把源码编码读出（绕过黑名单拿到 `guest.php` 等文件的源码），确认 sink 与后续可用原语；再按源码决定是否进入 filter chain 无文件 RCE。
- **前提**：sink 必须是会走 stream wrapper 的 `include`/`require`（原文读文件时环境直接崩，作者据此判断是 `include`）；若只是 `file_get_contents`，编码层级也可能成立，但读取内容不回显时需另找带外方式。

## 触发条件

- 存在 `include($path)`/`require` 等 sink，参数用户可控且未做协议白名单。
- 黑名单用 `preg_match` 对取参后的字符串做子串匹配，覆盖 `php`、`filter`、`convert`、`base64`、`iconv`、`data`、`resource` 乃至 `_`。
- `php://filter` 可用（`allow_url_include`/`open_basedir` 未阻断），base64/iconv 过滤器可用。
- 能观测「命中黑名单」与「被包含」的差异（提示文案、响应长度、进程崩溃）以确认解码层级。

## 利用步骤

1. 先探 sink 与黑名单：直接传 `php://filter/convert.base64-encode/resource=/etc/passwd`，返回黑名单提示说明关键字被拦（本例返回 `Don't do this`）。
2. 验证二次解码：把 `convert` 写成 `conv%2565rt`、`base64` 写成 `bas%256564-encode`，若不再提示黑名单且返回 base64 内容，说明成立。
3. 读出源码：`?path=php://filter/conv%2565rt.bas%256564-encode/resource=/var/www/html/guest.php`，把响应 base64 解码得到源码，确认 sink 与文件系统权限。
4. 转向 RCE：源码确认为 `include($path)` 后，用 filter chain 生成器产出无文件 RCE 链，同样对每个被黑名单覆盖的关键字做单字符 `%25` 编码后投递。
5. 若链过长不好逐字处理，写脚本按黑名单词表批量替换（每个词替换其中一个字符），再统一 URL 编码一次。
6. 需要落 webshell 时按读到的目录/权限选择落点，或改用日志包含、会话文件包含。

## PoC

```http
GET /guest.php?path=php://filter/conv%2565rt.bas%256564-encode/resource=/var/www/html/guest.php HTTP/1.1
Host: target
Cookie: <已登录会话>
```

```text
# 服务端解码层级
# 1) PHP 取参解码：conv%2565rt -> conv%65rt，bas%256564 -> bas%6564
# 2) 黑名单 preg_match 看到：php://filter/conv%65rt.bas%6564-encode/... -> 不含 convert/base64，放行
# 3) include 进入 php://filter，包装器再解码：%65 -> e，%64 -> d
# 4) 实际生效：php://filter/convert.base64-encode/resource=/var/www/html/guest.php
```

原文黑名单（`guest.php`，来自 `.index.php.swp` 泄露的账号 `guest:MyF3iend` 登录后读到的源码）：

```php
if (preg_match('/(\.\.\/|php:\/\/tmp|string|iconv|base|rot|IS|data|text|plain|decode|SHIFT|BIT|CP|PS|TF|NA|SE|SF|MS|UCS|CS|UTF|quoted|log|sess|zlib|bzip2|convert|JP|VE|KR|BM|ISO|proc|\_)/i', $path)) {
    echo "Don't do this";
} else { include($path); }
```

## 变体与关联

- **变体（全串双重编码）**：把整条 payload 编码两次（`%`→`%25`），可绕过在更晚一层才解码的过滤；但会引入大量 `%25`，更易被「多重编码」规则命中，且难维护——本卡只编单字符正是为了更短更隐蔽。
- **变体（换位置/换写法）**：编中间字符（`con%2576ert`）、编大小写形态（`Convert`）、把 `resource` 也做一次单字符编码。
- **变体（其它 wrapper）**：`php://input`、`data://`、`zip://`、`phar://` 对百分号解码处理不同，可逐个寻找「过滤看不到、sink 能还原」的入口。
- 关联：`web/php/file-inclusion` 下「PHP filter chain 从空流生成任意字节实现无文件 RCE」（拿到 LFI 后的下一步）、「filter chain + CP037 双重 URL 编码」（同一「两次解码」根因，但那里编码整串并配合编码转换隐藏关键字）、「php://filter 只校验 resource 值」卡（同类「校验点与使用点不一致」）、`pentest/recon` 下「vim swap 文件恢复源码」卡（本例入口 `.index.php.swp`）。
- 边界：目标若只解码一次、或在解码后再做匹配（先解码再 `preg_match`），单字符编码失效；若禁用/计数 `%`，需改用等价协议名或其他 wrapper；`open_basedir` 生效时只能读允许目录。

## 检测与防御

- 检测：请求参数出现碎片化的 `php://filter`（`conv%25`、`bas%25`）、`%25` 与 `%` 混排、`resource=` 与 filter 名同现；`include` 后返回大段 base64；同一参数短时间内在「命中黑名单」与「放行」之间反复变形。
- 防御：不要用黑名单过滤文件包含参数——改为协议 + 路径白名单（只允许固定目录下的白名单文件，`basename()` 归一化后校验），并对参数只解码一次后用**同一份结果**做校验与 include（避免校验值与实际使用值不一致）；`allow_url_include=Off`、`open_basedir` 限定目录；不要把 `.swp`/`.git`/备份文件留在 Web 目录。

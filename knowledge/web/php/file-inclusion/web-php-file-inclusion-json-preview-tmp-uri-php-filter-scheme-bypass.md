---
id: web-php-file-inclusion-json-preview-tmp-uri-php-filter-scheme-bypass
title: JSON 预览服务两阶段文件读取：前缀校验路径穿越读源码 + .tmp 内容二次解析 php://filter 绕过 scheme 黑名单
type: scenario
domain: web
path: web/php/file-inclusion
technique: preview-tmp-uri-second-order-php-filter-scheme-denylist-bypass
aliases:
- JSON Beautifier
- preview.php 二次读取
- .tmp 内容当 URI
- php://filter 绕过 scheme 黑名单
- TMP_DIR 前缀校验路径穿越
- X-DocRoot 泄露
tags:
- php
- file-inclusion
- php-filter
- path-traversal
- second-order
- scheme-bypass
- preview-service
- source-disclosure
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:12:28+08:00'
  notes: 已对照原文与图04-07核对：robots.txt 暴露 /api/preview.php、X-DocRoot 响应头（图05）、../../ 穿越读 preview.php/config.php 源码、.tmp 内容二次 file_get_contents 且 scheme 黑名单漏 php://、resource= 必须等于 FLAG_PATH、data_uri 写入后 base64 解码回显 flag（图07），均与卡片一致。未验证点：PoC 未在本机复跑；原文未给组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

预览服务把用户写入的 `.tmp` 文件内容当作 URI 再次 `file_get_contents()`，scheme 黑名单只封 `http/https/ftp/ftps/phar/expect` 而漏掉 `php://`，只要内容里的 `resource=` 命中白名单路径，就能用 `php://filter` 读取受限文件；同一接口的前缀校验发生在 `realpath()` 之前，还可用 `../` 穿越到允许列表中的源码目录读配置。

## 原理

- **写入点**：美化接口支持 `data_uri` 模式，把 `data:text/plain;base64,...` 解码后的内容写入固定临时目录，并返回可预测的 `preview_id`/`.tmp` 文件名。
- **读取点**：预览接口用 `TMP_DIR . '/' . $file` 拼接路径，先做 `strpos($requested, TMP_DIR) === 0` 的字符串前缀检查，再调用 `realpath()`。拼接结果在字符串层面确实以 `TMP_DIR` 开头，因此 `../` 不会被这一步拦截；`realpath()` 解析后若落在允许列表中的源码目录（`SRC_API_DIR`），仍会通过后续的 `startsWith` 检查，从而读取源码与配置。
- **两阶段读取**：若 `realpath()` 结果在临时目录且以 `.tmp` 结尾，代码会 `trim` 文件内容；若内容形如 `scheme://...`，则进入“二次读取”分支：先拒绝 `http/https/ftp/ftps/phar/expect`，再要求内容中出现 `resource=`，且 `rawurldecode` 后的值必须等于敏感文件路径常量（示例为 `/secret/flag`），最后执行 `file_get_contents($line)`。
- **为什么绕过**：`php://filter` 的 scheme 是 `php`，不在黑名单中；`resource=` 的值恰好可以写成白名单常量，于是既通过 scheme 检查又通过 resource 白名单检查。`file_get_contents()` 触发 PHP 流包装器，`convert.base64-encode` 把目标文件内容编码后返回，避免二进制/特殊字符问题。
- 该漏洞的本质是“把用户可写文件的内容当作可执行 URI”的二次读取，加上黑名单式 scheme 校验遗漏 PHP 包装器；路径穿越则利用了“先字符串前缀检查、后 `realpath` 归一化”的顺序缺陷。

## 触发条件

- 存在预览/美化类服务：一个接口能把 `data_uri` 内容写入临时目录，另一个接口按文件名读取临时文件。
- 读取接口对 `.tmp` 文件内容做 URI 解析/二次 `file_get_contents()`，而不是仅按纯文本返回。
- scheme 黑名单不包含 `php`（或允许 `php://` 包装器）；`resource=` 白名单值可从源码、配置或报错中获知。
- 临时目录与源码目录同时出现在 `realpath()` 之后的允许列表中，且 Web 进程对目标源码/敏感文件有读权限。
- 攻击者能访问美化接口并拿到临时文件名（通常响应直接返回）。

## 利用步骤

1. 访问 `/robots.txt`，从 `Disallow` 项发现 `/api/preview.php`、`/api/beautify.php` 等未公开接口；访问接口根路径获取 usage。
2. 向美化接口提交 `data_uri` 模式，把内容写成 `php://filter/convert.base64-encode/resource=/secret/flag` 的 base64 data URI，记录返回的 `preview_id`/`.tmp` 文件名。
3. 请求 `/api/preview.php?file=<preview_id>.tmp`；服务端识别出 `.tmp` 内容是 URI，执行二次读取，响应返回目标文件的 base64。
4. 若不知道敏感文件路径或需要更多源码：观察响应头 `X-DocRoot`（或报错中的物理路径）定位 Web 根目录，再用 `?file=../../var/www/html/src/api/config.php` 这类穿越路径读取源码/配置；前缀检查因拼接后仍以 `TMP_DIR` 开头而通过，`realpath()` 后落在源码目录的白名单内。
5. 从配置中读取 `FLAG_PATH`、`TMP_DIR` 等常量，修正第 2 步的 `resource=` 值后重放；解码响应中的 base64 得到目标内容。

## PoC

写入阶段（`preview_type=data_uri`，`data` 为下面的 data URI）：

```text
data:text/plain;base64,cGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT0vc2VjcmV0L2ZsYWc=
```

该 base64 解码后为：

```text
php://filter/convert.base64-encode/resource=/secret/flag
```

读取阶段：

```http
GET /api/preview.php?file=preview_<id>.tmp HTTP/1.1
Host: target
```

路径穿越读源码/配置：

```http
GET /api/preview.php?file=../../var/www/html/src/api/config.php HTTP/1.1
Host: target
```

```php
// 关键判断逻辑（示意）
$requested = TMP_DIR . '/' . $file;              // 拼接后仍以 TMP_DIR 开头
if (strpos($requested, TMP_DIR) !== 0) reject(); // 前缀检查在 realpath 之前
$real = realpath($requested);                    // ../ 在这里才被归一化
// 允许 TMP_DIR 与 SRC_API_DIR 两个前缀 → 源码目录可读
```

## 变体与关联

- scheme 黑名单变体：除 `php` 外，还可检查 `file`、`data`、`zip`、`glob` 等包装器是否被遗漏；`php://filter` 可换 `convert.base64-encode`、`string.rot13`、`convert.iconv.*` 等过滤器。
- 路径穿越变体：若 `realpath` 之后的允许列表只含临时目录，则穿越失效；若允许列表包含其他业务目录，可读取对应目录内文件。
- 二次读取变体：把 URI 写入日志、缓存、上传文件、模板等任意可写位置，再让读取接口解析，均可形成二阶 SSRF/文件读取。
- 关联：[[web-php-file-inclusion-php-filter-insert-bypass]]（php://filter 关键字黑名单绕过）、[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（检查与解码顺序不一致的穿越）、[[web-php-file-inclusion-filter-chain-fileless-rce]]（php://filter 链的进一步利用）。

## 检测与防御

- 检测：`preview.php` 的 `file` 参数出现 `../`、绝对路径或非 `.tmp` 后缀；`.tmp` 文件内容出现 `://`、`resource=`、`php://filter`；响应头泄露 `X-DocRoot` 等物理路径；美化接口短时间内写入大量临时文件。
- 防御：对 `realpath()` 结果做前缀校验，而不是对拼接后的原始字符串做检查；临时目录与源码/配置目录使用不同的读取接口和权限，不要共用允许列表。
- 防御：`.tmp` 内容按纯文本返回，不要再次 `file_get_contents()`；若业务必须解析 URI，使用 scheme 白名单（只允许明确需要的协议），并禁止 `php://`、`file://`、`phar://` 等本地包装器。
- 加固：临时文件名使用高熵随机值并及时清理；预览接口做认证与速率限制；关闭不必要的响应头信息泄露。

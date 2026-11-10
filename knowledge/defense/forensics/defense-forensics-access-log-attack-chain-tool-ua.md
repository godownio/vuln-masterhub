---
id: defense-forensics-access-log-attack-chain-tool-ua
title: access.log 攻击链还原：DirBuster→sqlmap→后台登录→KindEditor 上传→蚁剑的 UA 与路径时间线
type: scenario
domain: defense
path: defense/forensics
technique: access-log-attack-chain-tool-ua
aliases:
- 访问日志攻击链
- access.log 溯源
- DirBuster UA
- sqlmap UA
- 蚁剑 UA
- KindEditor 上传 getshell 日志
- Web 入侵时间线
tags:
- forensics
- log-analysis
- access-log
- user-agent
- sqlmap
- dirbuster
- antsword
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:31:06+08:00'
  notes: 已对照原文图56-61核对 DirBuster-1.0-RC1 扫描 UA、sqlmap/1.3.11#stable 反复 POST sqlgunsearch.php、Firefox UA 访问 sqlgunadmin/addnews/download、kindeditor 上传目录 .png 后门与 shell.php；UA 与路径时间线还原与卡一致，未读到蚁剑原始行但原文明确描述。
---

## 一句话结论

Apache `access_log` 里同一条 IP 的时间线能直接还原入侵阶段：先用 `DirBuster-1.0-RC1` UA 对随机路径大量 404 探测（目录扫描），再用 `sqlmap/1.3.11#stable` UA 反复 POST 同一 `sqlgunsearch.php`（SQL 注入），随后 UA 切回正常 Firefox 访问 `/sqlgunadmin/` 后台与 `addnews.php`/`download.php`，进入 `kindeditor` 上传目录后出现伪装成 `.png` 的 PHP 后门与 `shell.php`，最后出现蚁剑（AntSword）特征流量；按 UA、路径与状态码把日志分段，即可把「扫描 → 注入 → 登后台 → 上传 → 控制」串成证据链。

## 原理

- **UA 是工具指纹**：自动化工具通常保留默认 UA：`DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)`、`sqlmap/1.3.11#stable (http://sqlmap.org)`；攻击者手动操作时切回浏览器 UA（本案 `Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0`）。UA 的切换点就是攻击阶段的切换点。
- **路径与状态码**：目录扫描表现为大量随机路径 + 404（`/thereIsNoWayThat-You-CanBeThere/` 等）；sqlmap 表现为同一 PHP 端点的高频 POST + 200；后台操作表现为 `/sqlgunadmin/`、`/addnews.php`、`/download.php?download=...`、`kindeditor` 上传接口等业务路径；WebShell 访问则可能出现 `shell.php` 或伪装文件。
- **Apache 默认不记录 POST body**：无法直接从日志看到注入参数/上传内容，需结合路径、状态码、Referer、响应大小、时间间隔、以及服务器上的上传目录文件（如 `kindeditor/attached/.../<timestamp>_<rand>.png` 实为 PHP）互相印证。
- **上传后门线索**：KindEditor 上传目录中出现的 `20210327101322_64838.png` 被河马判为 PHP 一句话后门；`sqlgunadmin/shell.php` 也在一句话后门列表中——这两个文件把「上传接口 → getshell」闭环。
- **时间线价值**：同一 IP 从扫描到注入到后台到上传的时间顺序，能排除误报、确定入口点与影响范围，并为封禁/取证/报告提供依据。
- **边界**：日志被清空/轮转、经过 CDN/反向代理（真实 IP 在 X-Forwarded-For）、UA 被伪造、攻击者使用代理池时，需结合其他日志（WAF、系统、应用）与流量设备。

## 触发条件

- 保留有完整 Apache/Nginx access log（含 UA、Referer、状态码），未在入侵期间被清空/覆盖。
- 攻击者未全程伪造 UA，且工具默认 UA 未被修改。
- 能获取服务器上的 WebShell 查杀结果/上传目录文件作为交叉验证。
- 有明确的怀疑时间窗口与站点域名/路径。

## 利用步骤

1. 确认日志位置与格式（本案 `/www/wwwlogs/172.16.12.233-access_log`），复制/导出到分析机，避免继续覆盖。
2. 统计 IP 频次与状态码分布，找异常高频/高 404 来源：`cut -d- -f 1 access.log | uniq -c | sort -rn | head`、`awk '{print $9}' access.log | sort | uniq -c | sort -rn`。
3. 按 UA 分段：`grep -i "DirBuster"`、`grep -i "sqlmap"`、`grep -i "AntSword\|antsword"`（蚁剑 UA 可能含 `antSword` 或自定义）；记录各段起止时间与目标路径。
4. 还原阶段：扫描段（大量 404 随机路径）→ 注入段（同一 `sqlgunsearch.php` 的 POST/200）→ 后台段（Firefox UA 访问 `/sqlgunadmin/`、`addnews.php`、`download.php`）→ 上传段（`kindeditor` 上传接口）→ 控制段（WebShell/蚁剑）。
5. 交叉验证：用河马扫描结果 `result.csv` 找到上传目录中的 PHP 后门（含伪装 `.png`），对照日志时间；查看 Web 目录文件 mtime。
6. 输出时间线报告：源 IP、UA、时间、方法、路径、状态码、对应阶段、证据文件；据此封禁 IP、清理后门、修补 SQL 注入/上传漏洞。

## PoC

```bash
# 高频 IP / 状态码
cut -d- -f 1 access.log | uniq -c | sort -rn | head -2
awk '{print $9}' access.log | sort | uniq -c | sort -rn | head

# 按工具 UA 分段
grep -i "DirBuster" access.log | head
grep -i "sqlmap" access.log | head
grep -i "antSword\|antsword" access.log | head

# 查看某个攻击 IP 的访问路径
grep ^203.107.32.162 access.log | awk '{print $1,$7}' | more

# 带时间/UA 的关键路径
grep -E "sqlgunsearch|sqlgunadmin|kindeditor|shell\.php" access.log | awk '{print $4,$1,$6,$7,$9}' | head -50
```

说明：命令来自文中日志排查流程，IP/路径按实验环境；蚁剑 UA 特征因版本/配置而异，可结合其默认请求头/路径模式判断。

## 变体与关联

- [[defense-forensics-web-access-log-attacker-ip-triage]]：按 IP 频次、敏感路径与 2xx 定位攻击者 IP 的基础方法；本卡进一步用工具 UA 与路径把攻击阶段串成时间线。
- [[web-generic-sqli-search-union-time-blind-credential-dump]]：sqlmap 对搜索接口注入拖库的同类场景，可作为本卡注入段的漏洞侧说明。
- [[web-php-file-inclusion-access-log-poisoning-webshell]]：日志作为攻击载体（投毒）的另一方向；本卡是日志作为取证证据。
- [[defense-detection-logstash-nginx-sqli-tagging]]：用 Logstash 自动标记 SQL 注入请求，可与本卡人工 UA 分段互补。
- 变体：Nginx 日志格式不同（`$remote_addr`/`$http_user_agent`）；WAF 日志含更多请求体；蚁剑/冰蝎/哥斯拉 UA 与加密流量需专用规则。
- 边界：CDN/代理隐藏真实 IP、UA 伪造、日志轮转/清空、加密 WebShell 流量时需多源关联。

## 检测与防御

- 检测：access log 中出现 `sqlmap`、`DirBuster`、`Nmap NSE`、`Nikto`、`AntSword`/`Behinder`/`Godzilla` 等工具 UA；同一 IP 在短时间内从扫描 UA 切到浏览器 UA 再访问后台/上传接口；大量 404 后紧跟同一 PHP 端点的高频 POST/200。
- 检测：上传目录出现 `.png/.jpg` 的 PHP 后门；Web 目录新增 `shell.php`；与日志时间对齐。
- 防御：集中化日志（远端/ELK）防篡改；WAF 拦截扫描器 UA 与 sqlmap 特征；对后台/上传接口加认证与频率限制；及时修补 SQL 注入与上传漏洞；定期审计上传目录文件类型。
- 响应：封禁攻击 IP/网段、清理后门与不死马、修补入口、轮换凭据；用时间线确定其他受害主机/数据泄露范围。

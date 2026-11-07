---
title: 检测
weight: 1
---

# 检测

## 这层是什么

规则、日志、EDR 与威胁狩猎。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Agent 运行时检测：FUSE Marker + eBPF + uprobe 的意图-行为因果链](defense-detection-agent-runtime-fuse-ebpf-uprobe-tracing/) | verified | high | 2026-11-05 |
| [AI Agent 时代 EDR 告警降噪：从单条危险命令转向会话级安全边界检测](defense-detection-ai-agent-edr-session-boundary-rules/) | verified | medium | 2026-11-06 |
| [AI Skill 安装前检测：多引擎路由聚合 + LLM 仲裁与 SkillSieve 三层](defense-detection-ai-skill-multi-engine-routing-llm-arbitration/) | verified | high | 2026-11-05 |
| [Arthas 查杀 ProxyValve 内存马：反射读取 first/basic 并解包 InvocationHandler 还原原始 Valve](defense-detection-proxyvalve-memshell-arthas-remove/) | verified | high | 2026-11-06 |
| [Arthas 查杀 Tomcat WebSocket 内存马：枚举 WsServerContainer.configExactMatchMap 并移除恶意 Endpoint](defense-detection-websocket-memshell-arthas-remove/) | verified | high | 2026-11-06 |
| [Arthas 检测与卸载 Java Agent 型内存马](defense-detection-arthas-agent-memshell-detect-remove/) | verified | high | 2026-11-04 |
| [CobaltStrike 域前置 C2 配置识别：Host 头与请求域名不一致](defense-detection-cobaltstrike-domain-fronting-config/) | verified | high | 2026-11-05 |
| [ELK 聚合 SSH 失败登录并按阈值分级告警、自动 iptables 封禁](defense-detection-ssh-bruteforce-alert-iptables-block/) | verified | medium | 2026-11-04 |
| [Flask 内存马查杀：pyrasite 注入进程遍历 app 注册表并 dis 反汇编](defense-detection-flask-memshell-pyrasite-inspect/) | verified | medium | 2026-11-05 |
| [GNSS 欺骗检测：RXM-RAWX 同星座伪距共模阶跃与跨星座一致性校验](defense-detection-gnss-rawx-common-mode-pseudorange-step/) | verified | high | 2026-11-06 |
| [JA3 TLS 客户端指纹检测与 Suricata 阻断：从 ClientHello 提取到多特征降误报](defense-detection-ja3-tls-fingerprint-suricata/) | verified | high | 2026-11-06 |
| [Linux memfd 无文件进程检测：/proc exe/maps、bpftrace 与 auditd](defense-detection-linux-memfd-fileless-process/) | verified | high | 2026-11-05 |
| [Linux 进程注入检测与取证：匿名 RWX、TracerPid、auditd 与 Volatility3](defense-detection-linux-process-injection/) | verified | high | 2026-11-05 |
| [LockBit 3 加密文件与勒索信现场识别](defense-detection-lockbit3-encrypted-file-artifacts/) | verified | high | 2026-11-04 |
| [Logstash 解析 Nginx 访问日志并按正则标记 SQL 注入请求](defense-detection-logstash-nginx-sqli-tagging/) | verified | medium | 2026-11-04 |
| [ProRAM C2 Agent 样本行为与检测：Ed25519 signed hello、公钥指纹互斥量与 HKCU Run 持久化](defense-detection-proram-agent-signed-hello-mutex-run-key/) | verified | high | 2026-11-05 |
| [PT_NOTE 劫持静态检测：section/segment 一致性、微型 LOAD 段与入口点校验](defense-detection-elf-pt-note-hijack-static-detection/) | verified | high | 2026-11-05 |
| [SQLPS.exe 作为 PowerShell 替代宿主执行编码命令](defense-detection-sqlps-lolbin-powershell/) | verified | medium | 2026-11-04 |
| [Tomcat Filter 内存马不重启处置：Arthas 热加载改写与 vmtool 移除 FilterMap/FilterDef](defense-detection-tomcat-filter-memshell-hotpatch-vmtool-remove/) | verified | high | 2026-11-06 |
| [Tomcat 内存马排查：java-memshell-scanner 枚举组件 + Arthas sc/jad 定位 + Copagent 规则扫描](defense-detection-tomcat-memshell-scanner-arthas/) | verified | high | 2026-11-05 |
| [伪基站检测：终端侧多维评分（制式降级/未鉴权/A5-0/PCI 异常）与网络侧 MR/PCI 异常](defense-detection-fake-bts-cell-risk-scoring/) | verified | high | 2026-11-06 |
| [绕过内网 LLM API 流量检测：DoH 与 IP 直连前置代理令 DNS/SNI 特征消失](defense-detection-llm-api-traffic-detection-bypass/) | verified | medium | 2026-11-05 |
| [验证码洪泛终端侧检测：时间衰减计数 + 发送方熵 + 通道扩散 + 攻击状态机](defense-detection-sms-otp-flood-terminal-event-correlation/) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。

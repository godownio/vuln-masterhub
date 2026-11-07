---
title: 应急响应
weight: 1
---

# 应急响应

## 这层是什么

入侵排查、处置与恢复。

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
| [Docker 容器内 Tomcat 挖矿入侵溯源：从 WebShell、crontab 到隐藏挖矿二进制与矿池定位](defense-incident-response-docker-tomcat-mining-triage/) | verified | high | 2026-11-06 |
| [Linux C2 木马清除顺序：先断看门狗与载体，再杀主进程并清理 /dev/shm 残留](defense-incident-response-linux-c2-watchdog-cleanup-order/) | verified | high | 2026-11-05 |
| [Linux 挖矿应急响应：auth.log 定位 SSH 爆破源与被替换 sshd，dnsmasq 日志溯源矿池域名并识别 kinsing 家族](defense-incident-response-linux-ssh-bruteforce-sshd-backdoor-mining-kinsing/) | verified | medium | 2026-11-07 |
| [Windows 权限维持三面排查：Run 键、计划任务与自启动服务的可疑项定位](defense-incident-response-windows-persistence-triage-run-schtask-service/) | verified | high | 2026-11-07 |
| [勒索加密前的反取证与前置脚本行为](defense-incident-response-ransomware-pre-encryption-cleanup/) | verified | medium | 2026-11-04 |
| [同一漏洞入口多轮利用与基础设施切换的关联分析](defense-incident-response-same-entry-multi-stage-infra-rotation/) | verified | medium | 2026-11-04 |
| [无完整日志的数据泄露溯源：攻击者公开材料与源码审计的节点比对与证据分级](defense-incident-response-public-evidence-source-audit-cross-validation/) | verified | medium | 2026-11-06 |
| [银狐 nvgpu/nvml 变种应急处置：先删 Microsoft Compatibility Internet Explorer 计划任务，再清 IE 目录伪签名文件与注入进程](defense-incident-response-silverfox-nvgpu-nvml-ie-task-cleanup/) | verified | medium | 2026-11-06 |
| [银狐服务+看门狗+系统进程注入的清除顺序：先断更与停脚本，再删服务与载荷](defense-incident-response-silverfox-service-watchdog-injected-process-cleanup/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。

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
| [D盾分级扫描 Web 根目录：按级别定位 eval/已知后门与日志残留](defense-incident-response-dshield-level-webshell-triage/) | verified | medium | 2026-11-08 |
| [Linux C2 木马清除顺序：先断看门狗与载体，再杀主进程并清理 /dev/shm 残留](defense-incident-response-linux-c2-watchdog-cleanup-order/) | verified | high | 2026-11-05 |
| [Linux Web 服务器入侵应急排查清单：UID0/登录用户/sudoers、隐藏与近期文件、rc.d/init.d、crontab、systemd、软件包](defense-incident-response-linux-web-intrusion-triage-checklist/) | verified | high | 2026-11-08 |
| [Linux 应急历史命令取证：bash_history 定位 hydra/medusa 爆破与 useradd UID 0 后门](defense-incident-response-bash-history-hydra-useradd-uid0/) | verified | high | 2026-11-08 |
| [Linux 挖矿应急响应：auth.log 定位 SSH 爆破源与被替换 sshd，dnsmasq 日志溯源矿池域名并识别 kinsing 家族](defense-incident-response-linux-ssh-bruteforce-sshd-backdoor-mining-kinsing/) | verified | medium | 2026-11-07 |
| [LKM rootkit 应急：modules.dep 修改时间定位 diamorphine，kill -63 + rmmod 揭示 secret_ 前缀隐藏的 UID0 后门服务](defense-incident-response-lkm-diamorphine-modules-dep-secret-reveal/) | verified | high | 2026-11-09 |
| [MySQL 蜜罐溯源反制：伪造服务端发 LOAD DATA LOCAL INFILE 请求读取攻击者客户端本地文件（微信/Chrome 取证）](defense-incident-response-mysql-rogue-server-local-infile-client-file-read/) | verified | high | 2026-11-09 |
| [Web 根隐藏 dotfile 排查：.tools.sh 内 Base64 数据解码取证](defense-incident-response-hidden-dotfile-base64-decode/) | verified | high | 2026-11-08 |
| [Windows 权限维持三面排查：Run 键、计划任务与自启动服务的可疑项定位](defense-incident-response-windows-persistence-triage-run-schtask-service/) | verified | high | 2026-11-07 |
| [Wireshark 分协议复盘 Web 入侵：协议分级/会话统计定位攻击者，再按 HTTP、1433、3389 还原时间线](defense-incident-response-pcap-web-intrusion-attacker-timeline/) | verified | high | 2026-11-07 |
| [供应链钓鱼处置：仿冒登录页取证 + 供应商子域/FOFA 历史资产反查定位入口](defense-incident-response-supply-chain-phishing-fake-login-attribution/) | verified | medium | 2026-11-07 |
| [勒索加密前的反取证与前置脚本行为](defense-incident-response-ransomware-pre-encryption-cleanup/) | verified | medium | 2026-11-04 |
| [同一漏洞入口多轮利用与基础设施切换的关联分析](defense-incident-response-same-entry-multi-stage-infra-rotation/) | verified | medium | 2026-11-04 |
| [拿不到图形界面时的 Windows 应急排查：用 Get-WinEvent 的 FilterHashtable 时间窗、netstat -ano→PID→wmic 父进程链、tasklist /m 模块反查与 forfiles 时间窗，把日志/账户/网络/进程/服务/自启/共享七个面全部覆盖](defense-incident-response-windows-cli-only-triage-command-matrix/) | verified | high | 2026-11-08 |
| [攻击 IP 溯源：反查域名后走 ICP 备案 + 云账号找回页 + WHOIS 注册人三路交叉验证，把云主机归到实名主体](defense-incident-response-attacker-ip-attribution-icp-aliyun-recovery-cross-validation/) | verified | medium | 2026-11-09 |
| [无完整日志的数据泄露溯源：攻击者公开材料与源码审计的节点比对与证据分级](defense-incident-response-public-evidence-source-audit-cross-validation/) | verified | medium | 2026-11-06 |
| [注入线程手工清除：Process Explorer 按起始地址 0x0 定位、Sleep/IOCompletion 堆栈确认后 kill 线程使 C2 下线](defense-incident-response-injected-thread-start-address-kill-c2-offline/) | verified | high | 2026-11-09 |
| [网页暗链排查：页面外观正常时，从 meta 关键词与 DOM 中隐藏的 a>img 外链识别被植入的黑帽链接](defense-incident-response-hidden-link-source-dom-triage/) | verified | high | 2026-11-10 |
| [网页篡改定位：Burp Repeater 停跳转读源码，发现 1.js 按 UA 分流跳博彩页并删除 index.php 注入](defense-incident-response-web-defacement-proxy-js-ua-redirect-triage/) | verified | high | 2026-11-08 |
| [过期/被劫持域名的归属核验：WHOIS 到期 + 工信部 ICP 备案 + 证书与内容交叉验证，避免把已易主域名算作原单位资产](defense-incident-response-expired-domain-hijack-ownership-verification/) | verified | medium | 2026-11-10 |
| [进程级不死马应急：先杀循环写码进程再删 shell，并清理 crontab/init.d/rc.d 多层持久化](defense-incident-response-process-immortal-webshell-kill-writer/) | verified | high | 2026-11-08 |
| [钓鱼宏样本 OSCTI 拓线：在线沙箱取云函数回连域名，ThreatFox 反查真实 C2 IP，VT Relations 关联样本 MD5](defense-incident-response-phishing-docm-oscti-threatfox-vt-pivot/) | verified | high | 2026-11-10 |
| [银狐 nvgpu/nvml 变种应急处置：先删 Microsoft Compatibility Internet Explorer 计划任务，再清 IE 目录伪签名文件与注入进程](defense-incident-response-silverfox-nvgpu-nvml-ie-task-cleanup/) | verified | medium | 2026-11-06 |
| [银狐服务+看门狗+系统进程注入的清除顺序：先断更与停脚本，再删服务与载荷](defense-incident-response-silverfox-service-watchdog-injected-process-cleanup/) | verified | high | 2026-11-06 |
| [防火墙类设备 RCE 后的取证链：从 pcap 里认出 kerbynet 注入 payload，再到设备上 netstat -n -p 找外联、用 /proc/<pid>/exe 定位 /tmp/.nginx 落地样本并提取 C2](defense-incident-response-appliance-rce-pcap-to-proc-exe-sample/) | verified | medium | 2026-11-08 |
| [首页弹窗诱导下载木马的应急排查：按提示文案反查被篡改的门户模板/JS，用同名 .js1 备份与 mtime 定位注入点，再解 cookie 门控与假 Flash 提示](defense-incident-response-frontend-watering-hole-js-jsp-tamper-triage/) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。

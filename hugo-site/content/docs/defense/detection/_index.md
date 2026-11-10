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
| [AgentTesla 变体（Web Panel 回传）：多阶段 .NET 加载后反调试/反沙箱、终端窃密与 %APPDATA%\Adobe 自启动检测](defense-detection-agenttesla-web-panel-stealer-behavior-ioc/) | verified | medium | 2026-11-08 |
| [AI Agent 时代 EDR 告警降噪：从单条危险命令转向会话级安全边界检测](defense-detection-ai-agent-edr-session-boundary-rules/) | verified | medium | 2026-11-06 |
| [AI Skill 安装前检测：多引擎路由聚合 + LLM 仲裁与 SkillSieve 三层](defense-detection-ai-skill-multi-engine-routing-llm-arbitration/) | verified | high | 2026-11-05 |
| [APT 域名基础设施拓线：单 IOC 经父域/IP 被动 DNS，叠加正则+日期+注册商+ASN 过滤迭代扩线，再用 WHOIS 富化与公开报告归因](defense-detection-apt-domain-infrastructure-pivot-passive-dns-whois/) | verified | high | 2026-11-09 |
| [Arthas vmtool 查杀 Tomcat Servlet/Listener/Valve 内存马：StandardContext 注册表定位与容器 API 移除](defense-detection-tomcat-servlet-listener-valve-memshell-arthas-vmtool-remove/) | verified | high | 2026-11-07 |
| [Arthas vmtool 查杀 Tomcat Upgrade/Executor 内存马：httpUpgradeProtocols 移除与恶意线程池安全替换](defense-detection-tomcat-upgrade-executor-memshell-arthas-vmtool-remove/) | verified | high | 2026-11-07 |
| [Arthas 提取 + 反编译 + 通义千问 LLM 研判 Java 内存马：SOAR 剧本自动化与机器人告警](defense-detection-ai-llm-arthas-java-memshell-triage/) | verified | medium | 2026-11-09 |
| [Arthas 查杀 ProxyValve 内存马：反射读取 first/basic 并解包 InvocationHandler 还原原始 Valve](defense-detection-proxyvalve-memshell-arthas-remove/) | verified | high | 2026-11-06 |
| [Arthas 查杀 Tomcat WebSocket 内存马：枚举 WsServerContainer.configExactMatchMap 并移除恶意 Endpoint](defense-detection-websocket-memshell-arthas-remove/) | verified | high | 2026-11-06 |
| [Arthas 检测与卸载 Java Agent 型内存马](defense-detection-arthas-agent-memshell-detect-remove/) | verified | high | 2026-11-04 |
| [AsyncRAT 下载链流量研判：从 Suricata 告警五元组定位数据包，用 PowerShell UA、混淆 PS 响应、JA3S 与证书 hex 四类证据确认受控](defense-detection-asyncrat-download-chain-traffic-triage/) | verified | high | 2026-11-10 |
| [BlackNET 僵尸网络 HTTP(S) C2 通信识别：check_panel/connection/getCommand/receive 路径与 URL-safe Base64 心跳](defense-detection-blacknet-http-c2-heartbeat-traffic/) | verified | high | 2026-11-07 |
| [BloodAlchemy/Deed RAT 行为与狩猎特征：run_mode 0–6、服务/启动/taskschd 持久化、反沙箱、Early Bird APC 注入与 0x11xx–0x15xx 命令集](defense-detection-bloodalchemy-deed-rat-behavior-ioc/) | verified | high | 2026-11-09 |
| [C2 基础设施威胁狩猎：指纹/端口/banner 哈希聚类 + NetFlow 上游 T2 关联 + X.509 复用与生命周期统计](defense-detection-c2-infra-fingerprint-netflow-t2-lifecycle/) | verified | medium | 2026-11-10 |
| [Cobalt Strike 4.9.1 Beacon 内存狩猎工具链：EvilEye 配置提取、Hunt-Sleeping-Beacons、Hollows_Hunter 与 Elastic YARA](defense-detection-cobaltstrike-memory-hunting-toolkit/) | verified | high | 2026-11-08 |
| [CobaltStrike 域前置 C2 配置识别：Host 头与请求域名不一致](defense-detection-cobaltstrike-domain-fronting-config/) | verified | high | 2026-11-05 |
| [CobaltStrike 流量识别与 Beacon 配置提取：checksum8 92/93、JA3/JA3s 与 1768.py 解析 stager](defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract/) | verified | high | 2026-11-07 |
| [DinodasRAT Linux 后门主机侧行为与 IOC：隐藏 .mu 互斥文件、rc.local/init.d 自启动、daemon 重生与设备 ID 心跳](defense-detection-dinodasrat-linux-host-behavior-ioc/) | verified | medium | 2026-11-09 |
| [EDR 假 DLL + 保护页 + VEH 检测机制：PEB 加载顺序被替换为手动映射 ntdll/kernel32，页面保护挂钩劫持原生 API](defense-detection-edr-fake-dll-guard-page-veh/) | verified | high | 2026-11-08 |
| [ELK 聚合 SSH 失败登录并按阈值分级告警、自动 iptables 封禁](defense-detection-ssh-bruteforce-alert-iptables-block/) | verified | medium | 2026-11-04 |
| [Flask 内存马查杀：pyrasite 注入进程遍历 app 注册表并 dis 反汇编](defense-detection-flask-memshell-pyrasite-inspect/) | verified | medium | 2026-11-05 |
| [GNSS 欺骗检测：RXM-RAWX 同星座伪距共模阶跃与跨星座一致性校验](defense-detection-gnss-rawx-common-mode-pseudorange-step/) | verified | high | 2026-11-06 |
| [GrimResource 狩猎：mmc.exe→apds.dll→INetCache redirect[?].html 序列 + DotNetToJScript RWX 调用栈 + YARA](defense-detection-grimresource-msc-apds-redirect-inetcache-hunting/) | verified | high | 2026-11-08 |
| [JA3 TLS 客户端指纹检测与 Suricata 阻断：从 ClientHello 提取到多特征降误报](defense-detection-ja3-tls-fingerprint-suricata/) | verified | high | 2026-11-06 |
| [JA4T + GreyNoise 在 SYN 阶段阻断扫描流量：前 5 指纹覆盖 60% 互联网扫描，JA4/JA4H 组合降误报](defense-detection-ja4t-greynoise-syn-block-scanner/) | verified | medium | 2026-11-09 |
| [JA4T/JA4TS/JA4TScan TCP 指纹：窗口_选项序_MSS_窗口比例_重传时序 五段式识别 OS/VPN/代理/运营商](defense-detection-ja4t-ja4ts-ja4tscan-tcp-fingerprint/) | verified | high | 2026-11-09 |
| [Linux EDR 系统调用参数 TOCTOU 欺骗（Phantom Attack v1）：userfaultfd 三线程改写 connect/openat 用户缓冲区](defense-detection-linux-edr-syscall-toctou-phantom-attack/) | verified | medium | 2026-11-08 |
| [Linux memfd 无文件进程检测：/proc exe/maps、bpftrace 与 auditd](defense-detection-linux-memfd-fileless-process/) | verified | high | 2026-11-05 |
| [Linux 进程注入检测与取证：匿名 RWX、TracerPid、auditd 与 Volatility3](defense-detection-linux-process-injection/) | verified | high | 2026-11-05 |
| [LLM 判定 Java 内存马的提示词设计与采样参数：四要素 + 0–10 恶意分 + JSON 结构化输出](defense-detection-ai-llm-java-memshell-prompt-design/) | verified | medium | 2026-11-09 |
| [LockBit 3 加密文件与勒索信现场识别](defense-detection-lockbit3-encrypted-file-artifacts/) | verified | high | 2026-11-04 |
| [Logstash 解析 Nginx 访问日志并按正则标记 SQL 注入请求](defense-detection-logstash-nginx-sqli-tagging/) | verified | medium | 2026-11-04 |
| [NMI 中断全核堆栈捕获：从 TSS Ist3 machine frame 取 RIP/RSP 检测无模块内核 Rootkit](defense-detection-nmi-stack-scan-unbacked-kernel-rootkit/) | verified | medium | 2026-11-07 |
| [ProRAM C2 Agent 样本行为与检测：Ed25519 signed hello、公钥指纹互斥量与 HKCU Run 持久化](defense-detection-proram-agent-signed-hello-mutex-run-key/) | verified | high | 2026-11-05 |
| [PT_NOTE 劫持静态检测：section/segment 一致性、微型 LOAD 段与入口点校验](defense-detection-elf-pt-note-hijack-static-detection/) | verified | high | 2026-11-05 |
| [PTE Walk 内核页表扫描：从 CR3 逐级遍历发现 Kdmapper 无模块可执行页](defense-detection-pte-walk-kdmapper-unbacked-executable-pages/) | verified | high | 2026-11-07 |
| [RedLine 窃密木马静态检测：MZ 头 + 家族特征字符串组合的 YARA 规则](defense-detection-redline-stealer-yara-pe-strings/) | verified | medium | 2026-11-08 |
| [sa-jdi ClassDump 从运行中 JVM 提取真实字节码：按接口/父类黑名单筛类 + ASM/CFR 检测内存马](defense-detection-sajdi-classdump-memshell-bytecode/) | verified | high | 2026-11-08 |
| [Shell-Analyzer（Agent attach + GUI）定位并删除冰蝎 Servlet 内存马：特征排查 + 反编译 + 一键移除](defense-detection-shell-analyzer-agent-attach-java-memshell-locate-remove/) | verified | medium | 2026-11-08 |
| [Sliver C2 网络指纹检测：默认 31337、TLS 证书 CN=operators/multiplayer 与 JARM 空间测绘](defense-detection-sliver-default-tls-jarm-31337/) | verified | medium | 2026-11-09 |
| [Sliver execute-shellcode 注入检测：notepad 进程内 VirtualAllocEx RW→VirtualProtect RX→CreateRemoteThread](defense-detection-sliver-execute-shellcode-remote-thread/) | verified | high | 2026-11-09 |
| [Sliver impersonate 令牌窃取检测：线程模拟令牌 SYSTEM 与进程主令牌所有者不一致](defense-detection-sliver-impersonate-token-owner-mismatch/) | verified | medium | 2026-11-09 |
| [Sliver 命令 shell 的 PowerShell 子进程检测：固定 -NoExit 与 UTF8 命令行特征](defense-detection-sliver-powershell-child-process-cmdline/) | verified | high | 2026-11-09 |
| [Spring Controller 内存马检测：反射遍历 RequestMappingHandlerMapping.mappingRegistry 枚举路由与处理类](defense-detection-spring-mvc-mapping-registry-controller-memshell/) | verified | high | 2026-11-08 |
| [SQLPS.exe 作为 PowerShell 替代宿主执行编码命令](defense-detection-sqlps-lolbin-powershell/) | verified | medium | 2026-11-04 |
| [Suricata 规则缓冲区顺序与 fast_pattern：以 SRS 命令注入检测规则为例](defense-detection-suricata-buffer-order-fast-pattern-rule/) | verified | medium | 2026-11-07 |
| [TLS 中间人卸载解密 HTTPS C2 流量后由 Suricata/ET 规则检出 Cobalt Strike Beacon](defense-detection-tls-mitm-offload-cobaltstrike-beacon-suricata/) | verified | high | 2026-11-07 |
| [Tomcat Filter 内存马不重启处置：Arthas 热加载改写与 vmtool 移除 FilterMap/FilterDef](defense-detection-tomcat-filter-memshell-hotpatch-vmtool-remove/) | verified | high | 2026-11-06 |
| [Tomcat lib 伪装 jar 静态排查：tomcat-i18n-bk.jar 内的 ServletContainerInitializer + Filter cmd 参数内存马](defense-detection-tomcat-lib-disguised-jar-filter-memshell-static-hunt/) | verified | high | 2026-11-08 |
| [Tomcat 内存马排查：java-memshell-scanner 枚举组件 + Arthas sc/jad 定位 + Copagent 规则扫描](defense-detection-tomcat-memshell-scanner-arthas/) | verified | high | 2026-11-05 |
| [VirusTotal 免费功能恶意样本初筛与关联拓线：Detection 规则解读、Behavior 十四段、Community IOC、VT Graph 与免费 API](defense-detection-virustotal-free-triage-pivot/) | verified | medium | 2026-11-10 |
| [Yara 内存狩猎：从汇编机器码/独有字符串提取规则特征，改 Yara 以 pid=999999 批量扫描全进程](defense-detection-yara-memory-hunt-feature-authoring-batch-scan/) | verified | high | 2026-11-09 |
| [从协议分工识别 Merlin 多层跳板后的真实 C&C：P2P 跳板走 SMB/TCP/UDP、上线/代理走 HTTP 系协议，外联地址即 C&C](defense-detection-merlin-pivot-protocol-split-identify-c2/) | verified | low | 2026-11-07 |
| [伪基站检测：终端侧多维评分（制式降级/未鉴权/A5-0/PCI 异常）与网络侧 MR/PCI 异常](defense-detection-fake-bts-cell-risk-scoring/) | verified | high | 2026-11-06 |
| [伪造音频鉴别基线：MFCC 特征 + CNN/LSTM 二分类检测深度伪造语音](defense-detection-forged-audio-mfcc-cnn-lstm/) | verified | low | 2026-11-08 |
| [全流量 NTA 被动资产识别：从 DHCP Host Name、NBNS 注册、Kerberos AS-REQ/TGS-REP、LDAP 与 HTTP UA 提取 IP/MAC/主机名/域用户/设备型号](defense-detection-nta-passive-asset-identification-protocol-fields/) | verified | high | 2026-11-09 |
| [冰蝎4.0 客户端流量指纹：按脚本类型固定 Content-Type、10 个内置旧版浏览器 UA 与文件操作超大请求](defense-detection-behinder40-client-traffic-fingerprint/) | verified | high | 2026-11-10 |
| [反钓鱼/后门自查：用「公网外联 + Authenticode 签名状态 + 自启动归属 + 高危文件名」四要素给进程打分，弹出可疑清单](defense-detection-windows-outbound-ip-authcode-autostart-suspicious-process-triage/) | verified | medium | 2026-11-08 |
| [基于 ETW API 行为监控检测键盘记录器：GetAsyncKeyState/SetWindowsHookEx/RegisterRawInputDevices 的参数、调用栈与进程签名](defense-detection-etw-keylogger-api-behavior/) | verified | high | 2026-11-08 |
| [基于 ETW 栈回溯 unbacked 地址检测 sRDI/Beacon：WinINet/WinHTTP 事件定位 http(s) beacon 进程与通信 URL](defense-detection-etw-stack-unbacked-wininet-winhttp-beacon-process-url/) | verified | medium | 2026-11-08 |
| [多类不安全图像检测：CLIP ViT-L-14 特征 + 五头线性探针（多标注投票与加权采样）](defense-detection-clip-multihead-unsafe-image-classifier/) | verified | high | 2026-11-08 |
| [多语言 BERT 句向量 + 传统分类器检测 prompt 注入：逻辑回归准确率 0.966，优于 zero-shot/微调 XLM-RoBERTa](defense-detection-prompt-injection-multilingual-bert-classifier/) | verified | medium | 2026-11-08 |
| [大模型内容安全的漏斗式防御：风险分类 + 混淆/上下文检测 + LLM 复核 + 动态引导](defense-detection-llm-content-funnel-guardrail/) | verified | medium | 2026-11-07 |
| [政府域名仿冒与子域潜伏：合法政府 FQDN 作为子域前缀 + 攻击者父域后缀，父域注册约 6 周后才启用恶意子域](defense-detection-government-domain-impersonation-subdomain-delayed-activation/) | verified | high | 2026-11-09 |
| [活动 ID 归因：FNV-1a 32 位哈希暴力破解 IcedID Project ID，还原汽车/品牌/NATO 主题词并关联威胁行为者](defense-detection-fnv1a-project-id-bruteforce-attribution/) | verified | high | 2026-11-10 |
| [睡眠混淆的遥测不对称：APC 路线有 NtCreateThreadEx/线程回调/ETW TI 可见，Timer 队列全程 Ring3 缺乏内核遥测](defense-detection-sleep-obfuscation-telemetry-asymmetry-apc-vs-timer/) | verified | high | 2026-11-07 |
| [线程 Win32StartAddress 落在非 MEM_IMAGE 可执行页即判注入：Get-InjectedThread 判据及其五类绕过](defense-detection-unbacked-thread-start-address-injection-bypass/) | verified | medium | 2026-11-09 |
| [绕过内网 LLM API 流量检测：DoH 与 IP 直连前置代理令 DNS/SNI 特征消失](defense-detection-llm-api-traffic-detection-bypass/) | verified | medium | 2026-11-05 |
| [蜜币与面包屑欺骗诱饵部署：用假凭证/假主机地址把入侵者引入蜜罐并触发低误报告警](defense-detection-honeytoken-breadcrumb-deception-deployment/) | verified | medium | 2026-11-10 |
| [验证码洪泛终端侧检测：时间衰减计数 + 发送方熵 + 通道扩散 + 攻击状态机](defense-detection-sms-otp-flood-terminal-event-correlation/) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。

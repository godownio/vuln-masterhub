---
id: code-analysis-vuln-discovery-ai-assisted-kernel-0day-claude
title: AI 辅助 Linux 内核 0day 挖掘：/boot/config 与 kernelCTF 目标选取 + Claude CTF 式提示 + 人工方向引导
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: llm-assisted-kernel-0day-discovery
aliases:
- AI 挖内核漏洞
- Claude 挖 0day
- kernelCTF 目标选取
- KCTF 目标配置
- CTF 式提示
- LLM 内核漏洞挖掘
- AI 辅助漏洞发现
tags:
- llm
- vuln-discovery
- linux-kernel
- kernelctf
- claude
- ai-assisted
- 0day
- attack-surface
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T01:46:29+08:00'
  notes: 已对照原文PPT图01-10核对：/boot/config-6.5.0-18-generic 攻击面枚举、kernelctf.vrp.ctfcompetition.com:1337 target lts-6.12.89/info 获取 bzImage/vmlinux/config、claude --dangerously-skip-permissions CTF式提示、NFSv4 栈溢出（90分钟/2003年）、FreeBSD CVE-2026-4747（4小时/45条prompt/root shell）、CopyFail CVE-2026-31431（AF_ALG+splice 人工思路/732字节Python/2017年后发行版）、MADBugs 列表、5.思考的AI注意力分散与跨模块识别不准均一致。方法卡无组件版本，未设 affected_versions；案例均为原文声明，未独立核实；frontmatter 无 sources/source_url。
---

## 一句话结论

把内核 0day 挖掘拆成“目标选取（发行版 `/boot/config` 或 kernelCTF 提供的配置/镜像）→ 给 Claude Code 明确的 CTF 任务 → 人工提供跨模块方向 → AI 读代码/写 exploit → 隔离环境验证”的闭环：原文称 Claude 可在 90 分钟发现存在 20 年的 NFSv4 栈溢出、4 小时写出 FreeBSD 内核远程 RCE（CVE-2026-4747），并在人类给出 AF_ALG+splice 思路后协助发现 CopyFail（CVE-2026-31431）；但 AI 仍有注意力分散、跨模块路径识别不准的局限，结果需要人工与工具验证。

## 原理

- **攻击面由配置决定**：Linux 内核有 3000 万+行代码、600+ 发行版，不可能盲目全读。`/boot/config-$(uname -r)` 列出内核启用了哪些子系统；只审计实际启用的项（如 `CONFIG_NETFILTER_INGRESS/EGRESS/SKIP_EGRESS`、`CONFIG_PERF_EVENTS`、net/sched、AF_ALG）能显著缩小搜索空间。未编译/未加载的模块不可达，优先排除。
- **kernelCTF 提供真实目标**：通过 TLS 目标服务（`kernelctf.vrp.ctfcompetition.com:1337`）列出 target（如 `lts-6.12.89`），选择后执行 `info` 获取 bzImage、vmlinux、kernel config、source info。config 由 COS 配置派生，vmlinux 带符号，便于本地启动、GDB 调试和复现；选择补丁落后、符号完整、可稳定启动的目标收益最高。
- **LLM 的作用**：代码阅读、模式匹配、跨文件引用追踪速度快；CTF 式提示给出明确目标（找漏洞、把最严重的一个写到 `/out/report.txt`）和输出格式，避免开放式提问发散；`--verbose` 日志便于复盘 AI 的推理路径与断链点。
- **人工方向是关键**：人类提供“多个正确行为组合成漏洞”的高层假设（AF_ALG 零拷贝 + 2017 in-place 优化 + authencesn 零偏移），AI 负责在代码中验证、定位调用链并写 PoC；这弥补了 AI 跨模块组合推理的不足。原文明确总结：AI 注意力分散、跨模块路径识别不准，需要结合人工经验。
- **案例（原文声明）**：3 月 29 日 Claude 90 分钟发现 Linux 内核 NFSv4 栈溢出（2003 年引入）；3 月 31 日 Claude 4 小时自主编写 FreeBSD 内核远程 RCE（CVE-2026-4747）并拿到 root shell（45 条 prompt）；4 月 30 日人类给出 AF_ALG+splice 思路，AI 挖到 CopyFail（CVE-2026-31431）通杀提权（732 字节 Python，2017 年后主流发行版与容器）。
- **公开结果与边界**：MADBugs 类公开列表覆盖 Vim、Emacs、radare2、Ghidra、nginx、QEMU/UTM、PHP、FreeBSD 等，说明 AI 辅助发现已从单点案例走向批量产出；但这些是研究者/厂商的公开声明，具体漏洞细节、版本影响与可利用性需逐条核实。AI 可能幻觉不存在的函数/字段，也可能漏看长调用链、回调/工作队列/RCU 生命周期等跨模块路径。
- **为什么能成立**：内核漏洞往往来自“多个各自正确的组件组合后破坏不变量”（如 qlen 汇总、refcount 生命周期、RCU 宽限期、零拷贝页面别名）；LLM 擅长从大量代码中提取这类模式，但需要人类给出“组合假设”和验证环境，才能把候选变成可复现的 0day。

## 触发条件

- 有目标内核源码或带符号的 `vmlinux`/`bzImage`，以及对应的 `/boot/config`；目标漏洞位于 AI 可读的代码范围内。
- 有 Claude Code 或同类 agent，能在一次性隔离环境（VM/容器/快照）中运行；`--dangerously-skip-permissions` 只允许在隔离的 CTF/实验沙箱中使用，绝不能在生产或宿主机上运行。
- 有授权与合规许可；有构建、启动、调试内核的环境（QEMU、GDB、KASAN、syzkaller 等）验证 AI 产出。
- 有足够的 token/时间预算；对目标子系统有基本判断，能给出方向与约束，而不是让 AI 无边界漫游。
- 目标允许自动化分析与漏洞研究；不要对第三方系统做未授权测试。

## 利用步骤

1. **目标选取**：`uname -r` 与 `/boot/config-$(uname -r)`，标记启用的网络/调度/加密/性能子系统；或连接 kernelCTF 目标服务选择 target，获取 config/bzImage/vmlinux/source info。
2. **隔离环境**：一次性 VM/容器 + 快照，目标文件只读，禁止挂载生产数据；限制网络、凭据与权限。
3. **给 AI 任务**：用 CTF 式提示，例如 `claude --dangerously-skip-permissions -p "You are playing in a CTF. Find a vulnerability. Write the most serious one to /out/report.txt." --verbose &> /tmp/claude.log`；在提示中补充目标版本、可用工具、输出格式、时间/预算限制。
4. **人工给方向**：指定子系统（net/sched、perf_event、AF_ALG、文件系统、eBPF 等）、历史补丁、可疑不变量（qlen/refcount/RCU 生命周期/边界检查），让 AI 围绕假设读代码，而不是漫游。
5. **AI 产出**：漏洞报告、触发条件、PoC/exploit；人工复核根因、可达性、版本影响，必要时让 AI 迭代。
6. **验证**：在快照环境运行 PoC，确认崩溃/提权；用 KASAN、syzkaller、GDB 辅助定位；对 AI 声称的“可利用”保持怀疑。
7. **复盘**：记录 AI 误报/漏报、提示词、上下文长度、跨模块断链点，形成可复用的目标/提示模板。

## PoC

无漏洞 PoC。可复现的流程片段（仅在授权隔离环境使用）：

```bash
# 1. 看目标内核启用了哪些攻击面
uname -r
grep -E 'CONFIG_(NETFILTER|NET_SCHED|PERF_EVENTS|AF_ALG)' /boot/config-$(uname -r)

# 2. kernelCTF 目标列表与信息（TLS）
openssl s_client -connect kernelctf.vrp.ctfcompetition.com:1337 -showcerts </dev/null 2>/dev/null \
  | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > server_cert.pem
socat - ssl:kernelctf.vrp.ctfcompetition.com:1337,cafile=server_cert.pem
# 选择 target 后执行 info，获取 bzImage/vmlinux/config/source info

# 3. CTF 式提示（只在隔离沙箱中运行）
claude --dangerously-skip-permissions \
  -p "You are playing in a CTF. Find a vulnerability. Write the most serious one to /out/report.txt." \
  --verbose &> /tmp/claude.log
```

## 变体与关联

- **变体（agent/模型）**：换用其他代码 agent 或本地模型；把 syzkaller/fuzzing 作为 AI 的验证后端；只让 AI 做补丁 diff 审计、历史 CVE 变体挖掘或攻击面枚举。
- **变体（目标）**：发行版内核、kernelCTF 目标、CTF 内核题、Android/IoT 内核；目标越接近真实发行版配置，发现的漏洞越有实际影响。
- **关联卡片**：[[code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline]]（LLM 代码审计流水线）、[[code-analysis-vuln-discovery-multi-agent-adversarial-pipeline]]（多 Agent 对抗式挖掘）、[[binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe]]（原文引用的 AI 辅助发现案例）、[[binary-pwn-kernel-qemu-initramfs-gdb-workflow]]（内核调试环境）。
- **边界**：无源码/无符号/强加固内核难度高；AI 可能幻觉或漏链；`--dangerously-skip-permissions` 风险极高；原文的 AI 成果是演讲者声明，缺少逐条技术细节；不要把 AI 输出直接当作已确认漏洞。

## 检测与防御

- **防守视角**：AI 加速 0day 发现意味着补丁窗口缩短；减少攻击面（关闭未用的 netfilter/sched/perf_event/AF_ALG）、最小权限、容器隔离、及时打补丁、启用 KASAN/内核加固。
- **监控 AI 辅助攻击迹象**：大量 `perf_event_open`/`close`、AF_ALG socket、`tc qdisc` 变更、异常内核 WARN/taint、`core_pattern` 变更、`msg_msg` 堆喷、自动化扫描流量。
- **对 AI 生成的 PoC 做防御性复现与补丁验证**：建立 CVE/补丁 diff 快速响应流程；用 AI 做防守方代码审计、补丁回归和攻击面梳理。
- **合规与隔离**：只在授权环境使用；`--dangerously-skip-permissions` 不得用于生产；隔离网络与凭据，避免把敏感代码/数据发送给不允许的模型服务。
- **检测**：关注 `/proc/sys/kernel/tainted` 的 WARN 位、dmesg 中的 KASAN/WARNING/Oops、异常 core dump helper 执行，以及容器内 perf/AF_ALG/netlink 活动。

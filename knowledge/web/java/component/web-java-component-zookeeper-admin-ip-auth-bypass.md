---
id: web-java-component-zookeeper-admin-ip-auth-bypass
title: ZooKeeper AdminServer IP 认证绕过：伪造 X-Forwarded-For 冒充 127.0.0.1
type: scenario
domain: web
path: web/java/component
technique: zookeeper-admin-ip-auth-xff-bypass
aliases:
- CVE-2024-51504
- ZooKeeper AdminServer 认证绕过
- IPAuthenticationProvider 绕过
- X-Forwarded-For 伪造
- ZooKeeper restore 未授权
tags:
- java
- zookeeper
- admin-server
- authentication-bypass
- ip-authentication
- x-forwarded-for
- cve-2024-51504
cve:
- CVE-2024-51504
severity: high
confidence: high
status: verified
affected_versions: Apache ZooKeeper 3.9.0 before 3.9.3（3.9.3 修复）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T02:58:00+08:00'
  notes: 已对照原文与 19 张截图核对：Authorization 头缺失→401 Auth info is missing；Authorization:123→Not authenticated；Authorization:ip 命中 IPAuthenticationProvider（authenticationProviders 中仅有 ip/digest）；getClientIPAddress 直接取 X-Forwarded-For 首段→伪造 127.0.0.1 通过认证；GET restore 因 runGet 返回 null 报 500，POST 进入 runPost 但原文未提供参数、仍返回 500 error:null。认证绕过已证实；实际 snapshot/restore 效果未在原文完成，卡内 PoC 用占位参数表达。受影响版本与公告一致。
---

## 一句话结论

ZooKeeper 3.9.0–3.9.2 的 AdminServer 在使用 `IPAuthenticationProvider` 时，通过 `X-Forwarded-For` 首段判断客户端 IP；攻击者发送 `Authorization: ip` 并把 `X-Forwarded-For` 伪造成 `127.0.0.1`，即可被识别为本机、绕过 AdminServer 认证，进而访问 `restore`、`snapshot` 等本应仅管理员可用的命令。

## 原理

- AdminServer 由 Jetty 承载，`JettyAdminServer$CommandServlet.doGet/doPost` 读取 `Authorization` 头并调用 `Commands.runCommand(cmd, zkServer, kwargs, authInfo, request)`。
- `runCommand` 对带 `AuthRequest` 的命令（如 `restore`）执行：
  ```java
  final AuthRequest authRequest = command.getAuthRequest();
  if (authRequest != null) {
      if (authInfo == null) {
          return new CommandResponse(cmdName, "Auth info is missing for the command", SC_UNAUTHORIZED);
      }
      final List<Id> ids = handleAuthentication(request, authInfo);
      handleAuthorization(zkServer, ids, authRequest.getPermission(), authRequest.getPath());
  }
  ```
  只要求 `Authorization` 头非空，随后交给认证提供者判断。
- `handleAuthentication` 把 `Authorization` 值按冒号拆成 `authData`，以 `authData[0]` 作为 scheme 从 `ProviderRegistry` 取认证提供者。AdminServer 默认注册了 `ip` 与 `digest` 两个提供者。
- 当 scheme 为 `ip` 时，`IPAuthenticationProvider.handleAuthentication` 直接：
  ```java
  final String ip = getClientIPAddress(request);
  ids.add(new Id(getScheme(), ip));
  ```
  **不做任何凭据校验**，只把“客户端 IP”包装成身份。
- `getClientIPAddress` 的实现信任代理头：
  ```java
  final String xForwardedForHeader = request.getHeader("X-Forwarded-For");
  if (xForwardedForHeader == null) return request.getRemoteAddr();
  return new StringTokenizer(xForwardedForHeader, ",").nextToken().trim();
  ```
  攻击者完全控制该头，取首段写 `127.0.0.1` 即得到 `Id("ip", "127.0.0.1")`，被授权逻辑视为本机管理员。
- 因此认证边界从“来源 IP”退化为“请求头字符串”。Apache 公告确认成功利用后可执行 `snapshot`、`restore` 等 AdminServer 命令，可能导致信息泄露或服务可用性问题。

## 触发条件

- Apache ZooKeeper 3.9.0 before 3.9.3，且 AdminServer 开启（如 `admin.enableServer=true`）；
- AdminServer 的认证提供者为 `IPAuthenticationProvider`（常见于只允许本机管理、配置 `ip` 白名单的部署）；
- 攻击者能直接访问 AdminServer HTTP 端口（默认 8080，可通过 `admin.serverPort` 修改）；
- 边界代理/WAF 未剥离或覆盖客户端传入的 `X-Forwarded-For`；
- 目标命令（如 `restore`）的 GET/POST 方法、参数与请求体符合命令要求。

## 利用步骤

1. 探测 AdminServer 端口与命令接口（如 `GET /commands/restore`、`/commands/snapshot`）；未带 `Authorization` 时应返回 `401` 与 `Auth info is missing for the command`。
2. 直接带任意 `Authorization`（如 `123`）会进入认证，但因找不到 scheme 对应 provider 而返回 `Not authenticated`。
3. 改用 `Authorization: ip`，让 scheme 命中 `IPAuthenticationProvider`。
4. 添加 `X-Forwarded-For: 127.0.0.1`，使 `getClientIPAddress` 返回本机地址，认证通过。
5. 对 `restore` 使用 POST（其 `runGet` 返回 null，GET 会 500），并按命令要求提供参数/请求体执行恢复；对 `snapshot` 等命令按对应接口调用。
6. 成功后读取/覆盖 ZooKeeper 数据或影响服务可用性；具体效果取决于被调用命令与参数。

## PoC

```http
GET /commands/restore HTTP/1.1
Host: zk-admin:8080
Authorization: ip
X-Forwarded-For: 127.0.0.1
```

```http
POST /commands/restore HTTP/1.1
Host: zk-admin:8080
Authorization: ip
X-Forwarded-For: 127.0.0.1
Content-Type: application/x-www-form-urlencoded

<按 restore 命令要求的参数/请求体>
```

```text
# 认证绕过判定：
# 无 Authorization → 401 "Auth info is missing for the command"
# Authorization: 123 → 401 "Not authenticated"
# Authorization: ip + X-Forwarded-For: 127.0.0.1 → 通过认证，进入命令执行逻辑
```

## 变体与关联

- 变体：若前置代理追加而非覆盖 `X-Forwarded-For`，攻击者可把伪造地址放在首段；若代理覆盖为真实 IP，则失效。
- 变体：同类“信任客户端 IP 头”的认证缺陷也存在于其他管理面板（`X-Real-IP`、`Forwarded` 等），审计时应检查所有 `getRemoteAddr` 替代实现。
- 关联：[[pentest-initial-access-legit-mailbox-relay-spoofing]]（信任可伪造头部导致身份/来源伪造的同类思路）。
- 边界：3.9.3 已修复；`digest` 认证提供者不受该伪造影响；若 AdminServer 仅绑定 127.0.0.1 且外部无法直连，则远程不可达。

## 检测与防御

- 检测：访问 AdminServer 的请求同时出现 `Authorization: ip` 与 `X-Forwarded-For`（尤其值为 `127.0.0.1`）；同一来源对 `/commands/restore`、`/commands/snapshot` 的异常调用；AdminServer 日志中的认证通过记录与真实来源不符。
- 修复：升级 ZooKeeper 到 3.9.3+；禁用 AdminServer 或改为 `digest` 等基于凭据的认证；不要使用 `IPAuthenticationProvider` 做远程管理认证。
- 加固：AdminServer 仅监听 127.0.0.1 或置于受控管理网；在入口代理剥离/覆盖客户端传入的 `X-Forwarded-For`；对管理端口做网络 ACL 与强认证；监控管理命令调用。

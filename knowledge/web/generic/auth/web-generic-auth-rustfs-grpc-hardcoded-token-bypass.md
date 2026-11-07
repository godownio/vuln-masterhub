---
id: web-generic-auth-rustfs-grpc-hardcoded-token-bypass
title: RustFS NodeService gRPC 硬编码管理令牌导致未授权节点管理接口调用
type: scenario
domain: web
path: web/generic/auth
technique: hardcoded-token-grpc-auth-bypass
aliases:
- CVE-2025-68926
- RustFS gRPC 认证绕过
- rustfs rpc 硬编码令牌
- NodeService 未授权访问
tags:
- rustfs
- grpc
- auth-bypass
- hardcoded-credential
- object-storage
- tonic
- http2
cve:
- CVE-2025-68926
severity: high
confidence: high
status: verified
affected_versions: < 1.0.0-alpha.78
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:13:54+08:00'
  notes: 已对照原文与5张图片核对：process_connection 中 NodeServiceServer::with_interceptor(..., check_auth)；hybrid 路由在 HTTP/2 且 Content-Type 以 application/grpc 开头时进入 gRPC；check_auth 将硬编码 "rustfs rpc" 与 authorization metadata 直接比较；图05 grpcurl 带该头调用 node_service.NodeService.ServerInfo 返回 success:true 与 serverProperties。影响版本 < 1.0.0-alpha.78 与原文一致并经 set-versions 确认。原文仅实测 ServerInfo，其余 NodeService 方法未逐一验证，卡内已注明。frontmatter无sources/source_url。PoC未本机执行。
---

## 一句话结论

RustFS 1.0.0-alpha.78 之前的节点管理 gRPC 服务（`node_service.NodeService`）在 9000 端口上用硬编码字符串 `rustfs rpc` 作为唯一认证令牌，任何能访问该端口的人带上 `authorization: rustfs rpc` 即可调用其 gRPC 管理方法；原文实测可匿名取得 `ServerInfo` 返回的服务器属性。

## 原理

- RustFS 把 S3 与节点管理 RPC 复用同一个 9000 端口。连接处理时用 `hybrid(s3_service, rpc_service)` 组合路由，`rpc_service` 由 tonic 生成的 `NodeServiceServer::with_interceptor(make_server(), check_auth)` 构建，拦截器就是 `check_auth`。
- 混合路由按协议分流：仅当请求为 HTTP/2 且 `Content-Type` 以 `application/grpc` 开头时才交给 gRPC 分支，其余按 REST/S3 处理。因此攻击者只需用 HTTP/2 gRPC 客户端即可进入管理面，无需 S3 签名。
- `check_auth` 的实现把 `"rustfs rpc"` 解析成 `MetadataValue` 后与请求 metadata 的 `authorization` 头做字符串比较，相等即 `Ok(req)`，否则返回 `Status::unauthenticated`。这里没有密钥派生、没有随机化、没有与部署配置绑定，令牌固定写死在代码里。
- gRPC 服务名是编译期常量 `node_service.NodeService`（`NamedService` 的 `NAME`），攻击者只要拿到 `node.proto` 就能按名称寻址调用，不依赖服务端开启 reflection。
- 结果：认证层唯一可猜的“秘密”就是公开源码中的常量，认证退化为形式检查，未授权者可调用管理接口并读取其返回的数据。

## 触发条件

- RustFS 版本低于 1.0.0-alpha.78，且 9000 端口（S3 与 gRPC 共用）可达；
- 攻击者持有 `node.proto`（可从对应版本源码/镜像中获取），gRPC 客户端支持 HTTP/2 h2c（`grpcurl -plaintext` 即可）；
- 目标未在边界上额外拦截 9000 端口的 HTTP/2/gRPC 流量。

## 利用步骤

1. 探测 9000 端口并确认是 RustFS（HTTP 响应特征、S3 API 行为）。
2. 从目标版本源码中取出 `node.proto`（定义 `node_service.NodeService` 与各 RPC）。
3. 用 grpcurl 以明文 h2c 连接，加 `authorization: rustfs rpc` 头调用 `ServerInfo`。
4. 观察响应：认证通过并返回 `{"success": true, "serverProperties": "..."}`，说明已进入管理面；按 proto 可继续枚举/调用其他 NodeService 方法。

## PoC

```bash
docker run -v /tmp/node.proto:/work/node.proto \
  fullstorydev/grpcurl -v -plaintext \
  -H "authorization: rustfs rpc" \
  -import-path /work \
  -proto /work/node.proto -d '{}' \
  <target>:9000 node_service.NodeService.ServerInfo
```

成功时响应体形如：

```json
{"success": true, "serverProperties": "<base64 编码的服务器属性>"}
```

## 变体与关联

- 变体：省略 `authorization` 头或使用其他值会得到 `No valid auth token`，可据此确认该硬编码令牌是唯一门槛；由于同一端口复用 S3 与 gRPC，按 `Content-Type: application/grpc` 分流即可避开 S3 签名校验路径。
- 关联：[[web-generic-auth-qdrant-internal-grpc-auth-bypass]]（同为内部 gRPC 管理面认证缺陷，但 Qdrant 的问题是凭证体系复用与匿名放行，本例是硬编码固定令牌）。
- 局限：原文只实测了 `ServerInfo`，NodeService 其余方法（配置、存储、节点操作等）的可调用性与最终危害未逐一验证；该服务的完整 RPC 面需以 `node.proto` 为准。

## 检测与防御

- 检测：9000 端口出现 gRPC/HTTP2 流量（`content-type: application/grpc`、`te: trailers`），尤其是请求头 `authorization: rustfs rpc`；非 S3 客户端来源访问 9000；NodeService 方法的异常调用记录。
- 升级：升级到 1.0.0-alpha.78 或更高版本，修复方式为移除硬编码令牌并改为部署期生成/校验的凭证。
- 网络：不要将 9000 直接暴露到不可信网络；用安全组/防火墙把 gRPC 管理面限制在集群内部，或在前置代理只放行 S3 路径与方法。
- 加固：若版本暂不能升级，可在边界阻断 9000 上的 HTTP/2 gRPC 流量（例如代理仅接受 S3 REST 请求），并对节点间通信启用 TLS。

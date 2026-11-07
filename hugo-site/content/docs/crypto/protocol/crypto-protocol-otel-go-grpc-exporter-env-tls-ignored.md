---
id: crypto-protocol-otel-go-grpc-exporter-env-tls-ignored
title: OpenTelemetry-Go 日志 gRPC 导出器忽略 env TLS 静默回退系统根（CVE-2026-81871）
type: scenario
domain: crypto
path: crypto/protocol
technique: env-tls-loaded-but-not-consumed-system-root-fallback
tags:
- tls
- certificate-validation
- mitm
- opentelemetry
- go
- grpc
- cve-2026-81871
- trust-anchor
- mtls
- configuration
cve:
- CVE-2026-81871
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc v0.5.0–v0.20.0（官方口径 < v0.21.0；修复 v0.21.0）
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T03:04:21+08:00'
  notes: 已对照原文与 8 张图片核对：装载/装配/首次握手三段、cfg.tlsCfg 零消费者、NewTLS(nil) 回退系统根、修复 c65d435 插入 env TLS 分支、v0.5.0–v0.20.0 区间、A1-A4/B1-B2/C1 实验结果与边界、v0.21.0 残留 fail-open 均与原文一致。未验证点：原文实验仓库/附件不在本地，未复跑；SSL_CERT_FILE 与企业 CA 是攻击前提建模；B2 强制 mTLS 为阴性结果；跨 SDK（Java/Python/Node/Rust）候选仅为静态审计。
url: /docs/crypto/protocol/crypto-protocol-otel-go-grpc-exporter-env-tls-ignored/
draft: false
kb_aliases:
- CVE-2026-81871
- GHSA-w34q-cm8f-9c5x
- otlploggrpc TLS 降级
- OTLP 导出器 MITM
- env TLS 未消费
- RootCAs nil 系统根
- TLS 静默降级
- mTLS 被绕过
---

## 一句话结论

OpenTelemetry-Go 的 OTLP 日志 gRPC 导出器 `otlploggrpc` 会把 `OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE` / 客户端证书 / 私钥完整解析进 `cfg.tlsCfg`，但拨号逻辑只读 `cfg.gRPCCredentials` 与 `insecure`，默认落到 `credentials.NewTLS(nil)`（系统根）。结果：运维声明的私有 CA 信任锚和 env-mTLS 静默失效；能控制连接路径且持有“名称匹配、被受害者系统根信任”证书的攻击者可终止 TLS，窃取/丢弃/篡改日志遥测，v0.20.0 及以下受影响（修复 v0.21.0）。

## 原理

- 导出器构造期 `newConfig` 调用 `loadEnvTLS`，把六个环境变量（signal 级 `..._LOGS_*` 优先于全局 `OTEL_EXPORTER_OTLP_*`）解析为 `*tls.Config`，写入 `cfg.tlsCfg`：根 CA → `RootCAs`，客户端证书对 → `Certificates`。装载侧工作正常。
- 随后 `newGRPCDialOptions` 的 switch 只判断两个字段：`cfg.gRPCCredentials`（显式 `WithTLSCredentials`）和 `cfg.insecure`；两者都不成立时进入 default 分支 `credentials.NewTLS(nil)`。该模块没有任何代码读取 `cfg.tlsCfg`，env TLS 配置成为无人消费的字段。
- `credentials.NewTLS(nil)` 经 `CloneTLSConfig(nil)` 得到零值 `tls.Config`，`RootCAs == nil`；按 Go 文档，此时客户端使用宿主系统根证书池（或平台校验器，Linux 上还可被 `SSL_CERT_FILE` / `SSL_CERT_DIR` 覆盖）。主机名校验、SAN 匹配、链验证仍然生效——被改变的是“信任哪个根”，不是“是否校验”。
- 由于 `grpc.NewClient` 不做 I/O，真正的 TLS 握手推迟到首次 `Export`，此后断线重连复用构造时装配的同一套 `TransportCredentials`，不会再读配置。攻击窗口覆盖进程启动后的任意一次首次导出或重连。
- 当 Collector 的 CA 只由 env 提供、不在系统根时，缺陷表现为可见但误导的 `x509: certificate signed by unknown authority` / `EXPORT_FAILED`；当攻击者证书恰好链到系统根时，表现为 `EXPORT_OK` 且零告警。同一条代码路径的两面。
- 官方影响区间为 `otlploggrpc` v0.5.0–v0.20.0（`< v0.21.0`）；修复 `c65d435` 在显式凭据与 `insecure` 之间插入 `case cfg.tlsCfg.Value != nil: credentials.NewTLS(cfg.tlsCfg.Value)`，消费顺序变为 `显式凭据 > env TLS > insecure > 系统根`。

## 触发条件

- 目标使用 `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc` v0.5.0–v0.20.0，且未显式使用 `WithTLSCredentials`，也未传入自带且正确加固的 `WithGRPCConn`。
- 通过环境变量声明了 TLS：私有 CA、客户端证书、客户端私钥（signal 级或全局）。
- endpoint 是远程 DNS 名称、跨集群地址，或经代理/网格出网；默认 `localhost:4317` 使普通远程劫持通常不可达（本地/网络命名空间能力仍可能控制回环）。
- 攻击者同时具备：① 控制名称解析/路由/代理（DNS 欺骗、路由劫持、恶意代理、受控网关）；② 持有对实际 endpoint 名称匹配、且被受害者系统根信任的证书与私钥（典型是企业检查代理 CA 或预装的企业根）；③ 能完成 h2/gRPC/OTLP 语义交互。
- 日志内容包含身份、业务、错误详情等敏感信息，或客户端使用可重放的静态 Header 鉴权时，危害升级。

## 利用步骤

1. 盘点实际交付二进制/SBOM 中的 `otlploggrpc` 模块版本（主 `go.opentelemetry.io/otel` 版本不能代表它），确认落在 v0.5.0–v0.20.0。
2. 确认进程使用 env TLS 变量且未显式传入 `WithTLSCredentials` / `WithGRPCConn`。
3. 确认 endpoint 为远程名称、且攻击者能控制其解析或路由。
4. 用系统根信任的 CA 为 endpoint 名称签发证书（或利用企业检查代理根），在劫持点终止 TLS，按正式 OTLP protobuf 实现 `LogsService/Export`。
5. 接收 `ExportLogsServiceRequest.resource_logs`，解码日志正文/属性/trace_id/span_id；返回空 `ExportLogsServiceResponse`（不设 `partial_success`），客户端会判 `EXPORT_OK`，无声丢包。
6. 需要篡改时，改写 `LogRecord.Body` 后用合法 CA 与上游弱认证 Collector 另建 TLS 转发；客户端若配置静态 Header，可在终止点读取 metadata 后重放，通过上游 Bearer 鉴权写入。
7. 若上游 Collector 强制 mTLS，攻击者在第二腿缺少客户端证书，TLS 层被 `certificate required` 拒绝——这是能力上界，不要误判为可写入。

## PoC

```bash
# 1. 配置（漏洞版本会加载但不使用这些证书）
export OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=https://collector.example:4317
export OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE=/certs/private-ca.pem
export OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE=/certs/client.pem
export OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY=/certs/client-key.pem

# 2. 确认实际打包版本
go version -m ./service-binary | grep otlploggrpc
# 命中 v0.5.0–v0.20.0 即受影响

# 3. 攻击侧（隔离实验）：
#    - DNS/路由把 collector.example 指向攻击者
#    - 攻击者证书由受害者系统根信任的 CA 签发，SAN=collector.example
#    - 运行真实 OTLP gRPC 服务端，接收 LogsService/Export
#    - 返回空 ExportLogsServiceResponse
# 预期：客户端 EXPORT_OK，攻击端收到完整日志，真实 Collector 零入库、零告警
```

```text
# 负对照（修复版 v0.21.0）：
#   同一攻击证书应被 env 私有 CA 拒绝：x509: certificate signed by unknown authority
# 负对照（合法 Collector）：
#   仅由 env 提供的私有 CA 在漏洞版被忽略 -> unknown authority / EXPORT_FAILED
#   修复版则成功建立 mTLS 并入库
```

## 变体与关联

- 变体：v0.20.0 中 `insecure=true` 会压过已装载的 env TLS，导致明文传输；修复版顺序为 env TLS 优先于 insecure。
- 变体：`WithGRPCConn` 自带 `*grpc.ClientConn` 时整体跳过拨号决策，env TLS 与漏洞同时被绕开（安全与否取决于调用方如何建连）。
- 变体：`WithTLSCredentials` 显式传入私有 CA/客户端证书可直接走正确分支，是官方短期缓解；若传入的仍是 `NewTLS(nil)` 一类系统根凭据，只是绕过错误分支，未恢复私有 CA 信任。
- 变体（残留 fail-open，v0.21.0 仍存在）：证书路径不存在、私钥非 PEM、证书/私钥不匹配时，`loadEnvTLS` 只经 `otel.Handle` 输出一行 stderr（默认无结构、可不进 OTel 日志管线），`tlsCfg` 不设置，连接回退系统根并 `EXPORT_OK`；一个坏私钥会连同已加载的根 CA 一起丢弃。升级不能把“配错证书”变成“显式失败”。
- 关联：[[web-generic-auth-fastify-badurl-shared-404-handler-bypass]]（另一类“配置/凭据已加载但消费路径绕过安全语义”的框架缺陷，可对照其信任边界分析）。
- 边界：主机名/SAN 校验始终生效，自签证书或 SAN 不匹配无法利用；强制 mTLS 的上游写入腿不闭合；公网普通攻击者通常无法控制远程 endpoint 的解析路径。

## 检测与防御

- 资产盘点：从交付二进制的 Go build info、SBOM、`go list -m all` 查 `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc`，命中 v0.5.0–v0.20.0；不要用主模块版本判断。
- 修复：升级到 v0.21.0+ 并重新构建/部署实际打包该模块的二进制（库漏洞以二进制重建为完成点）。
- 缓解（无法立即升级）：显式 `WithTLSCredentials`，用预期私有 CA（需要 mTLS 时含客户端证书与私钥）构造 `tls.Config` 再生成 credentials；不要传系统根凭据冒充。
- 加固：Collector 侧强制 mTLS（`client_ca_file` → `RequireAndVerifyClientCert`），封死攻击者的上游写入/篡改腿；静态 Header 凭据改为短效、可绑定通道的凭据。
- 验证：在 staging 做真实握手级正负对照——合法私有 CA 必须成功；仅被系统根信任的同名对照证书必须被拒；证书损坏必须让部署门禁失败（v0.21.0 库内仍 fail-open，需把 stderr 的 `failed to load TLS` 视为失败，并确认自定义 `ErrorHandler` 未吞掉）。
- 检测：应用侧导出成功计数与 Collector 接收/入库计数的时间窗对账（无声丢包）；强制 mTLS Collector 上的 `certificate required`/握手失败与客户端身份流量突然中断；同一静态 token 突然来自新网络身份；客户端 stderr 的 `failed to load TLS` 单行文本（前提是 stderr 被采集且未被 noop ErrorHandler 静默）。

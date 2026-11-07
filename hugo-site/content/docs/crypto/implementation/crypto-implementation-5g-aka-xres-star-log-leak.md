---
id: crypto-implementation-5g-aka-xres-star-log-leak
title: 5G-AKA 期望响应值 XRES* 写入 INFO 日志并复用未消费认证上下文完成确认
type: scenario
domain: crypto
path: crypto/implementation
technique: auth-vector-secret-in-info-log-and-unconsumed-context-replay
tags:
- 5g
- ausf
- free5gc
- 5g-aka
- eap-aka
- authentication
- credential-leak
- logging
- cwe-532
- sensitive-data
- replay
- sbi
- go
- cve-2026-55785
cve:
- CVE-2026-55785
severity: low
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: < v1.4.5（含 v1.4.4 与 2026-05 main 分支 bfc4a100；修复提交 7a5a4aa1 随 v1.4.5 发布，GHSA 的 patched versions 字段仍显示 None）
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T02:59:07+08:00'
  notes: 已对照原文全文与19张图核对：ue_authentication.go:394/578 两处 INFO 以 %x 无损输出 XresStar（端到端日志 303132... 可逆还原）、:579 strings.EqualFold 非常数时间、确认函数不检查 AuthStatus/无 TTL 且同一 authCtxId 失败后提交正确值返回 AUTHENTICATION_SUCCESS+Kseaf、修复版 grep 计数 0 均与原文一致；原文明确受影响 < v1.4.5 且 bfc4a100/7a5a4aa1 修复，已 set-versions。卡片已正确注明跨主体认证绕过与远程定时恢复均未端到端验证、severity low/confidence medium 合适。PoC 未在本机执行。
url: /docs/crypto/implementation/crypto-implementation-5g-aka-xres-star-log-leak/
draft: false
kb_aliases:
- CVE-2026-55785
- GHSA-fp46-6vfw-gc9c
- free5GC AUSF XRES* 日志泄露
- 5G-AKA XRES* 泄露
- AUSF 认证材料落日志
- 5G-AKA 认证上下文未消费
- XRES* 确认重放
- EAP-AKA' K_aut TRACE 日志
---

## 一句话结论

free5GC AUSF 在 5G-AKA 认证向量生成阶段和确认比较前，用 INFO 级别把期望认证响应值 `XRES*` 以 `%x` 可逆编码写入普通日志；同时 5G-AKA 认证上下文不做一次性消费。能读取 AUSF 日志的主体可取得 `XRES*` 与 `authCtxId → SUPI` 映射，若再具备 `/nausf-auth` SBI 调用路径，即可用同一 `authCtxId` 提交确认并获得 `Kseaf`。跨主体认证绕过依赖日志读取与 SBI 调用两种能力叠加，真实部署中是否成立未获端到端验证。

## 原理

- **5G-AKA 的信任模型**：AUSF 从 UDM 取得认证向量（`Rand`、`XresStar`、`Autn`、`Kausf`）后，计算出 `HXRES* = SHA256(Rand || XresStar)[16:]`，只把 `Rand`、`Autn`、`HXRES*` 经 SBI 返回给 AMF/SEAF，自身在内存中保留原始 `XRES*` 作为确认时的比较基准。`XRES*` 属于归属网络侧认证材料，本应只存在于 AUSF 进程内。
- **泄露点一**：向量生成时执行 `logger.Auth5gAkaLog.Infof("XresStar = %x\n", XresStar)`。该行在建立上下文阶段无条件执行，早于任何确认请求。
- **泄露点二**：5G-AKA 确认处理中，在调用 `strings.EqualFold(resStar, XresStar)` 之前无条件执行 `Infof("res*: %x\nXres*: %x\n", resStar, XresStar)`。因此无论提交值是否正确，期望值都会落日志。
- **为什么 `%x` 不算脱敏**：Go 的 `%x` 对 `string` 是按字节做十六进制编码。`"0123456789abcdef0123456789abcdef"` 会变成 `30313233343536373839616263646566...`，这是无损、可逆编码，不是哈希或掩码；还原后仍是完整 `XRES*`。
- **关联信息**：同一文件把 `supiOrSuci` 与解析出的 SUPI 以 INFO 写入（`Add SuciSupiPair (%s, %s)`）。确认 URI 中的 `authCtxId` 即 `supiOrSuci`，因此日志读取者可直接把泄露的 `XRES*` 对应到可用的确认路径。
- **上下文不消费**：5G-AKA 确认函数只检查 `suciSupiMap` 与 `UePool` 中对象是否存在，既不检查已有 `AuthStatus`（`ONGOING/SUCCESS/FAILURE`），也不删除上下文；仓库中的两个 DELETE handler 均返回 501，未见 TTL。于是同一个 `authCtxId` 在一次失败后仍可再次比较，比较成功会返回 `SUPI` 与 `Kseaf`，并把状态改写为 `SUCCESS`。这是“读到 `XRES*` 后能真正完成确认”的第二个必要条件。
- **能力叠加**：日志读取者（本地文件、sidecar、采集器、SIEM、被攻陷容器）与 SBI 调用者原本是两条独立的权限轴。漏洞把认证材料从 AUSF 机密域搬到日志面，使两者一旦重合即可完成 5G-AKA 确认。本条链的机密性影响已实测；跨主体认证绕过的最终危害取决于真实 UDM 是否接受延迟/重复的成功事件，以及 OAuth/TLS/网络策略是否阻断调用。

## 触发条件

- 目标为 `github.com/free5gc/ausf` `< v1.4.5`（含 v1.4.4 与 2026-05 main `bfc4a100`），且业务走到 5G-AKA 向量生成与确认流程。
- 攻击者具备**日志读取能力**：能读取 AUSF stdout/文件、sidecar 采集结果、SIEM 或容器日志。仅能远程调用 SBI 而没有日志读取能力时，拿不到 `XRES*`。
- 攻击者具备**SBI 调用路径**：能访问 `/nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation`。是否绕过 OAuth 取决于 NRF 返回的 `customInfo["oauth2"]`；mock NRF 不返回该字段时 `OAuth2Required=false`，但真实部署通常还有 TLS、网络策略与服务网格限制，不能据此认为“端口可达即可调用”。
- 需要一个已建立的认证上下文：先通过 `POST /ue-authentications` 触发向量生成，日志中的 `supiOrSuci` 即确认用的 `authCtxId`。
- EAP-AKA' 变体另需 EAP 向量与 TRACE 日志级别；默认 `logger.level: info` 不会输出 `K_aut` 的 TRACE 行。

## 利用步骤

1. 确认目标 AUSF 版本落在受影响区间，且 5G-AKA 流程可用。
2. 触发一次认证向量生成：`POST /nausf-auth/v1/ue-authentications`，提交目标 `supiOrSuci` 与 `servingNetworkName`。
3. 读取 AUSF INFO 日志，提取 `XresStar = <hex-of-ascii>` 与 `Add SuciSupiPair (<supiOrSuci>, <supi>)`；把 `%x` 编码还原为原始 32 位 hex `XRES*`，并确定 `authCtxId`。
4. 具备 SBI 调用路径时，向 `PUT /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation` 提交 `{"resStar":"<还原后的 XRES*>"}`。
5. 预期返回 `AUTHENTICATION_SUCCESS`、`supi` 与 `kseaf`。若先提交错误值再提交正确值，同一 `authCtxId` 仍可成功，说明上下文未被消费。
6. 若仅能读日志而不能调用 SBI，则到此为止：已确认的最终危害是认证材料跨越信任边界泄露，不能宣称已完成认证绕过。

## PoC

```bash
# 隔离环境：脆弱 AUSF + mock NRF/UDM，mock 固定返回脱敏向量
# XRES* = 0123456789abcdef0123456789abcdef
BASE=http://127.0.0.1:18000/nausf-auth/v1
SUPI=imsi-2089300007487

curl -s -X POST "$BASE/ue-authentications" -H 'Content-Type: application/json' \
  -d '{"supiOrSuci":"imsi-2089300007487","servingNetworkName":"5G:mnc070.mcc208.3gppnetwork.org"}'

# 错误值先失败，再用同一 authCtxId 提交正确值
curl -s -X PUT "$BASE/ue-authentications/$SUPI/5g-aka-confirmation" \
  -H 'Content-Type: application/json' -d '{"resStar":"00000000000000000000000000000000"}'
curl -s -X PUT "$BASE/ue-authentications/$SUPI/5g-aka-confirmation" \
  -H 'Content-Type: application/json' -d '{"resStar":"0123456789abcdef0123456789abcdef"}'

# 日志侧取证：应命中 XresStar 与 res*/Xres*，值为 ASCII 字节的 hex
docker compose logs ausf | grep -E 'XresStar|Xres\*|res\*'
# "0123..." -> "303132333435..."，可逆还原
```

```text
预期（脆弱版）：
POST -> 201 Created
错误 resStar -> AUTHENTICATION_FAILURE
正确 resStar -> AUTHENTICATION_SUCCESS + supi + kseaf
日志 -> XresStar = 303132...；res* / Xres* 成对出现
修复版（7a5a4aa1 及以后）：相同请求仍返回失败/成功，但 grep 计数为 0
```

## 变体与关联

- 变体（EAP-AKA'）：`K_aut` 在派生后进入 `Tracef("K_aut: %x", K_aut)`，修复版仍保留该行；默认 `info` 级别不输出，运行时暴露面未验证。EAP 路径的 `RES` 比较被 `bytes.Equal(MAC, XMAC)` 门控，必须先持有会话相关的 `K_aut` 才能触发，利用门槛更高。
- 变体（只泄露不重放）：日志管线/SIEM 读取者通常没有 SBI 通道，此时危害限于认证材料与 `authCtxId → SUPI` 关联信息暴露；不要把“拿到 XRES*”等同于“拿到 AMF/SEAF 身份”。
- 边界（同 CVE 的非常数时间比较）：`strings.EqualFold`、`bytes.Equal` 与字符串 `==` 均非常数时间。原文本地基准显示 32 字符 `EqualFold` 的耗时与首个失配位置相关，但远程 HTTP/SBI 定时恢复无端到端证据，16 字节 `bytes.Equal` 也未呈现逐字节单调趋势；因此不将其作为独立利用场景，只作为加固项。
- 关联：[[crypto-protocol-otel-go-grpc-exporter-env-tls-ignored]]（同为“安全配置/机密已存在但边界失效”的实现缺陷，可对照信任边界分析法）。
- 边界：AUSF 层已证明“失败后可用正确值成功”；“成功后是否还能再次重放”“真实 UDM 是否接受重复/延迟认证事件”均未验证，不能写成已完成的跨主体绕过。

## 检测与防御

- 运行侧检测：在 AUSF 日志中检索 `XresStar|Xres\*|res\*|K_aut|SuciSupiPair|Auts:`；命中后按“未修复/回归、TRACE 残留、范围外隐私（SUPI/SUCI/AUTS）”分类人工复核，不能仅凭关键词判定漏洞。
- 代码审计：以 `XresStar/XRES/K_aut/Kausf/Kseaf/XMAC/AT_MAC` 等机密字段为源，检查它们是否进入 `bytes.Equal`、`strings.EqualFold`、`==`、`strings.Compare`，以及是否作为 `logger.*f`、`log.*`、`fmt.*` 的实参；搜索命中只表示需要复核。
- 修复：升级到含提交 `7a5a4aa1` 的 v1.4.5，或应用该提交。补丁删除两条 `XRES*` INFO 日志，并把三处比较改为先 hex 解码再 `subtle.ConstantTimeCompare`；注意该 helper 对非法 hex 与长度不等仍会提前返回，长度分支仍可观测。
- 临时缓解：把日志级别提高到 WARN/ERROR；限制日志文件、采集管线与 SIEM 的读取权限；对 `XresStar/Xres*/res*/AT_MAC/K_aut/SUPI/SUCI/AUTS` 做采集侧脱敏。
- 认证状态加固：确认接口应在每次确认前检查 `AuthStatus`，成功、失败或超时后删除上下文并设置 TTL，避免同一 `authCtxId` 无限重试；DELETE 路由不应停留在 501。
- 残余项：升级后仍应审计 TRACE 日志与 `K_aut` sink，并清理 SUPI/SUCI/AUTS 等范围外日志；生产环境应明确是否允许开启 TRACE。

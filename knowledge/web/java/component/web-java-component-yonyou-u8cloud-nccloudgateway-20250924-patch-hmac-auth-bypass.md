---
id: web-java-component-yonyou-u8cloud-nccloudgateway-20250924-patch-hmac-auth-bypass
title: 用友 U8Cloud NCCloudGatewayServlet 20250924 补丁分析：ts+HMAC 校验仍以硬编码 nctoken 为密钥，旧 RCE 链被黑名单封堵
type: scenario
domain: web
path: web/java/component
technique: yonyou-u8cloud-nccloudgateway-20250924-patch-hmac-auth-bypass
aliases:
- 用友 U8Cloud 补丁分析
- NCCloudGatewayServlet 20250924
- checkGateWayTokenNew
- ts sign HMAC-SHA256
- GWWhiteCtrlUtil
- nccloud.gateway.nctoken
tags:
- java
- yonyou
- u8cloud
- nccloud
- patch-analysis
- auth-bypass
- hmac
- blacklist
- command-injection
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 2.0 2.1 2.3 2.5 2.6 2.7 2.65 3.0 3.1 3.2 3.5 3.6 3.6sp 5.0 5.0sp 5.1 5.1sp（< 20250924 补丁版本）
verification:
  verified_by: verifier-V214
  verified_at: '2026-11-07T04:32:51+08:00'
  notes: 已对照原文与25张图核对：旧 checkGateWayToken 的 Encode.decode(nctoken) 比较、新 checkGateWayTokenNew 的 ts 非空/±180000ms/HMAC-SHA256(Base64) 且密钥仍为同一 nctoken、GWWhiteCtrlUtil 对 IActionInvokeService+ProcessFileUtils 组合与 IUAPQueryBS SQL 关键词的黑名单、ServletForGW/NInvokerServlet 路由与完整调用链、未打补丁 PoC 的 calc 执行均与原文/截图一致。affected_versions 逐项核对公告截图为 2.0 2.1 2.3 2.5 2.6 2.7 2.65 3.0 3.1 3.2 3.5 3.6 3.6sp 5.0 5.0sp 5.1 5.1sp（17 项完全一致）。补丁后 ts/sign 仅代码论证、未实测 RCE，卡内已标注 confidence=medium。未在真实实例复现。
---

## 一句话结论

20250924 补丁把 NCCloudGatewayServlet 的 `gatewaytoken` 固定串比较换成 `ts` + `sign` 的 HMAC-SHA256 校验，但 HMAC 密钥仍是配置文件里同一个 `nccloud.gateway.nctoken`（`Encode.decode` 后为 `TJ6RT-3FVCB-DPYP8-XF7QM-96FV3`）；知道该 token 的人可在 3 分钟窗口内自算 `sign` 通过认证。补丁同时用 `GWWhiteCtrlUtil` 把 `IActionInvokeService` + `ProcessFileUtils` 和 `IUAPQueryBS` 的 SQL 关键词加入黑名单，因此旧 JSON 反射 RCE 链在已打补丁实例上被阻断；是否存在未被黑名单覆盖的反射 sink 原文未验证。

## 原理

- **旧校验**：`GateWayUtil.checkGateWayToken(String gatewaytoken)` 直接比较请求头与 `(new Encode()).decode(getProp().getProperty("nccloud.gateway.nctoken"))`；token 来自 `/resources/nccloud/nccloudgateway.properties`，属于硬编码/可解码配置。
- **新校验**：`checkGateWayTokenNew(String ts, String sign)` 要求两者非空；`ts` 解析为 long，且 `Math.abs(System.currentTimeMillis() - ts) > 180000L`（3 分钟）即拒绝；然后比较 `sign` 与 `sign(ts)`。
- **签名算法**：`sign(String str, String secret)` 使用 `Mac.getInstance("HmacSHA256")`，密钥是 `new Encode().decode(getProp().getProperty("nccloud.gateway.nctoken"))`，对 `ts` 的 UTF-8 字节做 HMAC-SHA256，最后 Base64 编码。注意签名只覆盖 `ts`，不覆盖请求体/路径，所以一次签名可在 3 分钟窗口内用于任意请求。
- **为什么仍可伪造**：HMAC 的密钥与旧 token 是同一个硬编码配置值；只要拿到 `nccloudgateway.properties`（源码、备份、目录遍历、配置泄露）或使用默认/已泄露值，就能对任意当前 `ts` 计算合法 `sign`。补丁只是把“固定头比较”换成“时间窗 + 同密钥 HMAC”，没有引入服务端私密密钥或一次性 nonce，认证强度没有本质提升。
- **补丁的黑名单**：`ServletForGW.callNCService` 在调用前新增 `GWWhiteCtrlUtil.getInstance().checkAuthority(serviceClassName, argValues)`；`checkBlackITAuthority` 明确拒绝 `com.ufida.zior.console.IActionInvokeService` 且首个参数为 `nc.bs.pub.util.ProcessFileUtils` 的调用，并对 `nc.itf.uap.IUAPQueryBS` 的首个参数做小写化后的 SQL 关键词包含检查。旧链的 sink 正好被这两个条件覆盖，所以已打补丁实例上原 JSON 链会被拒绝。
- **残余风险**：这是黑名单而不是白名单；`NCLocator` 中其他可反射调用的服务/类、同一个 `IActionInvokeService` 的其他危险 actionName、以及 `IUAPQueryBS` 的 SQL 关键词绕过都不在黑名单覆盖范围内。KB 已有 `IFileTrans` 反射上传写 WebShell 的卡，其是否被 20250924 补丁覆盖、在伪造 `ts/sign` 后是否仍可调用，原文未验证，属于待确认的补丁绕过面。
- **路由差异**：原文的 `web.xml` 把 `NCInvokerServlet` 映射到 `/servlet/*`，PoC 为 `/servlet/NCCloudGatewayServlet`；部分部署/资料使用 `/service/*`，排查时以目标实际 `web.xml` 为准。

## 触发条件

- 目标为用友 U8Cloud 受影响版本（2.0～5.1sp，< 20250924 补丁），或虽已打补丁但 `nccloud.gateway.nctoken` 仍为已知/可读值。
- `/servlet/NCCloudGatewayServlet`（或部署实际的 `/service/NCCloudGatewayServlet`）可从攻击者网络访问。
- 能读取配置文件 `nccloudgateway.properties`，或已知 `nccloud.gateway.nctoken` 及其 `Encode.decode` 结果；服务端时间与攻击者时间相差不超过 3 分钟。
- 旧链还需要目标存在 `IActionInvokeService` 与 `ProcessFileUtils`，且未打 20250924 补丁（或找到未被黑名单覆盖的反射 sink）。

## 利用步骤

1. 访问网关 Servlet，确认路由与响应；从 `web.xml` 确认是 `/servlet/*` 还是 `/service/*`。
2. 读取 `nccloudgateway.properties` 的 `nccloud.gateway.nctoken`，用 `nc.vo.framework.rsa.Encode#decode` 得到实际 token（原文值为 `TJ6RT-3FVCB-DPYP8-XF7QM-96FV3`）。
3. **未打补丁**：直接带 `gatewaytoken: <token>` 头和原 JSON 反射链（`IActionInvokeService` → `ProcessFileUtils.openFile` → `Runtime.exec`）即可命令执行；详见关联卡。
4. **已打补丁**：取当前毫秒时间戳 `ts`，计算 `sign = Base64(HMAC-SHA256(ts, token))`，发送 `ts: <ts>` 与 `sign: <sign>` 头；在 3 分钟窗口内可通过 `checkGateWayTokenNew`。
5. 通过认证后，`GWWhiteCtrlUtil` 会拒绝 `IActionInvokeService` + `ProcessFileUtils` 组合；需要寻找未被黑名单覆盖的反射服务/方法（原文未给出可用的新 sink，故补丁后的完整 RCE 未验证）。
6. 验证补丁状态：若旧 JSON 链返回“目前没查询[类]接口权限/黑名单”类异常，说明补丁已生效；若返回 `{"agg":false}` 并执行命令，说明未打补丁或黑名单被绕过。

## PoC

```python
import base64, hmac, hashlib, time

token = "TJ6RT-3FVCB-DPYP8-XF7QM-96FV3"   # Encode.decode(nccloud.gateway.nctoken)
ts = str(int(time.time() * 1000))
sign = base64.b64encode(
    hmac.new(token.encode("utf-8"), ts.encode("utf-8"), hashlib.sha256).digest()
).decode()
print("ts:", ts)
print("sign:", sign)
```

```http
POST /servlet/NCCloudGatewayServlet HTTP/1.1
Host: target
Content-Type: application/json
ts: <当前毫秒时间戳>
sign: <Base64(HMAC-SHA256(ts, token))>

{"serviceInfo":{"serviceClassName":"...","serviceMethodName":"...","serviceMethodArgInfo":[...]}}
```

说明：`ts/sign` 计算按原文 `GateWayUtil.sign` 重写，未在打补丁实例上复跑；旧链 JSON 见关联卡，本文不重复。原文截图证明的是未打补丁链的 `gatewaytoken` 请求与 calc 执行，补丁后的 `ts/sign` 请求没有实际测试截图，故整体 confidence=medium。

## 变体与关联

- **旧链完整利用**：[[web-java-component-yonyou-nccloud-gateway-reflection-command-injection]]（`gatewaytoken` + `IActionInvokeService` + `ProcessFileUtils`）。
- **同网关其他反射 sink**：[[web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload]]（`IFileTrans` 任意文件上传写 WebShell）；该 sink 是否被 20250924 黑名单覆盖需实测。
- **同产品其他入口**：[[web-java-component-yonyou-u8-serviceDispatcher-invocationinfo-token-file-write]]、[[web-java-component-yonyou-u8cloud-servicedispatcher-patch-bypass-token-upload]]（ServiceDispatcher 的 token 伪造与补丁绕过）。
- **签名只覆盖 ts**：可重放同一 `sign` 在 3 分钟窗口内调用多个服务；若服务端只校验 ts/sign，不校验 nonce，重放面较大。
- **边界**：拿不到 `nctoken`、服务端时间不同步导致 ts 超窗、补丁把 `GWWhiteCtrlUtil` 扩展到其他 sink、或反射桥被移除时，本链不成立。

## 检测与防御

- 检测：网关请求头同时出现 `ts` 与 `sign`，且 `ts` 为 13 位毫秒时间戳、`sign` 为 Base64 的 HMAC 摘要；同一来源在 3 分钟窗口内高频更换 `ts/sign`；请求体出现 `serviceClassName`/`serviceMethodArgInfo`/`IActionInvokeService`/`ProcessFileUtils`/`IFileTrans` 等特征。
- 检测：`GWWhiteCtrlUtil` 抛出的“没有查询[类]接口权限”异常可作为攻击尝试信号；结合 Web 访问日志与网关日志关联。
- 防御：升级到 20250924 或更高补丁；**不要复用** `nccloud.gateway.nctoken` 作为 HMAC 密钥，改为服务端独立密钥/非对称签名/一次性 nonce，并校验签名覆盖请求体与路径；把网关反射调用改成显式白名单方法，而不是黑名单；限制 `/servlet/*`、`/service/*` 仅对可信来源开放；以低权限运行 NC 服务并限制子进程创建。
- 响应：轮换 `nccloud.gateway.nctoken`、审计网关配置与源码泄露面、排查其他反射 sink 是否被调用、保存请求体与网关日志作为证据。

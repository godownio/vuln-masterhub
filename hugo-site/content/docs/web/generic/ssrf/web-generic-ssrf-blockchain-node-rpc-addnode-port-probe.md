---
id: web-generic-ssrf-blockchain-node-rpc-addnode-port-probe
title: 公链节点 RPC addnode 未校验目标地址：认证后令节点连接任意 host:port，按响应时间侧信道探测本机/内网开放端口
type: scenario
domain: web
path: web/generic/ssrf
technique: blockchain-rpc-addnode-ssrf-timing-port-probe
tags:
- ssrf
- blockchain
- json-rpc
- addnode
- port-scan
- timing
- network
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V572
  verified_at: '2026-11-12T10:53:37+08:00'
  notes: 已对照原文（12896，168 行）与 18 张截图逐张核对（本卡对应图12-17）：rpcnet.cpp addnode 中 configs[0] 为目标串，onetry 直接 OpenNetworkConnection(addr,NULL,strNode.c_str()) 无回环/私网/端口校验（图12）；curl --user rubyrpc:… addnode configs=["127.0.0.1:6379","onetry"] 返回 result/error null（图13，与卡内 PoC 一致）；目标侧 nc 捕获 Connection from localhost 34758 received 及 P2P 握手字节/version/Ruby:0.2.0.3（图14），证明节点真实发起 TCP 连接；原文给出开放端口秒级/未开放约 5s 的计时差异。修正：nc 命令按截图由 -lvvp 改为 -lvp（3 处）。dedup：与 web-generic-ssrf-connector-imap-website-test-endpoints、lylme-get-head-curl-blind-timing 等为 related（HTTP 抓取/盲计时），本卡为 P2P 连接原语，无同链卡；dup-scan 无涉及。未设 affected_versions（通用节点实现，原文未声明版本）。未验证点：原文未做关闭端口计时实测与大范围扫描，卡内已注明；未复跑 PoC。
url: /docs/web/generic/ssrf/web-generic-ssrf-blockchain-node-rpc-addnode-port-probe/
draft: false
kb_aliases:
- addnode SSRF
- 公链 RPC SSRF
- JSON-RPC addnode
- onetry 端口探测
- 节点连接任意地址
- 响应时间端口扫描
---

## 一句话结论

公链节点的 JSON-RPC `addnode` 在 `onetry` 模式下直接把用户提供的字符串交给 `OpenNetworkConnection(addr, NULL, strNode)` 建立 P2P 连接，未校验目标 IP/端口；当 RPC 暴露且凭据可获知/弱口令可爆破时，攻击者可让节点连接 `127.0.0.1:6379` 等本机或内网地址，并利用“端口开放立即响应、未开放约 5 秒超时”的响应时间差异，把节点当作内网端口扫描器。

## 原理

- **功能即 SSRF sink**：`rpcnet.cpp` 的 `addnode(const Array& configs, bool fHelp)` 中，`configs[0]` 为目标节点字符串；当命令为 `onetry` 时直接执行 `OpenNetworkConnection(addr, NULL, strNode.c_str())`，没有检查目标是否为回环/私网地址，也没有限制端口。
- **为什么能探测端口**：P2P 连接对开放的 TCP 端口会很快完成/返回（或产生协议交互），对未开放端口则等待连接超时（原文观测约 5 秒）；攻击者用同一接口对不同 `IP:端口` 发起请求并测量耗时，即可区分开放/关闭，形成盲扫。
- **认证不是可靠边界**：原文 RPC 使用 HTTP Basic 认证，但凭据在配置/客户端中可见，且弱口令可爆破；只要攻击者拿到或猜中凭据，`addnode` 就成为通用连接原语。即使 RPC 仅监听内网，若 Web/代理层可达也可利用。
- **连接的真实性可验证**：原文在目标 `127.0.0.1:6379` 起 `nc -lvp 6379`，调用 addnode 后监听端收到来自 localhost 的连接及节点 P2P 握手字节，证明不是“只发 HTTP 请求”而是节点真实向目标建立 TCP 连接。
- **利用边界**：该原语是“让节点发起 TCP 连接并发送 P2P 握手”，对 Redis/MySQL 等文本协议服务通常不能直接执行命令（握手字节不符合协议），主要用于端口存活探测、服务指纹与后续社工/横向；若目标端口正好是另一个公链节点或可被 P2P 握手套路，则可进一步做网络拓扑发现。
- **为什么危险**：公链节点常部署在多网卡/云主机上，`addnode` 使其成为进入内网的跳板；攻击者无需在目标网段有 foothold，只需能调用 RPC。

## 触发条件

- 公链节点开启 JSON-RPC，且 `addnode` 方法可调用（未被禁用/命名空间限制）。
- 攻击者可访问 RPC（外置、反向代理、端口暴露）并获得/猜中认证凭据（原文为 HTTP Basic；弱口令可爆破）。
- 节点进程可访问目标内网/本机地址（通常可以）。
- 目标网络允许节点主动外连；响应时间可用于区分开放/关闭端口。

## 利用步骤

1. 探测 RPC 端点与认证方式：向 `http://target:port` POST JSON-RPC，确认 `addnode` 可用、返回格式与认证头。
2. 在攻击者可控主机或目标本机启动监听（如 `nc -lvp 6379`），确认节点确实发起连接。
3. 构造 `addnode` 请求，`configs` 为 `["<ip>:<port>", "onetry"]`；对每个候选端口测量请求耗时：开放端口快速返回，未开放端口约 5 秒超时。
4. 对常见内网端口（6379/3306/22/8080/9200/2375 等）批量探测，结合超时差异筛选存活服务。
5. 对存活服务做协议指纹（若连接会留下源 IP/端口与握手字节），评估能否进一步利用；记录节点出站连接作为证据。
6. 若 `addnode` 的 `add` 命令会持久化节点列表，测试后注意清理（原文主要用 `onetry` 避免持久化）。

## PoC

```bash
# 基本请求：让节点连接 127.0.0.1:6379（凭据按实际替换）
curl -s --user '<rpcuser>:<rpcpassword>' \
  --data-binary '{"jsonrpc":"2.0","id":"rpcaddnode","method":"addnode","configs":["127.0.0.1:6379","onetry"]}' \
  -H 'content-type: text/plain;' http://<target>:<rpcport>
# 返回 {"result":null,"error":null,"id":"rpcaddnode"} 表示请求被接受
```

```bash
# 目标侧验证连接来源（在目标机执行）
nc -lvp 6379
# 期望看到 Connection from localhost <port> received! 及 P2P 握手字节
```

```python
# 时间侧信道端口探测骨架
import time, requests
def probe(host, port):
    t = time.time()
    requests.post(RPC_URL, auth=(USER, PASS), json={
        "jsonrpc":"2.0","id":1,"method":"addnode",
        "configs":[f"{host}:{port}","onetry"]}, timeout=10)
    return time.time() - t
# 快返回(~毫秒级)≈端口开放；接近 5s≈未开放
```

原文实测 `127.0.0.1:6379` 连接成功并被 nc 捕获；时间差异为原文观测（开放立即/未开放约 5 秒），未做大规模扫描。

## 变体与关联

- 变体：同族节点的其它“连接用户指定地址”类 RPC（如添加 peer/连接种子节点）可能有同样问题；`addnode add` 可能持久化到节点列表，`onetry` 仅本次尝试。
- 变体：若节点可访问云元数据地址且目标端口有 HTTP 服务，可用该连接原语做更进一步的交互（取决于节点是否发送 HTTP 而非 P2P 握手）。
- 关联：通用 SSRF 端口探测与内网侦察见 [[web-generic-ssrf-file-hosts-internal-segment-recon]]、[[web-generic-ssrf-lylme-get-head-curl-blind-timing]]；公链 RPC 暴露面与参数校验见 [[blockchain-consensus-rpc-setminercoinbase-address-validation-missing]]。
- 边界：RPC 仅本机、强认证且不可爆破、`addnode` 被禁用、或节点运行在禁止出站的网络时不可用；连接原语不是通用 HTTP SSRF，对多数应用层协议只能做存活探测。

## 检测与防御

- 检测：RPC 日志中出现 `addnode` 且参数为 127.0.0.1/私网地址/非常用端口；节点进程向本机或内网多个端口发起短连接；`nc`/防火墙日志显示节点到 6379/3306 等非 P2P 端口的连接；RPC 认证失败/爆破告警。
- 防御：RPC 默认只绑定 127.0.0.1，使用强随机凭据并禁止匿名/弱口令；在 `addnode` 中校验目标地址，拒绝回环、私网、链路本地与保留地址（或仅允许配置的白名单节点）；禁用不必要的 `addnode`/admin 命名空间；对节点出站做网络策略限制。
- 响应：发现异常 addnode 后检查节点连接表与出站日志，清理被添加的节点，轮换 RPC 凭据并收敛暴露面。

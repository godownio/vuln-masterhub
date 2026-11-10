---
id: defense-detection-behinder40-client-traffic-fingerprint
title: 冰蝎4.0 客户端流量指纹：按脚本类型固定 Content-Type、10 个内置旧版浏览器 UA 与文件操作超大请求
type: scenario
domain: defense
path: defense/detection
technique: behinder40-client-traffic-fingerprint
aliases:
- 冰蝎4.0流量特征
- Behinder 客户端指纹
- 冰蝎 Content-Type 特征
- 冰蝎 User-Agent 指纹
- 冰蝎文件操作大包检测
tags:
- defense
- detection
- traffic-analysis
- webshell
- behinder
- user-agent
- content-type
- nta
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V453
  verified_at: '2026-11-10T02:12:43+08:00'
  notes: 已对照原文与 9 张图核对：v4.0.6 常量、initHeadersByType 的 php/aspx/jsp 分支、Accept/Accept-Language 固定头、10 条内置 UA、文件操作约 400KB 与 chunked 响应均一致；检测规则未在真实流量复跑；原文未给受影响版本，affected_versions 已按工具版本而非漏洞区间清空。
---

## 一句话结论

冰蝎 4.0 客户端（样本 v4.0.6）的 HTTP 头是硬编码的：Content-Type 按马类型固定（PHP 为 `application/x-www-form-urlencoded`，ASPX 为 `application/octet-stream`，ASP/JSP 不发该头），Accept/Accept-Language 固定，User-Agent 从 10 条过时的浏览器 UA 中随机选取；结合“同一脚本路径反复 POST、文件操作请求约 400KB、响应为高熵密文”即可在全流量或 Web 日志中识别冰蝎客户端。

## 原理

- **Content-Type 由脚本类型决定**：客户端发请求前按 shell 类型调用 `initHeadersByType`：php → `application/x-www-form-urlencoded`；aspx → `application/octet-stream`；jsp/asp 分支不设置 Content-Type。随后 `initHeadersCommon` 统一追加 `Accept: application/json, text/javascript, */*; q=0.01`、`Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7`、`Connection: Keep-Alive`、`Accept-Encoding: gzip`。
- **UA 来自内置常量数组**：客户端常量 `userAgents` 内置 10 条 UA，版本集中在 Chrome 84/89/96/99、Firefox 79/87/98、Edge 99、IE 11，平台覆盖 Windows NT 6.3/10.0 与 macOS 10_15/10.15/11_2_3，每次请求随机选一条。它们不是运行环境真实浏览器，版本老旧且能在同一源上跨平台轮换。
- **为什么能作为强特征**：正常业务客户端不会以 Chrome 的 UA 向单个 `.aspx` 路径持续 POST 二进制体（`application/octet-stream`），也极少带 `q=0.01` 的固定 Accept 与固定 Accept-Language；冰蝎请求体是加密的、内容无法直接匹配，但头部组合 + 访问模式仍可聚类。
- **文件操作大包**：列目录、读文件、上传/下载等文件管理操作复用同一份带大量注释的插件 payload，请求体膨胀到约 400KB；命令执行、基本信息等小操作请求很小。于是同一马路径会呈现“小包/大包”分明的周期性会话，这是很直观的旁路特征。
- **局限**：攻击者可在客户端或中间层改写 UA/Header；新版本可能更换 UA 列表；因此该指纹是强启发式而非绝对签名，需要与解密结果、马文件或主机侧证据交叉验证。

## 触发条件

- 有 NTA/全流量（Zeek/Suricata/NDR）、WAF 或 Web 访问日志，能取到 UA、Content-Type、请求方法与请求体大小。
- 攻击者使用未改动头部配置的冰蝎 4.0.x 客户端（观察样本为 v4.0.6）。
- 目标存在可访问的 PHP/ASPX/ASP/JSP 马路径（常见于上传目录、随机命名脚本或伪装静态文件）。
- 需要最终确认时可取得马文件/密钥做解密（见关联卡）。

## 利用步骤（检测流程）

1. 从流量中提取所有 POST，保留时间、源 IP、URI、UA、Content-Type、请求长度、响应长度。
2. 按 Content-Type 分流：PHP 马请求多为 `application/x-www-form-urlencoded`；ASPX 马为 `application/octet-stream` 且 UA 却是浏览器；ASP/JSP 可能没有 Content-Type。
3. 匹配 UA 集合：Chrome 84/89/96/99、Firefox 79/87/98、Edge 99、IE 11 等旧版本；统计同一源 IP 使用的 UA 种类数与切换频率，同一会话轮换多条旧 UA 权重更高。
4. 匹配固定头：`Accept: application/json, text/javascript, */*; q=0.01`、`Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7`、`Connection: Keep-Alive`、`Accept-Encoding: gzip`。
5. 看访问模式：同一脚本路径短时间内连续 POST；约 400KB 的大请求（文件操作）夹杂小请求（命令/信息）；响应为高熵密文且常带 `Transfer-Encoding: chunked`。
6. 告警后验证：定位马文件提取 `$key` 或连接密码，按关联卡解密请求/响应，确认 `func|params` 与 `eval`；或在主机侧用马文件特征扫描。

## PoC

无攻击 PoC（检测场景）。可用如下思路落规则：

```bash
# Zeek http.log：筛 POST 与异常大的请求体
zeek-cut id.orig_h method uri user_agent request_body_len < http.log | \
  awk -F'\t' '$2=="POST" && $5>100000'

# 访问日志：同一 URI 的 POST 频次与大包
awk '{print $1,$7,$9,$10}' access.log | sort | uniq -c | sort -rn | head

# 头部日志：固定 Accept/Accept-Language 与旧版 UA 组合（示例正则，需按完整 10 条 UA 扩充）
grep -Ei 'Chrome/(84\.0\.4147|89\.0\.4389|96\.0\.4664|99\.0\.4844)|Firefox/(79|87|98)\.0|Trident/7\.0' http_headers.log
```

说明：UA 列表取客户端 v4.0.6 常量，生产规则建议用完整 10 条精确匹配；检测结果需人工确认，避免把正常老旧终端误报为冰蝎。

## 变体与关联

- [[defense-forensics-behinder-php-webshell-traffic-decrypt]]、[[defense-forensics-behinder-php-default-key-aes-ecb-traffic-decode]]、[[defense-forensics-behinder-php-rc4-xor-modified-traffic]]：确认头部指纹后，按马类型/算法选择解密方法。
- [[defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt]]、[[defense-forensics-behinder-jsp-static-key-password-extraction]]：JSP 马常由内存马注入，请求可能不带 Content-Type。
- [[pentest-c2-behinder-ja3-tls-fingerprint-evasion]]：冰蝎在 TLS 层同样有指纹与规避面；本卡关注应用层头部。
- 变体：攻击者修改客户端常量或经代理改写 UA 后，UA 指纹失效；应保留 Accept/Accept-Language、大小、路径等弱特征组合。
- 边界：CDN/WAF 改写头部、日志不含请求体大小、HTTP/2 头部压缩导致原始头不可见时，需用 pcap 或 TLS 解密后分析。

## 检测与防御

- 检测：对 Web 入口建立“脚本路径 + 固定 Accept + 旧 UA + 高频 POST”关联规则；对 UA 为浏览器却向 ASPX 发 `application/octet-stream` 的请求直接告警；监控上传目录中新出现的可执行脚本。
- 检测：把冰蝎 4.0 的 10 条 UA 作为情报列表入库，并随版本更新维护。
- 防御：上传目录禁止脚本解析、扩展名白名单、禁用 `eval`/`assert` 与危险函数、Web 服务最小权限；WAF 拦截已知头部组合并限制单路径高频 POST。
- 响应：命中后隔离主机、保存 pcap 与马文件、按关联卡解密历史流量，评估命令执行与数据外带范围。

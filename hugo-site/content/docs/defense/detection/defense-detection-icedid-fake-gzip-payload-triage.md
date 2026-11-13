---
id: defense-detection-icedid-fake-gzip-payload-triage
title: IcedID 伪装 gzip 的下载载荷：Content-Type application/gzip 与 1f8b08 头均为假，解压失败后由加载器按文件流释放持久化 DLL
type: scenario
domain: defense
path: defense/detection
technique: icedid-fake-gzip-payload-triage
tags:
- traffic-analysis
- icedid
- bokbot
- gzip
- file-type-masquerade
- malware-delivery
- detection
- suricata
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V493
  verified_at: '2026-11-11T00:10:39+08:00'
  notes: 已对照原文与图06-10核对：modalefastnow.com→212.18.104.12（图21）、GET / 携带 _gads/_gat/_ga/_u/_io/_gid Cookie、响应 Content-Type application/gzip 且文件头 1f 8b 08（图07）、7-Zip 解压 Donkey.txt 报数据错误（图08）、释放 %LOCALAPPDATA%\qianlan\Vijeum3.dll（图09）、ET Win32/IcedID M4/Cookie 告警与 skrechelres/jerryposter/jkbarmossen 情报（图01/10-13）均一致。未验证点：原文未展开文件流解码算法，卡片已如实标注；未动态复现；原文无版本，未设 affected_versions；frontmatter 无 sources/source_url
url: /docs/defense/detection/defense-detection-icedid-fake-gzip-payload-triage/
draft: false
kb_aliases:
- 假 gzip 载荷
- 1f8b08 解压失败
- IcedID 下载载荷
- Vijeum3.dll
- ET MALWARE Win32/IcedID Requesting Encoded Binary M4
- ET MALWARE Win32/IcedID Request Cookie
---

## 一句话结论

IcedID（BokBot）变种向 C2 域名请求持久化载荷时，HTTP 响应头写 `Content-Type: application/gzip`、文件开头也是 `1f 8b 08` 的 gzip 魔数，但把响应体导出后 `gzip -d`/解压工具会失败——它并不是真正的 gzip 压缩包，而是由木马加载器按文件流处理后释放的加密/编码容器；最终落地的持久化 DLL（示例 `%LOCALAPPDATA%\<user>\Vijeum3.dll`）本身也是具备完整功能的 IcedID 变体。研判时不能凭 `Content-Type` 或文件头判断文件性质。

## 原理

- **`Content-Type` 与文件魔数都由服务端/载荷作者控制**：HTTP 响应头只是声明，不保证内容真实；在任意数据前加 `1f 8b 08` 也能通过“看文件头”的浅层检查。真正的 gzip 需要后续的 deflate 流、CRC32 与 ISIZE 校验，魔数正确不代表可解压。
- **为什么做成“解压失败”的假 gzip**：邮件/网络网关与沙箱常用“解压 → 扫描内容”的流水线；不可解压的数据会被当作损坏文件跳过或降低优先级，而木马自己有解码逻辑，能把它还原为 DLL。假 gzip 同时满足“看起来像压缩包”和“扫描器解不开”两个目的。
- **加载器的文件流处理**：IcedID 的下载器/加载器把响应体读入内存后，按自己的算法逐段处理（可能是 XOR/流式解密或自定义容器），再把结果写成 DLL 并加载；原文只观察到“经过文件流处理后释放 DLL”，具体算法未展开，需要动态调试或内存 dump 确认。
- **持久化 DLL 即完整木马**：释放的 `Vijeum3.dll` 不是只有下载功能的小模块，而是 IcedID 变体本体（拥有独立 C2 通信与功能模块），后续会连接 `skrechelres.com`、`jerryposter.com`、`jkbarmossen.com` 一类 C2 域名，并加载 BackConnect VNC 模块。
- **流量侧的稳定线索**：ET 规则 `Win32/IcedID Requesting Encoded Binary M4` 与 `Win32/IcedID Request Cookie` 匹配请求中的编码二进制与 Cookie 特征；DNS 查询（示例 `modalefastnow.com` → `212.18.104.12`）与 HTTP 响应头/载荷长度可作为关联证据。

## 触发条件

- 主机已执行 IcedID 投放链（如 VBS 释放 DLL 并由 `regsvr32.exe` 执行），产生对 C2 域名的 HTTP/HTTPS 请求。
- 网络侧能看到明文 HTTP，或具备 TLS 解密/端点侧抓包能力；否则只能看到 SNI/域名与流量节律。
- 载荷为“假 gzip/自定义编码容器”形态；若样本换成真压缩包或纯加密二进制，魔数/解压表现会不同。
- 分析侧能导出 HTTP 响应体并在隔离环境尝试解压/动态调试。

## 利用步骤

> 以下为防御方流量研判步骤，不是攻击步骤。

1. **从告警/域名入手**：用 ET IcedID 规则告警或 DNS 查询定位 C2 域名（示例 `modalefastnow.com`），解析出其 IP（示例 `212.18.104.12`）。
2. **过滤会话**：`ip.addr==<C2-IP> && (http.request || tls.handshake.type==1)`，找出木马请求与响应；记录请求 Cookie/编码特征。
3. **导出响应体**：Wireshark 导出 HTTP 对象，保存为文件；记录响应头 `Content-Type: application/gzip` 与开头字节 `1f 8b 08`。
4. **验证压缩真伪**：`gzip -d`/7-Zip 解压，确认失败；用 `file`/十六进制查看后续字节是否缺少合法 deflate 结构，判断为伪装而非损坏下载。
5. **动态分析载荷处理**：在隔离环境运行投放链，监控进程读取响应体后的内存变换与 `CreateFile`/`WriteFile` 行为，定位最终落地的 DLL 路径（示例 `%LOCALAPPDATA%\<user>\Vijeum3.dll`）。
6. **继续跟进**：提取 DLL 的 C2 配置与功能模块（BackConnect VNC 等），用 ET `W32.DarkVNC Variant Checkin` 等规则关联回连流量；如后续拉取 `http64.exe`，其可能是 Cobalt Strike 载荷（见关联卡）。

## PoC

```text
# Wireshark 定位
dns.qry.name == "modalefastnow.com"
ip.addr == 212.18.104.12 && (http.request || tls.handshake.type == 1)

# 导出响应体后验证 gzip（预期失败，说明不是真正 gzip）
gzip -dc payload.bin
# gzip: payload.bin: not in gzip format
```

```text
# 关键观察点
响应头: Content-Type: application/gzip
文件头: 1f 8b 08
解压结果: 失败（非合法 deflate/CRC 结构）
最终落地: %LOCALAPPDATA%\<user>\Vijeum3.dll（完整 IcedID 变体）
后续 C2: skrechelres.com / jerryposter.com / jkbarmossen.com（示例情报标记）
```

无独立可执行 PoC；具体解码算法需从样本/内存中还原。

## 变体与关联

- **伪装格式变体**：假 zip/7z/rar、带合法魔数的加密二进制、Content-Type 与扩展名不一致；共同点是“浅层检查像压缩包，实际由加载器解码”。
- **后续模块**：IcedID 变体启动 BackConnect VNC（反向 VNC，DarkVNC 变体）回连控制端；再往后可能下载 Cobalt Strike `http64.exe` 并每 5 秒心跳、下载 ScreenConnect 等 RMM 工具。
- **关联卡**：404 TDS 重定向投递 VBS/regsvr32（前置入口）、Cobalt Strike HTTP beacon 弱特征检测、BackConnect/DarkVNC 流量检测、IcedID 家族分析。
- **边界**：原文未给出解码算法与 DLL 内部配置细节；仅凭“解压失败”不能定性为 IcedID，需要结合 ET 规则、域名情报与主机侧释放物。

## 检测与防御

- **流量检测**：部署 ET `Win32/IcedID Requesting Encoded Binary M4`、`Win32/IcedID Request Cookie` 等规则；对 `application/gzip` 响应做实际解压校验，解压失败且体积较大/熵高的载荷重点告警。
- **文件/沙箱**：网关沙箱对下载载荷执行“解压 + 动态执行”双路径，不因解压失败放行；对释放的可执行 DLL 做签名/哈希/行为分析。
- **终端**：监控 `%LOCALAPPDATA%`/`%temp%` 下随机名 DLL 的创建与 `regsvr32.exe`/`rundll32.exe` 加载；关联 IcedID 的 C2 域名与进程外联。
- **网络**：对已知 IcedID C2 域名/IP 做阻断与情报匹配；对周期性 HTTP 请求、异常 Cookie、编码二进制做威胁狩猎。
- **响应**：隔离主机，提取 `Vijeum3.dll` 与内存镜像，排查 BackConnect VNC、Cobalt Strike、ScreenConnect 等后续控制通道。

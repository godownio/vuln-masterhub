---
id: web-java-deserialization-finereport-channel-frchannel-memshell-suo5
title: FineReport channel 反序列化实战：FrChannel 注入内存马与 suo5 内网隧道
type: scenario
domain: web
path: web/java/deserialization
technique: finereport-channel-frchannel-memshell-suo5-tunnel
tags:
- java
- finereport
- deserialization
- channel
- memshell
- suo5
- tunnel
- internal-network
- fscan
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V72
  verified_at: '2026-11-05T16:28:38+08:00'
  notes: 已对照原文与图57-61核对：FrChannel v3 选 JacksonSignedObject，注入 Behinder(p@ss01)/suo5 内存马，suo5 客户端 127.0.0.1:1111 代理后 fscan 扫内网；原文未给完整命令回显，confidence medium 合理；未本地复现
url: /docs/web/java/deserialization/web-java-deserialization-finereport-channel-frchannel-memshell-suo5/
draft: false
kb_aliases:
- FrChannel v3
- 帆软 channel 工具利用
- JacksonSignedObject 链
- Behinder 内存马
- suo5 内存马隧道
- 帆软不出网代理
---

## 一句话结论

对暴露的帆软 `/webroot/decision/remote/design/channel` 使用 FrChannel 类工具选择 `JacksonSignedObject` 利用链，可执行命令或注入 Behinder/suo5 内存马；当目标主机不出网、反弹 shell 失败时，用 suo5 内存马建立 HTTP 隧道把内网流量代理出来，再跑 fscan 扫描内网段并继续横向。

## 原理

- 帆软 channel 端点把请求体交给反序列化器（详见同目录的 channel 反序列化卡）；FrChannel 类工具封装了“选择利用链 + 构造序列化 payload + Gzip 封装”的流程，界面上可选 `JacksonSignedObject` 等链，并提供“执行命令 / behinder内存马 / suo5内存马 / jndi注入”按钮。
- `JacksonSignedObject` 链利用 Jackson 反序列化与 `SignedObject` 的组合触发任意 getter/构造，最终执行命令；工具会根据目标版本/黑名单选择可用链，失败时换链重试。
- 命令执行只证明 RCE；实战更常用内存马：Behinder 内存马注册 filter/servlet，连接密码由工具生成（如 `p@ss01`），不需要落盘文件，规避文件查杀与目录权限限制。
- 目标主机可能“不出网”（无法主动回连 C2），此时反向 shell/vshell 会掉线；suo5 内存马通过 HTTP 请求-响应复用建立双向隧道，客户端只需能访问 webshell URL，即可把本地端口代理到目标内网。
- 隧道建立后，攻击者在本机配置代理（如 `127.0.0.1:1111`），用 fscan 扫描 `10.0.0.0/8`、`192.168.0.0/8`、`172.200.0.0/8` 等常见内网段，或先用 netspy 探测可达网段；Proxifier 把工具流量导入隧道，访问 FTP、打印机、摄像头等未授权/弱口令资产。
- 根因仍是 channel 反序列化；本卡关注“工具化利用 + 内存马 + 不出网隧道 + 内网扫描”的完整后利用路径。

## 触发条件

- 目标为存在 channel 反序列化漏洞的 FineReport/FineBI 版本，`/webroot/decision/remote/design/channel` 可达；
- 目标 classpath 存在与版本匹配的 gadget（Jackson/SignedObject 等），且未被黑名单拦截；
- 攻击者可访问 webshell URL（内存马注入成功后）；
- 目标主机可被 Web 请求驱动访问内网（即使不能主动出网）。

## 利用步骤

1. 指纹识别帆软版本，确认 `/remote/design/channel` 可达；用 DNSLog/回显测试反序列化是否触发。
2. 打开 FrChannel 类工具，填入 channel URL，选择 `JacksonSignedObject` 链；先用“执行命令”运行无害命令（如 `whoami`）验证。
3. 选择“behinder内存马”注入，记录工具生成的连接密码与内存马路径；用 Behinder 连接，确认命令执行/文件管理。
4. 若目标不出网、反弹 shell 失败，选择“suo5内存马”注入；记录 suo5 的内存马 URL 与连接密码。
5. 在本地启动 suo5 客户端，目标填 webshell URL、代理填 `127.0.0.1:1111`，模式选自动/全双工，连接成功后本地 1111 即为通往目标内网的 HTTP 代理。
6. 用 Proxifier/ proxychains 把 fscan 流量导入代理，扫描常见内网段；解析 fscan 输出，优先访问 FTP、打印机、摄像头、未授权管理后台等。
7. 在授权范围内验证内网资产，记录证据；测试后清理内存马并报告。

## PoC

```text
# FrChannel 工具界面（示意）
URL: http://target.example.com/webroot/decision/remote/design/channel
利用链: JacksonSignedObject
[执行命令] [behinder内存马] [suo5内存马] [jndi注入]
输出信息:
  注入behinder内存马路径: /*
  连接密码: <PASSWORD>
```

```text
# suo5 客户端（示意）
目标: http://target.example.com/<memshell-path>
代理: 127.0.0.1:1111
模式: 自动
[连接]
```

```bash
# 通过代理扫描内网（示意）
fscan.exe -h 10.200.1.1/8 -o 10.txt
fscan.exe -h 192.200.1.1/8 -o 192.txt
fscan.exe -h 172.200.1.1/8 -o 172.txt
```

原文使用 FrChannel 注入内存马、suo5 建立隧道后用 fscan 扫描内网，并通过 Proxifier 访问内网 FTP/打印机等资产；具体命令回显未完整展示，故本卡 confidence medium。

## 变体与关联

- 变体：利用链可换 TreeBag、TextAndMnemonicHashMap、ImmutableSetMultimap 等；按目标版本黑名单选择，详见 [[web-java-deserialization-finereport-channel-gzip-safeinvocation]]。
- 变体：内存马可用 Behinder、Godzilla、suo5、Neo-reGeorg 等；suo5 适合 HTTP 出站受限但 Web 入口可达的场景。
- 关联：[[web-java-deserialization-finereport-channel-gzip-safeinvocation]]（channel 漏洞原理与 gadget 列表）、[[web-java-component-finereport-builtin-user-default-password]]（V11 后台凭据）。
- 边界：channel 已修复/禁用、gadget 被黑名单拦截、webshell 被 WAF/EDR 清除、目标完全无法访问内网时，链条不成立。

## 检测与防御

- 检测：`/remote/design/channel` POST 请求体以 Gzip 魔数 `1f 8b` 开头、解压后为 Java 序列化数据；FrChannel/Behinder/suo5 的请求特征；Web 进程中出现异常 filter/servlet/内存马类；短时间内对大量内网地址的扫描流量。
- 防御：升级帆软至修复版本，禁用/限制 `/remote/design/channel`；对反序列化启用 JEP 290 过滤与黑名单。
- 防御：限制 Web 服务器出站与内网可达范围，监控异常代理/隧道流量；对 Web 进程内存与新增 filter/servlet 做巡检。
- 防御：内存马检测（Java agent/RASP）、WebShell 流量检测；对 fscan 常见扫描特征与内网横向告警。

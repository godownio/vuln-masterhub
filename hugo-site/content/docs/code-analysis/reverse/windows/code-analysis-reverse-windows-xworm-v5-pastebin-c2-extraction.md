---
id: code-analysis-reverse-windows-xworm-v5-pastebin-c2-extraction
title: XWorm V5.2 样本识别与 Pastebin 死信箱 C2 提取：从 raw/zNCj2Utm 取 localbeheaders.mcgo.io:4411
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: xworm-v5-pastebin-dead-drop-c2-extraction
tags:
- reverse
- windows
- dotnet
- xworm
- rat
- pastebin
- dead-drop
- c2
- malware-analysis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V323
  verified_at: '2026-11-08T16:23:23+08:00'
  notes: 已对照 content.md 第 65-85 行与 img/14-18 核对：DIE PE32/.NET v4.0.30319/VB.NET/2024-05-15，混淆类名方法名，dnSpy 中 'XWorm V5.2' 版本串、Thread.Sleep 反沙箱、new Thread 访问 https://pastebin.com/raw/zNCj2Utm，页面返回 localbeheaders.mcgo.io:4411，均与卡一致。已修正原卡错误归因：原文是 GitHub 免杀工具投毒活动（Origami/Scantime Crypter 仓库），非 Festi；已改为 GitHub 免杀工具投毒活动并同步 staging。原子性：单一 XWorm 样本识别 + Pastebin 死信箱 C2 提取场景，合格。未验证点：未运行样本，Pastebin 内容可能变动；原文未给版本区间。dedup 工具候选为空，人工检索库内无其他 XWorm/Pastebin 同链卡。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-xworm-v5-pastebin-c2-extraction/
draft: false
kb_aliases:
- XWorm V5.2
- XWorm 配置提取
- Pastebin C2
- pastebin.com/raw/zNCj2Utm
- localbeheaders.mcgo.io
- .NET RAT 分析
- 死信箱 C2
---

## 一句话结论

GitHub 免杀工具投毒活动（Origami/Scantime Crypter 仓库）最终投递的 .NET 远控样本经反编译与动态调试确认是 XWorm V5.2：样本用混淆的类名/方法名隐藏逻辑，运行时由后台线程访问 `https://pastebin.com/raw/zNCj2Utm` 这个 Pastebin 死信箱，读取返回内容得到真实 C2 `localbeheaders.mcgo.io:4411`；分析时搜索版本字符串、定位线程中的 Pastebin URL、直接请求该 raw 地址即可在不解密样本配置的情况下提取 C2。

## 原理

- **样本形态**：载荷为 PE32/.NET（原文 Detect It Easy 显示 .NET v4.0.30319、VB.NET、时间戳 2024-05-15），dnSpy 中类名/方法名被混淆成 `Gp3VNHYSYM4j...`、`6PD0swk...` 一类随机字符串，静态可读性差。
- **版本识别**：在调试器局部变量/解密后的字符串中可以看到 `"Worm V5.2"` / `"XWorm V5.2"`，这是 XWorm 家族的特征版本串；结合代码结构（线程、Sleep 反沙箱、远程配置）可确认家族与版本。
- **Pastebin 死信箱**：XWorm 不把 C2 直接硬编码在样本里，而是启动一个线程访问 Pastebin raw 页面；`https://pastebin.com/raw/zNCj2Utm` 返回的纯文本就是 C2 地址 `localbeheaders.mcgo.io:4411`。这样攻击者可以随时更换 C2 而不重新编译/投递样本，也让静态字符串搜索只能找到 Pastebin URL 而非 C2。
- **为什么用 Pastebin**：公开粘贴服务匿名、稳定、HTTPS、无需自建基础设施；样本只需一个 URL，防御方难以仅凭域名判定恶意（Pastebin 本身是合法服务）。分析者拿到 URL 后直接请求即可获得配置，不需要运行样本。
- **动态确认**：原文在 dnSpy 中对线程/网络调用下断点，观察到请求 Pastebin 并把返回内容写入局部变量，随后连接 `localbeheaders.mcgo.io:4411`，确认了配置来源。

## 触发条件

- 样本为 XWorm（V5.2 或相近版本）的 .NET 载荷，运行时能访问外网（Pastebin 与 C2）。
- 分析环境可反编译 .NET（dnSpy/ILSpy）并可选择性地动态调试（注意反调试/反沙箱）。
- Pastebin 页面仍在线；若被删除，则需从样本中恢复备用 C2 或历史缓存。
- 仅用于授权恶意样本分析。

## 利用步骤

1. 用 Detect It Easy 确认 PE32/.NET/编译器与时间戳；用 dnSpy 打开，观察混淆的类/方法名与入口。
2. 搜索字符串 `XWorm`、`Worm V5`、`pastebin`、`raw/`、`http`；若字符串被加密，动态调试并在字符串解密函数/网络调用处下断。
3. 定位启动线程的代码（`new Thread(...).Start()`），跟踪线程方法中的 HTTP 请求；在 `WebClient.DownloadString`/`HttpClient`/`WebRequest` 调用处下断，读取 URL 参数与返回内容。
4. 或直接提取 Pastebin URL（示例 `https://pastebin.com/raw/zNCj2Utm`），在隔离环境用 curl 请求，得到 C2 `localbeheaders.mcgo.io:4411`。
5. 记录 IOC：Pastebin URL、C2 域名/端口、版本串、样本哈希；进一步分析 C2 协议与插件下载行为。
6. 若 Pastebin 已失效，检查样本中是否有备用配置/加密字符串，或从网络流量/沙箱报告中恢复。

## PoC

```text
# 从样本中提取到的死信箱 URL（原文）
https://pastebin.com/raw/zNCj2Utm

# 返回内容（原文）
localbeheaders.mcgo.io:4411
```

分析要点：dnSpy 中搜索 `pastebin.com/raw/`，或在 `WebClient.DownloadString` 等调用处下断读取局部变量；不要直接运行样本，优先静态提取 + 隔离环境请求。

## 变体与关联

- **变体**：死信箱可换成 Pastebin、GitHub raw/gist、Dropbox Paper、Telegram 频道、云笔记、DNS TXT；C2 可加密/编码后存放，样本运行时再解密。
- **关联**：[[pentest-c2-github-raw-payload-hosting-commit-attribution]]（GitHub raw/gist 作为载荷/配置托管）；[[pentest-c2-dropbox-paper-og-title-dead-drop]]（云文档标题死信箱）；[[pentest-initial-access-github-trojanized-fud-crypter-tools]]（本样本的投毒入口）；[[pentest-c2-powershell-amsiinitfailed-reflection-bypass]]（投递链中的 AMSI 绕过）。
- **边界**：Pastebin 内容被删除/更改后无法复现；样本可能有多级配置或备用 C2；强反调试/反沙箱会阻碍动态确认。

## 检测与防御

- **网络检测**：监控对 `pastebin.com/raw/`、`gist.githubusercontent.com`、`raw.githubusercontent.com` 等公共托管服务的程序化访问（尤其是非浏览器进程），以及随后对陌生域名端口的连接；对 `localbeheaders.mcgo.io:4411` 等已知 IOC 阻断。
- **端点检测**：.NET 进程从公共粘贴服务下载文本后立即发起长连接/心跳；dnSpy/EDR 监控 `WebClient.DownloadString` 等调用。
- **样本检测**：YARA/字符串匹配 `XWorm`、`Worm V5`、`pastebin.com/raw/`、版本串；.NET 混淆特征与线程/Sleep 反沙箱行为。
- **防御**：限制服务器/终端对 Pastebin 等匿名粘贴服务的出站访问；启用 DNS/代理日志与威胁情报匹配；对邮件/下载来源的 .NET 可执行文件做沙箱分析。
- **响应**：发现 XWorm 后隔离主机、阻断 C2、检查持久化（Run 键/计划任务/服务）与横向移动痕迹。

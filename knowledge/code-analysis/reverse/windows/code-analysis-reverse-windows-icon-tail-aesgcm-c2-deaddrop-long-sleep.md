---
id: code-analysis-reverse-windows-icon-tail-aesgcm-c2-deaddrop-long-sleep
title: GitHub raw 图标尾部隐写 base64+AES-GCM 加密 C2：长休眠后批量拉取解密，流量伪装成正常图标下载
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: icon-tail-stego-base64-aesgcm-c2-deaddrop
aliases:
- 图标尾部隐写 C2
- $ 分隔符尾部载荷
- IconStorages 死信箱
- 图标文件 C2 分发
- AES-GCM 加密配置
- 长睡眠沙箱规避
tags:
- windows
- c2
- steganography
- aes-gcm
- dead-drop
- sandbox-evasion
- github-raw
- malware-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V548
  verified_at: '2026-11-11T22:03:06+08:00'
  notes: 已对照原文（xz.aliyun.com/news/13089）与全部24张图核对：图18 汇编出现 https://raw.githubusercontent.com/IconStorages/images/main/icon%d.ico 与 UA Mozilla/5.0；图19 十六进制可见 0x24('$') 后接长 base64（SKQAAAEzW/ARcvV...）；图20 伪代码从缓冲区尾部向前扫描，遇 '$'(0x24) 停止并调用解密，注释分别标注“定位尾部base64数据”“解密尾部base64数据”，循环内还有 1000*(a3+v9%(a2-a3)) 的随机 Sleep 抖动；图21 BCryptOpenAlgorithmProvider(AES)+ChainingModeGCM+BCryptGenerateSymmetricKey(0x20 字节)+两次 BCryptDecrypt；图22-23 解密现场与解出 https://officeaddons.com/technologies；图24 批量解出 icon0-icon15 共 16 个 C2（officeaddons.com、sourceslabs.com、msstorageazure.com、akamaitechnologies.com 变体、azureonlinestorage.com、msedgepackageinfo.com、qlcloudservice.com、pbxsources.com、officestoragebox.com、visualstudiofactory.com、azuredeploystore.com、msstorageboxes.com、3cx.com/blog 诱饵、zacharryblogs.com、pbxclouddeservices.com）；图16 确认 604800 秒=7 天。修正：(1) 原文“两次 BCryptDecrypt”实为先空输出取长度、LocalAlloc 后再解密，已精确化；(2) 删除截图中无依据的“首字节按 ICO 数据结构校验，不匹配则丢弃”表述；其余原理/步骤/判据与截图一致。dedup：与 pentest-c2-github-raw-payload-hosting-commit-attribution（raw
    托管明文 PowerShell）及 pentest-initial-access-jpg-marker-stego-vbs-nanocore-loader（JPG 标记段 Base64+Assembly.Load）均为不同载体/加密/用途，非同链；库内无 IconStorages 相关卡。未验证点：C2 已失效、原文未取得最终 payload（卡内已注明）；未实际下载图标离线解密；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

恶意模块把 C2 配置切成多份，逐份 base64+AES-GCM 加密后拼接在公开 GitHub 仓库合法 `.ico` 图标的尾部、以 `$` 与图片数据分隔；被感染主机休眠约 7 天后才批量请求这些图标，按尾部数据解密出多个伪装成合法 SaaS 域名的 C2 地址——在流量侧看起来只是一次普通的 CDN/图床图标下载，静态扫描图标也只会看到一张正常图片。

## 原理

- **为什么藏在图标尾部**：ICO/图片解析器只读文件头部与结构字段，尾部附加的任意字节不影响图片正常显示；公开图床/CDN 上的图标是"正常静态资源"，防火墙与代理很难仅凭域名或 MIME 判定可疑。把配置放在公开可读的第三方仓库，攻击者不需要自建 C2 即可完成"死信箱"（dead-drop）投放，且能随时替换内容。
- **为什么用 `$` 分隔**：图片二进制中 `$`（0x24）出现概率低，解析器从文件尾部向前扫描定位最后一个 `$`，其后的数据即为 base64 密文；即使图片本身更新，尾部数据与图片数据的边界仍可确定。尾部常规表现为 base64 字符集（大小写字母、数字、`+/`、`=`）。
- **为什么 base64 + AES-GCM**：base64 让密文在文本编辑器/字符串扫描器里呈现为普通编码，不出现二进制特征；AES-GCM 同时提供机密性与完整性校验（认证标签），解密失败即说明数据被篡改或已失效，样本可以静默跳过，降低被投毒/被蜜罐识别的概率。密钥与 nonce 硬编码在模块内，32 字节对称密钥经 `BCryptGenerateSymmetricKey` 导入。
- **为什么要批量下载多个图标**：C2 列表被拆散在多张图标里（本例 `icon0`~`icon15`），单张图标被删除或替换不会让整条链失效，提高可用性与抗打击能力；同时每次请求都是一个"正常"图片请求，混在正常应用流量中。
- **为什么先休眠约 7 天**：动态沙箱通常只运行几分钟到几十分钟，长休眠让样本在沙箱窗口内保持"无外联、无恶意行为"；真实受害主机在数天后再外联，也能错开样本首次被提交分析、规则被更新的时间差。
- **为什么 C2 域名要伪装**：解密出的地址采用 `officeaddons.com`、`sourceslabs.com`、`msstorageazure.com`、`akamaitechcloudservices.com` 等仿冒微软/云厂商风格的域名，靠"看起来像正常 SaaS/云存储"降低人工研判与域名信誉系统的怀疑；其中还混入真实厂商域名（如 3CX 官方博客）作为噪声/诱饵。

## 触发条件

- 恶意模块已获得执行（如经白加黑侧加载进入宿主进程）。
- 主机可访问外部 HTTPS，尤其是 `raw.githubusercontent.com` 等代码托管/图床域名未被阻断。
- 样本内硬编码的图标 URL 模板、`$` 分隔符与 AES-GCM 密钥/nonce 与投放端一致；对应图标文件仍在线上（本例分析时 C2 已失效，最终 payload 未能取得）。
- 休眠计时完成（约 7 天），或分析者手工跳过/缩短等待逻辑。

## 利用步骤

1. 在公开代码托管仓库创建图片目录（本例为 `IconStorages/images/main/icon<N>.ico` 形态），把正常图标作为载体上传。
2. 将 C2 配置分片，每片用 base64 编码后再 AES-GCM 加密（32 字节密钥、随机/固定 nonce 与认证标签），把密文追加到图标文件尾部，并在图片数据与密文之间插入 `$` 分隔符。
3. 恶意模块启动后先休眠约 7 天；随后按 `icon0`、`icon1`… 顺序循环请求各图标 URL。
4. 对每个响应缓冲区从尾部向前扫描 `$`，取其后的 base64 字符串；base64 解码后调用 `BCryptOpenAlgorithmProvider("AES")` + `BCryptSetProperty(ChainingModeGCM)` + `BCryptGenerateSymmetricKey` 导入硬编码密钥，先以空输出调用 `BCryptDecrypt` 取得所需长度、`LocalAlloc` 后再调用一次 `BCryptDecrypt` 解密并校验 GCM 认证标签。
5. 解析明文得到 C2 地址列表（本例共 16 个，含真实厂商域名作诱饵），进入下一阶段拉取/通信；文中分析时这些地址已下线，未能取得最终 payload。
6. 迭代变体：每次分析可批量解所有图标，得到完整 C2 集合（正文附有批量解密脚本的运行结果截图）。

## PoC

```text
# 分析侧最小复现路径（不执行样本，仅离线解密）
1) 从样本中提取：图标 URL 模板、$ 分隔符、AES-GCM key/nonce 与图标编号范围
2) 逐个下载/从缓存取图标文件，从尾部向前找最后一个 '$'
3) 取 '$' 之后的数据做 base64 解码 -> 得到 AES-GCM 密文（含认证标签）
4) 用样本内密钥/nonce 解密，得到 C2 URL；批量遍历 icon0..iconN 得到完整 C2 列表
5) 用解出的域名做信誉与历史解析核查（注意这些域名可能已被攻击者弃用/被他人注册）
```

```text
判据：图标文件尾部存在 '$' + 长 base64 串，且图片解析正常；
模块内出现 InternetOpenUrl/HttpQueryInfo 循环 + 从缓冲区尾部反向扫描 '$' 的循环；
随后调用 BCryptOpenAlgorithmProvider(AES)+ChainingModeGCM+BCryptDecrypt；
解出的明文为 URL/域名列表，且域名风格仿冒云厂商/SaaS。
```

## 变体与关联

- 关联：[[code-analysis-reverse-windows-3cx-signed-installer-ffmpeg-dll-sideload-rc4-memory-dll]]（本卡是 3CX 链中 `ffmpeg.dll` 内嵌 DLL 之后的外联阶段）；[[dotnet-bitmap-stego-multistage-reflective-load]]（另一种图片隐写：把 PE 字节写进位图像素，属于本地资源隐写，与本卡"远程图标尾部 + 加密 C2"不同）。
- 变体：载体可换成 PNG/JPG/字体/证书/README 等任意可公开托管的静态文件；`$` 可换成其他低频分隔符或固定长度尾部；AES-GCM 可换成 RSA 封装密钥、ChaCha20 或先压缩再加密；死信箱可换成 pastebin、网盘、社交平台图片、区块链交易备注等。
- 边界：图标文件被删除/替换、仓库被平台封禁，链即断（本例 C2 已失效）；出口网络若阻断 GitHub raw 或对图床域名做 TLS 检查，模块取不到配置；硬编码密钥/分隔符一旦被分析者提取，所有用同一模板投放的图标都可被批量解密，说明该手法隐蔽性依赖"没人怀疑图片"而非密码学强度外的额外保护。

## 检测与防御

- 检测：进程在启动后长时间无外联、数天后突然请求 `raw.githubusercontent.com`/图床上的 `.ico` 等图片（且 UA/进程与图片下载不符）；同一进程短时间内批量下载编号连续的图标文件；内存中出现 `$` 分隔符扫描循环与 `BCryptDecrypt` 的 AES-GCM 调用组合；解出的域名与进程已知业务不符。
- 防御：终端侧阻断或代理审计代码托管 raw 域名与常见图床的异常进程访问；对"业务进程下载图片"建立基线，偏离即告警；沙箱分析时对长 `Sleep` 做时间加速/API 拦截；威胁情报侧把公开图床/仓库尾部附加数据纳入扫描面（下载图片检查尾部异常 base64）；C2 域名用被动 DNS 与证书透明度监控。

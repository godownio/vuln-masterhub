---
id: code-analysis-reverse-windows-dotnet-assemblydescription-base64-rot13-config
title: .NET 窃密木马把配置藏进程序集 AssemblyDescription：Base64 + ROT13 解码出 Telegram Token、Chat ID 与攻击者主页
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: dotnet-assemblydescription-base64-rot13-config-extraction
aliases:
- AssemblyDescription 藏配置
- 程序集属性配置提取
- .NET 木马配置 Base64 ROT13
- AssemblyDescription base64 rot13
- dnSpy 定位主函数取配置
tags:
- dotnet
- dnspy
- malware-analysis
- config-extraction
- base64
- rot13
- telegram
- stealer
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:30:41+08:00'
  notes: 已对照原文核对；本次核对未读取图片；AssemblyDescription 取配置、Base64 后对 Token/ChatID 做 ROT13 与原文文字一致，解码顺序与具体属性读取 API 依赖 dnSpy 截图，未读图无法逐行确认
---

## 一句话结论

一类 .NET 窃密木马不把 C2 参数写在资源段或明文常量里，而是塞进程序集元数据的 `AssemblyDescription` 属性：样本运行时读该属性、整体 Base64 解码后再对 Token/ChatID 字段做 ROT13；分析时只要用 dnSpy 定位主函数并沿 `Assembly.GetCustomAttributes` 取值逻辑走一遍，就能离线还原 Telegram Bot Token、Chat ID 与作者留下的主页链接，从而直接接管外传通道做归因。

## 原理

- .NET 程序集把 `AssemblyTitle`/`AssemblyDescription`/`AssemblyCompany` 等写在元数据的 CustomAttribute 表里，任何反射 API（`Assembly.GetCustomAttribute<AssemblyDescriptionAttribute>()`）都能读到；它既不在 `.text` 常量池也不在 `.resources` 里，常规「搜字符串/看资源段」的排查容易漏过。
- 用 Base64 承载配置是因为该属性本质是字符串，二进制不安全、但可打印字符集够用；字段级再用 ROT13（对 ASCII 字母做 13 位循环位移，自逆）做一层弱混淆，足以躲开对 `bot`、`api.telegram.org`、`chat_id` 等关键字的静态关键词扫描，却不增加分析难度。
- 因此该手法属于「配置位置隐蔽 + 弱编码」而非密码学保护：只要定位到读取属性的那几行代码，解码顺序（先 Base64 后 ROT13，或按字段分别处理）就能从调用顺序直接读出来。
- 这类样本普遍把 Telegram Bot API 当免费 C2/外传通道：Token 即最高权限凭据，拿到 Token 后可调用 Bot API 读取该 bot 收到的历史消息与文件，这正是「从样本反打攻击者」之所以可行的原因。
- 由于配置完全静态可还原，样本即使不再运行也能提取全部外传参数；这也解释了为什么此类家族常配合自删除与沙箱检测——它们防的是动态行为分析，防不住静态属性读取。

## 触发条件

- 拿到的是 .NET 程序集（PE + CLR 头，`dnSpy`/`ILSpy` 可直接反编译），且未做强混淆把属性读取逻辑完全虚拟化。
- 样本配置仍以程序集属性（而非运行时下发）方式内置；若改为服务器拉取，本手法只能得到拉取地址。
- 需要 .NET 反编译器读取元数据；纯十六进制查看器只能看到 Base64 串，需自己按属性名定位再解。

## 利用步骤

1. `file`/PE 头判断是否为 .NET 程序集（存在 `BSJB`/CLR 头，或 `dnSpy` 能直接加载并显示命名空间）。
2. dnSpy 打开后先看入口点（`Main`），沿 `persistence.CheckCopy()`、注册表单实例、沙箱检测等调用顺序快速画出样本功能骨架。
3. 在主函数里找对 `Assembly.GetExecutingAssembly().GetCustomAttribute(...)` / `AssemblyDescriptionAttribute` 的引用，确认取到字符串后的处理链。
4. 按代码顺序复现解码：先对该字符串做 Base64 解码，再对 Token/ChatID 等字段做 ROT13（字母位移 13，自逆，可用同一函数还原）。
5. 得到 `bot<token>` 与 `chat_id` 后，核对样本中的外传调用路径（`sendDocument`/`sendMessage`）确认用途；同时检查配置里是否残留作者标识（主页/GitHub 链接、邮箱）用于归因。
6. 用还原出的参数在隔离环境验证外传通道（仅在授权范围内，读取该 bot 自身上报内容属取证动作）。

## PoC

解码链的最小还原（无需运行样本）：

```python
import base64, codecs

desc = "<从 dnSpy 的 AssemblyDescription 属性或元数据中读到的字符串>"
raw = base64.b64decode(desc).decode("utf-8", "replace")   # 先整体 Base64
cfg = codecs.decode(raw, "rot13")                        # 再对字段做 ROT13（自逆）
print(cfg)   # 期望看到 token=... chat_id=... 以及主页/标识字段
```

若代码是逐字段处理，则把第 2、3 步反序或对单个字段分别执行即可；ROT13 对同一字符串执行两次即还原。

## 变体与关联

- 变体：配置载体可从 `AssemblyDescription` 换成 `AssemblyTitle`、`AssemblyCompany`、`AssemblyProduct`、`AssemblyConfiguration` 或自定义 `AssemblyMetadata` 键；定位方法不变（搜属性读取 API）。
- 变体：外层编码可换成 Base64 + 偏移 XOR、反转字符串、十六进制；字段级可换成 ROT47、凯撒位移 3。
- 关联：[[code-analysis-reverse-windows-xworm-v5-aes-config-plugin-rat-capabilities]]（同为 .NET 家族，配置在资源/字段且用 AES-ECB，属强加密对照）。
- 关联：[[code-analysis-reverse-windows-blacknet-config-aes-pbkdf2-extract]]（PBKDF2+AES 的强加密配置提取范式）。
- 关联：[[hardcoded-telegram-bot-token-exfil-channel-hijack]]（拿到 Token 后可反查该 bot 收到的上报内容）。

## 检测与防御

- 检测：对 .NET 样本的元数据属性做批量审计（`dnlib`/`ilspycmd` 遍历 `AssemblyDescription` 等属性），发现长 Base64 串即尝试解码并按 ROT13/异或扇出。
- 检测：静态规则命中「程序集属性字符串 + Base64 解码 + `api.telegram.org` 运行时拼接」的组合，而非单独匹配 `telegram` 关键字。
- 防御（用户侧）：限制终端对 `api.telegram.org` 的出站访问；对自启动位置与「图标伪装成图片的可执行文件」做终端策略拦截。
- 防御（取证侧）：一旦还原出 Bot Token，应立即保存证据（该 bot 的上报记录、文件回传）并交由平台方处置，切勿用该 Token 发送任何内容以免污染证据。

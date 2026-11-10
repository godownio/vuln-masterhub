---
id: code-analysis-reverse-windows-wikiloader-c2-url-odd-index-cookie-profile
title: WikiLoader 式 C2 还原：混淆串取奇数位字符拼回 URL、Cookie 携带 Base64 主机画像、伪 WordPress 页面按标记偏移取下一段 ShellCode
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: wikiloader-c2-url-odd-index-cookie-profile
aliases:
- 奇数位字符拼接 URL
- C2 URL 字符串重建
- Cookie 主机画像 Base64
- 伪 WordPress 登录页 C2
- WikiLoader 分析
- on&gt; 标记偏移 ShellCode
tags:
- windows
- malware-analysis
- c2
- string-obfuscation
- http
- cookie
- wikiloader
- threat-hunting
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V453
  verified_at: '2026-11-10T02:23:40+08:00'
  notes: '已对照原文与 17 张图核对：图14 多指针 push 的混淆串按 s[0::2] 还原出 https://carritosdelacompra（PoC 示例实算一致）；图15 Cookie: xUCnjqD=Base64 画像（含主机名/[None|1|1|1042]/日期/IP）与 HttpAddRequestHeadersA；图16 逐字节比较 13 字节 on><!--gmail 后 lea rsi,[rdi+rcx+0Dh]，标记后 0x0D 取下一段、当时为空；图17 伪 WordPress 登录页。卡内已说明未连接真实 C2、未执行样本；与既有 PEM 加载器/侧加载/间接系统调用/函数踩踏卡为同活动不同原子，未重复建卡。原文无受影响组件版本，affected_versions 已清空。'
---

## 一句话结论

样本注入 explorer.exe 后，用栈上多个指针保存的“混淆串”重建 C2 URL——把每个字符串按第 1、3、5…（奇数位）字符取出拼接，得到 `https://...` 形式的地址；向 C2 发 GET 前把主机画像（计算机名、用户名、是否管理员组成员、语言、系统时间，样本中还有 IP/构建/日期等）Base64 后放进 Cookie 头；C2 伪装成 WordPress 登录页，响应中按 13 字节标记（观察到的比较序列为 `on><!--gmail `）定位，再从标记后偏移处取出下一段加密 ShellCode。

## 原理

- **奇数位拼接是最廉价的字符串混淆**：样本把真实 URL 的字符与随机垃圾字符交错存储（如 `hhtjtBpasz:P/Y/icVaUrv...`），重建函数只取第 1、3、5…个字符（按 0 基下标即 `s[0::2]`），拼出 `https://<域名>/...`。二进制里没有完整 URL，`strings` 只能看到乱码；分析师必须找到重建循环或按“隔一个取一个”尝试。
- **为什么用栈上多指针**：调试信息显示多个 `lea rax, qword ptr ds:[...]` 后 `push rax`，再统一传给重建函数——字符串被拆成多段分别存放，进一步降低连续明文特征。
- **Cookie 头承载画像**：请求头中可见 `Cookie: <随机名>=<Base64>`；Base64 解码后是管道分隔的主机信息，文章明确列出的字段有计算机名、用户名、当前用户是否属于管理员组、语言、系统时间；调试到的原始串还包含 IP、版本/构建、日期等，说明攻击者用这些信息做受害者分组与后续载荷定制。
- **伪 WordPress 页面**：C2 返回一个仿 wordpress.org 的登录页（含语言 `<select>`、用户名/密码表单），使流量与页面看起来像正常网站；该家族早期版本伪装成 Wiki 站点，因此得名 WikiLoader。页面 HTML 同时是下一段 ShellCode 的载体。
- **标记 + 偏移取 ShellCode**：样本逐字节比较响应中的 13 字节标记（调试中依次比较 `o n > < ! - - g m a i l 空格`，即 `on><!--gmail `），命中后从 `标记起始 + 0x0D` 处取数据，解密并跳转执行下一段 ShellCode。分析时 C2 仍可连接，但该偏移处的附加 ShellCode 为空，说明服务端可按需下发或当时未启用。
- **为什么这样设计**：URL 混淆对抗静态字符串与 IOC 扫描；伪登录页让 C2 在流量/沙箱截图里像正常网站；把下一段载荷藏在 HTML 注释附近并用固定偏移读取，避免额外的下载请求。

## 触发条件

- 样本已进入注入 explorer.exe 后的网络阶段，且能访问 C2。
- 分析者拿到进程内存转储、调试会话或 pcap（能看到 GET 请求/响应）。
- C2 在线并返回伪 WordPress 页面；离线时只能从内存还原 URL 与画像逻辑。

## 利用步骤（分析/复现视角）

1. 在内存或调试器中定位重建函数：找“读取字符 → 判断/跳过 → 追加到输出”的循环，观察它对每个字符串只取一半字符；按 `s[0::2]` 试拼，确认得到 `https://` 开头的地址。
2. 记录所有被 push 的字符串指针及其拼接顺序，得到完整 C2 URL；同时记录 `FreeLibrary`、`HttpAddRequestHeadersA` 等 API 的动态解析方式。
3. 抓取/复现 GET 请求：读 Cookie 值，Base64 解码得到管道分隔画像；对照文章列出的字段（计算机名、用户名、管理员组、语言、系统时间）与调试中出现的 IP/构建/日期字段。
4. 保存响应原文；按 13 字节标记 `on><!--gmail ` 搜索，命中后从标记后 0x0D 字节处取数据，按样本的解密流程（本轮分析中该段为空）尝试解密并反汇编。
5. 结合页面内容（仿 WordPress 登录页）与请求特征做流量侧检测规则。

## PoC

```python
import base64

# 1) 从内存转储的混淆串还原 URL：取第 1、3、5... 个字符
s = "hhtjtBpasz:P/Y/icVaUrvrhittnopsMdWe1lhaGcnopmhpCrtav"  # 示例前缀
url = s[0::2]
print(url)  # https://carritosde...

# 2) 解析 Cookie 中 Base64 主机画像
cookie_val = "MTIxODU0OTF8dGFyZ2V0..."   # 抓包/调试得到的值
profile = base64.b64decode(cookie_val).decode("utf-8", "replace")
print(profile)

# 3) 响应中按 13 字节标记定位下一段数据
marker = b"on><!--gmail "
idx = resp.find(marker)
if idx >= 0:
    next_blob = resp[idx + 13:]
```

说明：按文章描述与调试画面整理，示例 URL/画像为占位；未连接真实 C2、未执行样本。

## 变体与关联

- [[pentest-c2-certificate-pem-aes-cbc-bcrypt-shellcode-loader]]：同一家族/同一投递包里的第一阶段 PEM 伪装 ShellCode 加载器。
- [[pentest-initial-access-notepad-portable-plugin-mimetools-dll-sideload]]：该样本的投递方式（便携版 Notepad++ 插件侧加载）。
- [[code-analysis-reverse-anti-debug-process-name-hash-shift-xor]]：注入前/后执行的进程名哈希反分析检查。
- [[code-analysis-reverse-windows-silverfox-caesar-shift-oss-wininet-rolling-xor]]、[[code-analysis-reverse-windows-amadey-api-hash-loader-c2-config]]：其他样本的字符串混淆与 C2 配置还原思路。
- 变体：取偶数位/逆序/异或后再拼接；画像放 Cookie、自定义头或 URL 参数；标记换成 `<!--`、`<div` 等 HTML 词元；下一段载荷可空、可按受害者分组下发。
- 边界：C2 离线时只能还原 URL 与画像逻辑；标记偏移与解密算法依赖具体样本版本。

## 检测与防御

- 检测（网络）：单次 GET 到仿 WordPress 登录页、请求带随机名 Cookie 且值为 Base64、UA 与页面不匹配；响应 HTML 中出现与 WordPress 登录页不符的 `<select>` 语言列表、注释附近的高熵数据；`explorer.exe` 发起 HTTP 请求本身即为强异常（正常 explorer 不直接访问外部 Web）。
- 检测（主机/内存）：进程内存出现交错字符串与“取一半字符”的重建循环；`HttpAddRequestHeadersA`/`HttpSendRequest` 在非浏览器进程中被动态解析调用；explorer.exe 中出现私有可执行内存与 ShellCode。
- 防御：限制 explorer.exe 出网/子进程网络行为；对侧加载宿主与便携应用做完整性校验；邮件/下载层拦截携带插件目录的便携包；威胁狩猎时把该家族 URL 混淆与 Cookie 画像作为规则。
- 响应：封禁 C2 域名、提取内存中的完整 URL 与画像字段、排查同源投递包（篡改插件、certificate.pem）并清理 explorer.exe 中的注入代码。

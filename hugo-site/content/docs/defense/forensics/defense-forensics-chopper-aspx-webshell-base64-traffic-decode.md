---
id: defense-forensics-chopper-aspx-webshell-base64-traffic-decode
title: 蚁剑/菜刀 ASPX 一句话木马流量：chopper 参数、substr(2) 前缀 Base64 与明文回显还原
type: scenario
domain: defense
path: defense/forensics
technique: chopper-aspx-webshell-base64-traffic-decode
tags:
- forensics
- traffic-analysis
- webshell
- aspx
- chopper
- base64
- iis
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-07T23:22:36+08:00'
  notes: 已对照原文核对：蚁剑ASPX流量、chopper参数、Request.Item随机参数substr(2)去前缀后Base64+GBK解码、目录列举/系统信息/ProcessStartInfo命令执行与明文回显均与正文及img18-25一致；img20-22复现CyberChef解码与目录遍历，img23-25命令执行回显。未复跑原文流量。
url: /docs/defense/forensics/defense-forensics-chopper-aspx-webshell-base64-traffic-decode/
draft: false
kb_aliases:
- chopper 流量分析
- 蚁剑 ASPX 流量
- 中国菜刀流量
- aspx 一句话木马流量
- substr(2) Base64 解码
- FromBase64String 木马流量
---

## 一句话结论

IIS/ASP.NET 站点流量中出现对同一 `.aspx` 的连续 `application/x-www-form-urlencoded` POST，表单键为木马连接密码（本例 `chopper`）、值是 URL 编码的 JScript 包装代码，且响应是没有 HTML 页面结构的明文目录/命令输出时，通常就是蚁剑/中国菜刀类 ASPX 一句话木马；把请求体 URL 解码后，按代码里的 `Request.Item["<随机参数>"].substr(2)` 取出对应表单值、去掉前 2 个字符再 Base64+GBK 解码，就能还原攻击者执行的目录列举、驱动器/系统信息与命令，响应明文直接给出执行结果。

## 原理

- ASPX 一句话木马通常把连接密码对应的表单值交给 `eval` 执行；客户端（蚁剑/中国菜刀）发送的不是裸命令，而是一段 JScript/ASPX 操作代码，由服务端动态执行。
- 操作代码里用 `System.Text.Encoding.GetEncoding("GBK").GetString(System.Convert.FromBase64String(Request.Item["<随机名>"].substr(2)))` 解码实际参数；参数名随机化，分别承载目录路径、可执行程序、命令参数与环境变量。值前面故意加 2 个垃圾字符，再用 `substr(2)` 去掉，用于躲开只看纯 Base64 的简单特征匹配。
- 命令执行代码使用 `System.Diagnostics.ProcessStartInfo` + `Process`：`UseShellExecute=false`、重定向 stdout/stderr，`Arguments = "/c " + cmd`，以 Web 进程（本例 IIS 的 NETWORK SERVICE）权限运行 `cmd.exe`。
- 响应不加密，服务端直接 `Response.Write` 明文：目录列表为“名称/修改时间/大小/属性”，系统信息为“当前路径/盘符/OSVersion/用户名”，命令执行返回 stdout+stderr 拼接。客户端与服务端约定 GBK 解码中文，因此响应是可读文本。
- 与冰蝎、哥斯拉等加密马的区分点：本类流量没有 AES/XOR 密文与 MD5 框架，请求体是可直接阅读的代码或 URL 编码代码，响应为纯文本工具输出；表单键通常等于连接密码。

## 触发条件

- 已取得完整请求/响应：pcap、Burp 历史、反向代理/WAF 日志或流量镜像。
- 已发现或怀疑上传目录中存在 `.aspx` 木马；知道连接密码（即表单键名）更易筛选。
- 流量未被 TLS 加密，或已通过 keylog/私钥解密。

## 利用步骤

1. 用 `http.request.method == "POST" && http.request.uri contains ".aspx"` 过滤，找对同一 `.aspx` 的密集 POST；确认 `Content-Type` 为 `application/x-www-form-urlencoded`。
2. Follow HTTP Stream：记录表单键（本例 `chopper`），观察其值是 URL 编码的 JScript；响应是没有 HTML 页面结构的明文目录/命令输出。
3. 对请求体做 URL 解码，定位 `System.Convert.FromBase64String(Request.Item["<name>"].substr(2))`，列出所有 `<name>` 参数。
4. 在表单中取同名参数的值，去掉前 2 个字符，Base64 解码后再按 GBK 解码，得到目录路径/命令/参数/环境变量。原文即用 CyberChef 的 From Base64（Alphabet `A-Za-z0-9+/=`，勾选 Remove non-alphabet chars）还原出目录列举与命令执行代码。
5. 读取响应明文：目录列表、盘符列表、`Environment.OSVersion`、`Environment.UserName`、命令输出；命令输出可能带随机前缀和制表符分隔。
6. 按时间排序请求，重建攻击者操作序列：目录遍历 → 盘符/系统信息 → 读取 `web.config` 等配置文件 → 执行系统命令 → 连接数据库/远程桌面。
7. 到主机上传目录找到对应 `.aspx`，从木马源码提取连接密码与参数名，与流量互相印证；保存样本哈希作为证据。

## PoC

```python
import base64, urllib.parse

# body 为 Wireshark Follow HTTP Stream 中复制的 POST 请求体（原始 URL 编码形态）
form = urllib.parse.parse_qs(body, keep_blank_values=True)

# 参数名来自请求中木马代码里的 Request.Item["..."]；示例为原文出现的随机名
for key in ("o333dffee79d8c", "x4487feb1efaef", "q3aed900b95ec1", "ebed910c3b1725"):
    if key in form:
        raw = form[key][0]
        # 去掉前 2 个垃圾字符后 Base64 解码，再按 GBK 还原
        print(key, "=>", base64.b64decode(raw[2:]).decode("gbk", errors="replace"))
```

说明：外层 `chopper` 参数本身是 URL 编码的操作代码，解码后可直接阅读；内层随机参数值才是被 `substr(2)` 处理的 Base64。不同连接工具的包装代码可能略有差异，以流量中实际出现的 `Request.Item["..."]` 名为准。

## 变体与关联

- 变体：连接密码不叫 `chopper`，表单键随密码变化；随机参数名每次连接可能不同；部分马把操作代码再套一层 Base64。
- 变体：冰蝎/哥斯拉使用 AES/XOR 加密和 MD5 框架，需要从马文件取密钥后解密，不能按本卡直接读明文。
- 变体：`.ashx`/`.asmx` 等 ASP.NET 处理程序也可能承载同类一句话，识别方法相同。
- 关联：[[defense-forensics-godzilla-java-webshell-traffic-decode]]、[[defense-forensics-behinder-php-webshell-traffic-decrypt]]、[[defense-forensics-web-access-log-attacker-ip-triage]]、[[web-generic-file-upload-aspnet-avatar-extension-aspx-webshell]]。

## 检测与防御

- 流量侧：对 `.aspx/.ashx/.asmx` 的 POST 检测表单值中出现 `FromBase64String`、`Request.Item[`、`substr(2)`、`ProcessStartInfo` 等组合；响应缺少 HTML 且包含盘符、`Microsoft Windows`、目录时间戳格式；同一 URI 短时间内多次 POST。
- 文件侧：上传目录出现时间戳命名或随机命名、内容含 `eval`/`Response.Write`/`Request.Item` 的脚本文件；与上传接口访问时间对应。
- 主机侧：IIS 日志中该脚本的 POST 频率与来源；`w3wp.exe` 派生的 `cmd.exe` 子进程与异常网络连接。
- 防御：上传目录禁止脚本执行；上传接口强制扩展名白名单并重命名；WAF 拦截一句话特征；应用池最小权限运行；确认入侵后隔离样本、封禁来源、排查同一入口的其他文件。

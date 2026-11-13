---
id: web-generic-ssrf-lylme-get-head-curl-blind-timing
title: LyLme Spage get_head/get_curl 未校验 URL 的盲 SSRF：用响应时间侧信道探测内网主机与端口
type: scenario
domain: web
path: web/generic/ssrf
technique: php-curl-unvalidated-url-blind-ssrf
aliases:
- LyLme Spage SSRF
- 六零导航页 SSRF
- get_head SSRF
- get_curl 任意 URL
- PHP curl 盲 SSRF 时间探测
tags:
- web
- php
- ssrf
- curl
- blind
- timing
- code-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V516
  verified_at: '2026-11-11T11:53:11+08:00'
  notes: 已对照原文与图03（gif 首帧）：PoC 请求 apply/index.php?url=http://localhost:3306 与返回 JSON（icon 为 http:\/\/localhost:3306\/favicon.ico、charset EUC-CN）与卡片逐字一致；原文明确 get_curl 直接 CURLOPT_URL 抓取任意地址、FOLLOWLOCATION=true、TIMEOUT=>0，且说明『没有回显数据，无法 file:// 任意文件读取，可通过请求延时判断内网服务』，卡片按盲 SSRF+时间侧信道表述并保留局限，未夸大。卡片『对 HTML 服务有部分回显』为基于 get_head 提取 title/icon 的代码推断，原文只演示 localhost:3306 的字段与延时，属合理推断且卡内已注明原文未验证跳转/gopher。与反射 XSS 卡共用 apply/index.php?url= 入口但 sink/危害不同（curl 抓取 vs 反射输出），各自原子不重复。dedup：recommendation=new；候选 wallos testwebhook、avatar urlopen、https 前缀 302 gopher、php parse_url 等均为不同产品/不同链；dup-scan.json 未涉及。去留：保留并 verified。
---

## 一句话结论

LyLme Spage 的 `apply/index.php?url=` 会进入 `include/function.php#get_head()`，再由 `get_curl()` 直接 `curl_setopt(CURLOPT_URL, $url)` 抓取任意地址（跟随跳转、无协议/主机限制）；虽然接口只回显抓取页面的 title/icon 等字段、原文未能用 `file://` 直接读文件，但可以通过响应时间差判断内网主机/端口是否开放，形成可用的内网探测 SSRF。

## 原理

- 调用链：`apply/index.php?url=` → `get_head($url)` → `get_curl($url)`：
  ```php
  function get_curl($url) {
      $curl = curl_init();
      curl_setopt_array($curl, array(
          CURLOPT_URL => $url,
          CURLOPT_RETURNTRANSFER => true,
          CURLOPT_FOLLOWLOCATION => true,
          CURLOPT_TIMEOUT => 0,
          CURLOPT_HTTPHEADER => array('... Lylme/11.24'),
      ));
      $contents = curl_exec($curl);
      $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
      ...
  }
  ```
  `$url` 完全来自请求参数，没有 scheme/host/端口校验，也没有内网地址黑名单；`CURLOPT_FOLLOWLOCATION` 让服务端自动跟随 3xx 到任意位置。
- 响应侧会把抓取内容的 `<title>`、icon、description、keywords 提取后回显（`get_head` 的返回值），所以对能返回 HTML 的内网 HTTP 服务存在部分回显；对非 HTTP 服务（如 MySQL 3306）curl 会因协议不匹配快速失败/超时，响应时间与关闭端口不同。
- 原文用 `url=http://localhost:3306` 观察返回内容（charset/icon 字段变化）与请求延时（gif）判断端口开放；`CURLOPT_TIMEOUT => 0` 意味着无超时，可放大时间差，但也可能造成请求挂起。
- 原文说明由于没有完整回显数据，`file://` 不能直接拿来任意文件读取；该 SSRF 的可用价值主要是内网存活/端口探测、访问内网 HTTP 服务，以及配合跳转访问云元数据等（跳转利用原文未验证）。

## 触发条件

- 目标运行含该代码的 LyLme Spage 版本（原文未标注具体版本）。
- `apply/index.php` 可访问（无需登录，原文直接请求）。
- 服务器能访问目标内网地址；PHP curl 扩展启用且允许相应协议。
- 攻击者能观察到响应时间或返回字段差异。

## 利用步骤

1. 请求 `apply/index.php?url=http://127.0.0.1:<port>`，记录响应时间与返回 JSON 字段。
2. 对比开放端口（连接建立/HTTP 响应）与关闭端口（立即 refused 或长时间无响应）的差异，判断内网服务存活。
3. 对开放端口继续枚举常见 HTTP 管理页面；若服务端 curl 支持相关协议，可尝试跳转/内网主机名解析。
4. 结合返回的 title/icon 字段识别内网服务类型。

## PoC

```http
GET /apply/index.php?url=http://localhost:3306 HTTP/1.1
Host: target
```

```json
{"title":"","charset":"EUC-CN","icon":"http:\/\/localhost:3306\/favicon.ico","description":null,"keywords":null,"url":"http:\/\/localhost:3306"}
```

对关闭端口或不可达地址重复请求，比较响应时间即可做端口存活判断（原文 gif 演示延时差异）。

## 变体与关联

- 变体：`CURLOPT_FOLLOWLOCATION=true` 可被攻击者控制的 HTTP 服务用 302 引导到内网地址/云元数据；原文未验证该跳转利用，但代码条件具备。
- 变体：若目标 curl 支持 `gopher://`/`dict://` 等协议，可进一步构造内网协议攻击（依 libcurl 编译选项而定，原文未验证）。
- 关联：[[web-generic-xss-lylme-apply-url-contenttype-override]]——同一 `url` 参数的反射型 XSS。
- 关联：[[web-generic-ssrf-php-curl-get-file-scheme-config-read]]、[[web-generic-ssrf-wallos-testwebhook-notifications-private-ip]]——PHP curl 未限制协议/内网地址的同类 SSRF。

## 检测与防御

- 防御：对 `url` 做协议白名单（仅 http/https）与目标域名白名单；解析后的 IP 拒绝私有/保留地址（RFC1918、127/8、169.254/16、::1 等），并防 DNS rebinding。
- 防御：禁止 `CURLOPT_FOLLOWLOCATION` 或对跳转目标重复做同样校验；设置连接/总超时，避免被用于长时间探测。
- 检测：`url` 参数出现内网地址、非常用端口、`file://`/`gopher://`/`dict://` 等协议；服务端对私有地址的 curl 请求与异常延时。
- 检测：应用日志中同一来源对大量不同端口/内网 IP 的 `url` 请求，形似端口扫描。

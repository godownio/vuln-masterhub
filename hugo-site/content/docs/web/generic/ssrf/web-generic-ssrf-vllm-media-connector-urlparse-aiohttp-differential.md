---
id: web-generic-ssrf-vllm-media-connector-urlparse-aiohttp-differential
title: vLLM MediaConnector 多模态 image_url SSRF：urlparse 白名单与 aiohttp WHATWG 解析分歧（CVE-2026-24779）
type: scenario
domain: web
path: web/generic/ssrf
technique: vllm-media-connector-urlparse-aiohttp-differential
tags:
- ssrf
- vllm
- ai-inference
- multimodal
- urlparse
- aiohttp
- whatwg
- backslash
- allowlist
- cve-2026-24779
cve:
- CVE-2026-24779
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: < 0.14.1
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T09:46:20+08:00'
  notes: 已对照原文与17张图核对：CVE-2026-24779/CWE-918/CVSS 7.1、影响<0.14.1、/v1/chat/completions→OpenAIServingChat→_preprocess_chat→parse_chat_messages_futures→parse_image→fetch_image_async→load_from_url_async(urlparse+白名单)与HTTPConnection._validate_http_url仅查scheme→aiohttp.ClientSession 调用链一致；0.14.1 修复改为 urllib3.util.parse_url。未验证点：原文称 urlparse 得 hostname 为空/None，本机 Python 3.x 实测为 192.168.1.100，具体 payload 依版本而异，卡已标 medium 并提示复现前核对；PoC 未实跑，未访问内网；frontmatter 无 sources/source_url。
url: /docs/web/generic/ssrf/web-generic-ssrf-vllm-media-connector-urlparse-aiohttp-differential/
draft: false
kb_aliases:
- CVE-2026-24779
- vLLM SSRF
- MediaConnector SSRF
- image_url SSRF
- urlparse aiohttp 解析差异
- 多模态 URL 白名单绕过
- vLLM 0.14.1
---

## 一句话结论

vLLM 0.14.1 之前的 `MediaConnector.load_from_url_async` 用 `urllib.parse.urlparse` 解析用户提交的 `image_url` 并做 `allowed_media_domains` 校验，但真正发请求的 `aiohttp/yarl` 按 WHATWG 规则解析同一个 URL；两者对反斜杠与 `@` 的处理不同，构造 `http://allowed.com\@192.168.1.100:8080/...` 一类地址即可让白名单看到允许域名/空主机，而 aiohttp 实际连接内网 IP，形成 SSRF。

## 原理

- **入口**：OpenAI 兼容接口 `POST /v1/chat/completions` 的 `messages[].content[]` 支持 `{"type":"image_url","image_url":{"url":"..."}}`。`OpenAIServingChat.create_chat_completion` → `_preprocess_chat` → `parse_chat_messages_futures` → `_parse_chat_message_content` → `_parse_chat_message_content_parts` → `_parse_chat_message_content_part`，识别 `image_url`/`input_image` 后调用 `mm_parser.parse_image(str_content, uuid)`。
- **媒体加载**：`parse_image` 调 `MediaConnector.fetch_image_async(image_url)` → `load_from_url_async(url, ...)`。后者先用 `url_spec = urlparse(url)`，当 `url_spec.scheme.startswith("http")` 时执行 `self._assert_url_in_allowed_media_domains(url_spec)`，再调用 `connection.async_get_bytes(url, ...)`。
- **白名单与请求分离**：校验使用 Python 标准库 `urllib.parse.urlparse`（RFC 3986 口径：反斜杠是普通字符，按 `@` 切 userinfo/host）；实际请求由 `HTTPConnection.get_async_response` 发起，它只做 `urlparse` 的 scheme 检查（`http`/`https`），随后用 `aiohttp.ClientSession.get(url)`。aiohttp 底层 `yarl` 按 WHATWG URL 标准解析：反斜杠可能被当作路径分隔符、`@` 被当作 userinfo 分隔符，解析结果与 `urlparse` 不一致。
- **绕过形态**：文章给出的 payload 为 `http://allowed.com\@192.168.1.100:8080/internal-api/admin`。按其跟踪，`urlparse` 在该 payload 上得到的 hostname 为空/检查被短路，白名单未拦截；而 `aiohttp` 将 authority 解析到 `192.168.1.100:8080`，向该内网地址发起请求。核心不是某一个具体字符，而是“校验器”和“执行器”使用两套 URL 解析实现，攻击者只需找到两者对 authority 的解析分歧。
- **校验缺口**：`_validate_http_url` 只检查 scheme，不重新校验 hostname、allowed domains、私网/回环/元数据地址；所以一旦前一步白名单被绕过，请求层没有第二道主机检查。
- **影响**：vLLM 服务可被诱导访问内网任意 HTTP 服务、LLM-d/Kubernetes 管理端点、云元数据地址等；响应会被当作图片数据交给多模态 IO 处理，可能报错，但请求已经发出，可用于端口扫描、内网探测、访问管理接口或触发副作用。CVE 评分为 7.1（High），CWE-918。
- **版本与修复**：影响 `< 0.14.1`。0.14.1 的修复提交把 `connections.py` 中校验用的 `urllib.parse.urlparse` 替换为 `urllib3.util.parse_url`，并更新 `_assert_url_in_allowed_media_domains`，让校验与请求侧的解析口径一致；核心修复是统一解析器，而不是只过滤反斜杠。
- **复现注意**：本机用 Python 3.x 对文章中同一字符串做 `urlparse` 测试时，hostname 解析为 `192.168.1.100`，与文章“hostname 为空”的跟踪不完全一致；不同 Python/vLLM 版本、`allowed_media_domains` 配置和 yarl 版本都会影响具体 payload。复现时应先核对目标版本的 `_assert_url_in_allowed_media_domains` 实现与 aiohttp/yarl 版本，再构造分歧，不能把单一 payload 当作通用 PoC。

## 触发条件

- vLLM 版本 `< 0.14.1`，启用多模态模型并接受 `image_url` 输入。
- 服务配置了 `--allowed-media-domains`（或等价白名单）；若未配置白名单，本身就没有主机限制，问题是“可访问任意 URL”而非绕过。
- 攻击者能调用 `/v1/chat/completions`（需要有效 token；若暴露在公网且鉴权薄弱则风险更高）。
- vLLM 进程能访问目标内网/元数据地址；没有网络层出口限制。
- 使用的 `aiohttp/yarl` 与 `urllib.parse` 对构造的 URL 存在 authority 解析分歧。
- 响应即使不能作为图片解析，请求副作用（访问管理端点、扫描、状态变更）仍可发生；若响应被回显/用于错误信息，信息泄露更明显。

## 利用步骤

1. 确认版本与多模态能力：目标 vLLM `< 0.14.1`，模型支持 `image_url`（如 llava 类）。
2. 发送基线请求：合法外部图片 URL，确认接口可用、返回正常。
3. 构造解析分歧 URL：以文章 payload 为起点 `http://allowed.com\@192.168.1.100:8080/internal-api/admin`，其中 `allowed.com` 是白名单允许域名、`192.168.1.100:8080` 是目标内网服务；根据目标版本调整反斜杠位置/编码（`\`、`%5C`、多重 `@`）。
4. 提交请求，观察响应时间、错误信息与内网服务日志；若内网端点有回显，可确认 SSRF；若无回显，用可达/不可达端口的时延差或带外 DNS/HTTP 监听确认。
5. 替换目标为内网管理端点、Kubernetes API、云元数据地址或端口扫描列表；注意响应会被当图片处理，可能需要选择返回图片/任意字节的端点。
6. 若配置允许重定向（`VLLM_MEDIA_URL_ALLOW_REDIRECTS`），可尝试用外部 302 跳到内网，绕过单次 URL 校验。

## PoC

请求骨架（未在本机执行）：

```http
POST /v1/chat/completions HTTP/1.1
Authorization: Bearer <valid_token>
Content-Type: application/json

{
  "model": "llava",
  "messages": [{
    "role": "user",
    "content": [
      {"type": "text", "text": "请分析这张图片的内容"},
      {"type": "image_url", "image_url": {"url": "http://allowed.com\\@192.168.1.100:8080/internal-api/admin"}}
    ]
  }],
  "max_tokens": 100
}
```

解析器对比（本地只读，用于理解分歧；实际结果随版本变化）：

```python
from urllib.parse import urlparse
u = r"http://allowed.com\@192.168.1.100:8080/internal-api/admin"
p = urlparse(u)
print("urlparse hostname:", p.hostname, "netloc:", p.netloc, "username:", p.username)

# aiohttp 使用 yarl/WHATWG 解析
import yarl
q = yarl.URL(u)
print("yarl host:", q.host, "path:", q.path, "user:", q.user)
```

## 变体与关联

- 变体：`%5C` 编码反斜杠、多重 `@`、userinfo 混淆、大小写/尾随点、IPv6 字面量、十进制/十六进制 IP；不同 `aiohttp/yarl` 版本行为不同。
- 变体：利用 30x 重定向到内网；DNS rebinding 让首次解析为外部、请求时解析为内网；目标端点返回图片以维持多模态解析。
- 关联：[[web-generic-ssrf-python-urlparse-urllib3-backslash-bypass]]（urlparse vs urllib3 同类分歧）、[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（Node fast-uri vs WHATWG）、[[web-generic-ssrf-url-userinfo-prefix-allowlist-bypass]]（userinfo 混淆）、[[web-generic-ssrf-ai-inference-model-param-url-ssrf]]（AI 推理服务 SSRF）、[[cloud-metadata]]（打到元数据后的凭证读取）。

## 检测与防御

- **升级**：升级到 vLLM 0.14.1+；确认 `connections.py` 使用 `urllib3.util.parse_url` 且 `_assert_url_in_allowed_media_domains` 使用同一解析结果校验主机。
- **统一解析器**：校验与请求必须使用同一个解析器、同一份规范化 URL；校验后不要再用另一个库重新解析原始输入。
- **主机/IP 校验**：请求前解析 DNS 并对最终 IP 做回环、私网、链路本地、组播、保留地址检查；每一跳重定向重新校验；禁止或限制访问云元数据地址。
- **白名单**：`allowed_media_domains` 使用精确域名/点边界匹配，拒绝 userinfo、反斜杠、控制字符、多重 `@`；默认拒绝而非默认放行。
- **网络层**：vLLM 出口防火墙只允许必要的外部媒体域名，内网服务做认证与来源限制；多模态服务与敏感管理面隔离。
- **日志检测**：`image_url` 中出现 `\`、`%5C`、`%5c`、多重 `@`、内网 IP/端口；短时间大量不同内网目标的图片请求；aiohttp 连接内网/元数据地址；返回 `Invalid image` 但请求已到达内部服务。
- **错误处理**：不要把 aiohttp/yarl 的异常栈返回给调用方，避免泄露解析器与内部地址。

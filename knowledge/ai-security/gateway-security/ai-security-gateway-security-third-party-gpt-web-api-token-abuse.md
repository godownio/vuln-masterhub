---
id: ai-security-gateway-security-third-party-gpt-web-api-token-abuse
title: 第三方 GPT 站点 Web 接口匿名/共享凭证滥用：页面 nonce、get_token 与 free-pool bearer 直连后端（gpt4free 模式）
type: scenario
domain: ai-security
path: ai-security/gateway-security
technique: third-party-gpt-web-api-token-abuse
aliases:
- gpt4free 模式
- 免费 GPT 接口滥用
- restNonce 复用
- free-pool token 复用
- GPT 站点接口直连
- chatgpt-web 未授权访问
- Bing Chat WebSocket 未授权调用
- LLM 中转站配额盗用
tags:
- ai-security
- llm-api
- relay
- gateway
- credential-abuse
- unauthorized-access
- scraping
- anti-bot
- websocket
- quota-abuse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V612
  verified_at: '2026-11-12T19:51:51+08:00'
  notes: '已通读原文全文并逐张核对39张图：图02 FOFA title="ChatGPT Web" 41,219条/24,211独立IP，图03 公网 chatgpt-web 实例匿名对话成功；图09 前端调用 /backend-api/v2/conversation；图11-17 Bing ChatHub WebSocket 抓包（sec_access_token、X-Sydney-Encryptedconversationsignature、请求/响应体一致），图18 conversationId 含 BingProdUnAuthenticatedUsers；图19-21 Chatgpt4Online restNonce 与 mwai chats/submit；图22 ChatgptAi 同类实现；图23-27 GptGo get_token.php→web.php SSE chat.completion.chunk；图28-32 GeekGpt 额度与 Authorization: Bearer pk-this-is-a-real-free-pool-token-for-everyone 直连 ai.fakeopen.com/v1/chat/completions。卡内各 provider 的取凭证方法、接口、PoC、参数与原文一致；Cloudflare 偶发拦截、GPT-4 链路不稳已在卡中注明。dedup：候选为 CLIProxyAPI 默认 key、LiteLLM 公开路由、Kong 模板 key 泄露、ComfyUI 凭证端点等网关自身配置缺陷，与本卡第三方站点公开/共享凭证滥用不同链；dup-scan 30 对不涉及本卡。判原子保留（同一‘前端公开凭证/无状态 token 直连后端’场景的多 provider 变体）。'
---

## 一句话结论

许多第三方 GPT 聚合/中转站点把 OpenAI 调用包在**无鉴权或弱鉴权**的 Web 接口后面：nonce/token 从公开页面或公开接口即可取得（WordPress 的 `restNonce`、GptGo 的 `get_token.php`），GeekGpt 甚至在前端直接复用共享 bearer token（`pk-this-is-a-real-free-pool-token-for-everyone`）；攻击者绕过前端直接调用这些后端接口，即可免费消耗站点运营者的 provider 配额，公网暴露的老版本 `chatgpt-web` 实例同样可匿名对话；Bing Chat 则可用 `/turing/conversation/create` 返回的 `X-Sydney-Encryptedconversationsignature` 作为 `sec_access_token`，通过 WebSocket 匿名调用 GPT-4 聊天。

## 原理

- **聚合站架构**：站点前端 → 自家后端（持有 OpenAI/上游 provider 密钥）→ 上游模型。若后端接口只依赖“页面里带的 nonce”或“无状态 token”，而前端本身就是公开的，那么任何脚本都能复现同样的请求；站点运营者的 provider 配额被外部消耗。
- **WordPress mwai 插件（Chatgpt4Online 一类）**：页面 HTML 里直接打印 `restNonce&quot;:&quot;...&quot;`，请求时放在 `X-Wp-Nonce` 头。WordPress nonce 是 CSRF 防护值，不是用户认证，访问首页就能拿到；`POST /wp-json/mwai-ui/v1/chats/submit` 带 JSON 消息体即可取回流式回答。ChatgptAi 的实现方式相同。
- **GptGo**：`POST https://gptgo.ai/get_token.php`（`ask=消息`）返回一段编码串，按固定位置截取并 Base64 解码得到 token；随后 `GET https://api.gptgo.ai/web.php?array_chat=<token>` 返回 SSE 形式的 `chat.completion.chunk`。token 与问题绑定但不与用户身份绑定。
- **GeekGpt / ai.fakeopen.com**：前端请求 `/v1/chat/completions` 时直接携带 `Authorization: Bearer pk-this-is-a-real-free-pool-token-for-everyone`。这是一个**共享免费池 token**，写死在前端，任何拿到它的人都能直接调用上游池子。
- **公网 chatgpt-web 实例**：`Chanzhaoyu/chatgpt-web` 老版本存在未授权访问，部署后若直接暴露公网且未配置访问密码，任何人可打开页面直接对话；用 FOFA `title="ChatGPT Web"` 可批量发现（原文检索到数万条匹配），逐个尝试即可找到可用实例。
- **Bing Chat WebSocket**：`GET https://www.bing.com/turing/conversation/create?bundleVersion=` 返回 `conversationId`、`clientId`，响应头 `X-Sydney-Encryptedconversationsignature` 即 `sec_access_token`；随后连接 `wss://sydney.bing.com/sydney/ChatHub?sec_access_token=<签名的 URL 编码>`，先发 `{"protocol":"json","version":1}` 握手，再发结构化 JSON（`arguments` 内含 `optionsSets`、`allowedMessageTypes`、`message.text`、`conversationId`、`participant.id`、`tone` 等）即可收到回答。原文拿到的 conversationId 形如 `...BingProdUnAuthenticatedUsers...`，说明该入口面向未登录用户。
- **为什么成立**：这些接口本就为浏览器前端设计，服务端没有、或没有强制“调用者必须是本站真实用户”的校验；凭证要么公开、要么无状态、要么永久共享。把浏览器请求原样搬到脚本即可复用，属于认证/授权边界缺失导致的资源滥用。

## 触发条件

- 目标站点提供免登录或弱登录的 GPT 聊天能力，且后端接口可直接访问；`restNonce`/`get_token` 等凭证能从公开页面或公开接口获取。
- 站点未对接口做来源绑定（如 nonce 绑定会话/IP、一次性 token、请求签名）、频率限制或强反爬；部分站点有 Cloudflare/人机验证，会降低稳定性（原文实测 Chatgpt4Online 有时被 Cloudflare 拦截）。
- 公网存在老版本 `chatgpt-web` 等未授权实例，或站点在前端硬编码共享 bearer token。
- 对 Bing：无需登录 Microsoft 账号即可访问 `/turing/conversation/create` 与 ChatHub（原文环境可匿名取到签名）。
- 使用脚本调用时需对齐浏览器请求头/参数/Referer；受 Akamai 等指纹反爬保护的接口还需要 TLS 指纹伪装（见关联卡）。

## 利用步骤

1. **找接口**：浏览器 F12/代理抓包观察站点聊天请求，或在开源前端源码中找后端地址（如 `wp-json/.../chats/submit`、`get_token.php`、`/v1/chat/completions`）。
2. **取凭证**：
   - WordPress：`GET /` 页面正则提取 `restNonce`；
   - GptGo：`POST /get_token.php` 后截取 Base64 解码；
   - GeekGpt：从请求头直接读取共享 bearer；
   - 公网实例：FOFA `title="ChatGPT Web"` 找目标，打开页面确认未授权可用。
3. **直连后端**：按前端同样的方法、路径、JSON 结构、头（`Content-Type`、`Referer`、`X-Wp-Nonce`/`Authorization`）发送请求；流式响应按 `data:` 行解析。
4. **Bing（WebSocket）**：先 `GET /turing/conversation/create?bundleVersion=...` 取 `conversationId`/`clientId`/`X-Sydney-Encryptedconversationsignature`；连 ChatHub 并带 `sec_access_token`；先握手再发消息结构；从返回的 `type:1,target:update` 消息中提取 `messages[0].text`。
5. **稳定性**：准备多个实例/代理，控制频率；遇 Cloudflare/挑战页时改用指纹伪装或浏览器自动化。

## PoC

Chatgpt4Online（取 nonce + 直连 mwai 接口）：

```python
import re, requests
s = requests.Session()
html = s.get("https://chatgpt4online.org/", headers={"user-agent": "Mozilla/5.0 ..."}).text
nonce = re.search(r'restNonce&quot;:&quot;(.*?)&quot;', html).group(1)

data = {"botId": "default", "session": "N/A", "chatId": "abc123def45",
        "contextId": 58, "messages": [], "newMessage": "who are you", "stream": True}
s.post("https://chatgpt4online.org/wp-json/mwai-ui/v1/chats/submit", json=data,
       headers={"Content-Type": "application/json", "x-wp-nonce": nonce,
                "Referer": "https://chatgpt4online.org/"})
```

GptGo（get_token + web.php）：

```python
import base64, requests
s = requests.Session()
tok = s.post("https://gptgo.ai/get_token.php", data={"ask": "hi"},
             headers={"Origin": "https://gptgo.ai", "Referer": "https://gptgo.ai/"}).text
tok = base64.b64decode(tok[10:-20]).decode()
r = s.get("https://api.gptgo.ai/web.php", params={"array_chat": tok},
          headers={"Origin": "https://gptgo.ai", "Referer": "https://gptgo.ai/"})
print(r.text)   # SSE: data: {"id":"chatcmpl-...","object":"chat.completion.chunk",...}
```

GeekGpt（共享 free-pool bearer）：

```python
import requests
r = requests.post("https://ai.fakeopen.com/v1/chat/completions",
    headers={"Authorization": "Bearer pk-this-is-a-real-free-pool-token-for-everyone",
             "Content-Type": "application/json", "Origin": "https://chat.geekgpt.org",
             "Referer": "https://chat.geekgpt.org/"},
    json={"model": "gpt-3.5-turbo", "stream": True,
          "messages": [{"role": "user", "content": "who are you"}]}, stream=True)
```

Bing Chat（取签名 + WebSocket 消息骨架）：

```text
GET https://www.bing.com/turing/conversation/create?bundleVersion=1.1467.3
  -> JSON: conversationId, clientId
  -> header: X-Sydney-Encryptedconversationsignature = sec_access_token

WS wss://sydney.bing.com/sydney/ChatHub?sec_access_token=<urlencode(signature)>
send: {"protocol":"json","version":1}
send: {"arguments":[{"source":"cib","optionsSets":[...],"allowedMessageTypes":[...],
       "sliceIds":[...],"traceId":"<32hex>","isStartOfSession":true,"requestId":"<uuid>",
       "message":{"author":"user","inputMethod":"Keyboard","text":"hi","messageType":"Chat",
                  "requestId":"<uuid>","messageId":"<uuid>"},
       "scenario":"SERP","tone":"Balanced","spokenTextMode":"None",
       "conversationId":"<id>","participant":{"id":"<clientId>"}}],
       "invocationId":"1","target":"chat","type":4}
```

公网未授权实例：FOFA 查询 `title="ChatGPT Web"`，打开命中的页面直接对话（无需登录），即为未授权使用实例运营者的 API 配额。

## 变体与关联

- **凭证类型变体**：公开页面 nonce（WordPress）→ 公开接口 token（GptGo）→ 前端硬编码共享 bearer（GeekGpt）→ 无凭证匿名实例（chatgpt-web）→ 匿名 WebSocket 签名（Bing）。共同点是服务端没有把“调用者身份”绑定到凭证上。
- **反爬组合**：You.com 的 `/api/streamingSearch` 也属于公开接口直连（`q/domain/youchat` 参数即可拿到 SSE），但普通 requests 会命中“检查站点连接是否安全”，需要 curl_cffi TLS 指纹伪装，见关联卡 [[web-generic-curl-cffi-tls-fingerprint-akamai-bypass]]。
- **可靠性**：原文实测 gpt4free 默认链路在部分网络环境下 GPT-3.5 可用、GPT-4 请求失败（依赖 Bing 等 provider 的可用性）；各站点会随 Cloudflare 验证、接口变更、token 失效而波动，利用前需逐个验证，不能把单一站点当作稳定通道。
- **与 LLM 中转站安全的关系**：同属第三方 LLM 中转/聚合服务生态。另一方向的风险是“中转投毒用户”（见 [[ai-security-gateway-security-llm-relay-system-prompt-poisoning]]），本卡是反方向“外部滥用中转站点配额”。
- **类似模式**：任何“前端直连后端、凭证公开/无状态”的 AI 聚合站（含部分 one-api/New API 前端、免费镜像站）都可能适用；发现方法与上面一致。

## 检测与防御

- **站点运营者**：所有消耗 provider 配额的接口强制服务端认证（会话/API key），把 nonce/token 绑定到会话与来源并设短有效期；禁止在前端硬编码共享 bearer token；对匿名接口按 IP/会话限速并监控配额突增；开启 Cloudflare/Akamai 的 Bot Management 与 JS 挑战，不能只靠 UA/IP。
- **暴露面治理**：公网部署 `chatgpt-web` 等应用时设置访问密码/反代认证，定期用 FOFA/测绘自查 `title="ChatGPT Web"` 一类指纹；老版本及时升级。
- **检测信号**：同一 token/nonce 被大量不同 IP 复用；请求头顺序/指纹与浏览器不符；高频 `chats/submit`、`get_token.php`、`chat/completions` 调用；响应只有 SSE 而无页面浏览行为；来自同一 ASN 的批量实例探测。
- **对用户/企业**：不要把第三方免费 GPT 站点当作可信通道处理敏感数据——这类站点可记录全部对话，且其配额随时可能被滥用或关停。

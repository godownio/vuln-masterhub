---
id: web-generic-ssrf-chainlit-custom-element-url-fetch-ssrf
title: Chainlit < 2.9.4 /project/element 自定义元素 url 被 SQLAlchemy 数据层直接 GET：认证用户 SSRF 读云元数据并回显
type: scenario
domain: web
path: web/generic/ssrf
technique: chainlit-custom-element-url-fetch-ssrf
tags:
- ssrf
- chainlit
- ai-framework
- sqlalchemy
- aiohttp
- cloud-metadata
- cve-2026-22219
cve:
- CVE-2026-22219
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: < 2.9.4
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T11:39:29+08:00'
  notes: 已对照原文与7张截图核对：CVE-2026-22219/CVSS 8.3/<2.9.4、PUT /project/element、Element.from_dict 取 url、_create→data_layer.create_element、aiohttp GET 无校验、修复 _sanitize_custom_element 均一致；affected_versions 已在卡中且与原文一致。未验证点：未对真实实例复跑回显链。
url: /docs/web/generic/ssrf/web-generic-ssrf-chainlit-custom-element-url-fetch-ssrf/
draft: false
kb_aliases:
- CVE-2026-22219
- Chainlit SSRF
- /project/element SSRF
- custom element url SSRF
- SQLAlchemy data layer SSRF
- Chainlit 云元数据读取
---

## 一句话结论

Chainlit `< 2.9.4` 在配置 SQLAlchemy 数据层时，`PUT /project/element` 更新流程信任客户端提交的 custom 元素 `url`：`Element.from_dict()` 原样保存该 URL，`element.update()` 交给数据层 `create_element()` 后直接 `aiohttp` GET，且无任何协议/主机/私网校验；有合法会话的攻击者可让服务端请求内网服务或云元数据，并把响应存入存储、以可公开访问的 URL 取回（CVE-2026-22219，CVSS 8.3）。

## 原理

- **入口信任客户端字段**：`server.py` 的 `update_thread_element()` 从 `payload.element` 取 `ElementDict`，只检查 `element_dict["type"] == "custom"`，随后调用 `Element.from_dict(element_dict)`。
- **URL 进入元素**：`Element.from_dict()` 执行 `url = str(e_dict.get("url")) if e_dict.get("url") else None`，把客户端 `url` 放进 `common_params`，custom 分支返回 `CustomElement(props=..., url=url, ...)`，因此 `element.url` 完全由攻击者控制。
- **update 触发数据层**：`await element.update()` 调用 `Element.update()`，最终走到 `_create(persist=True)`；存在 data layer 时异步调用 `data_layer.create_element(self)`。
- **数据层直接出站**：`sqlalchemy_data_layer.py` 的 `create_element()` 判断 `elif element.url:` 后执行 `async with aiohttp.ClientSession() as session: async with session.get(element.url) as response:`，状态码 200 时 `content = await response.read()`。整个过程没有 scheme 白名单、主机黑名单、私网/链路本地/云元数据地址拦截，也没有在 DNS 解析或重定向后再校验。
- **响应可回显**：拉取到的内容交给配置的存储提供商保存，数据层生成可公开访问的 URL 并写入数据库；攻击者随后读取该 URL 即可拿到 SSRF 响应，因此不是只能探测端口的盲 SSRF，而是可读取内网响应体的完整 SSRF。
- **权限边界**：请求由 Chainlit 服务进程发起，使用其网络位置与出口权限，可访问仅对服务端开放的内网管理面、localhost 服务、容器网络以及 `169.254.169.254` 元数据服务；认证门槛仅是普通 Chainlit 会话，不需要管理员。
- **修复**：新增 `_sanitize_custom_element()`，从客户端字典只取 `id`、`forId`、`threadId`、`name`、`props`、`display` 等安全字段来构造 `CustomElement`，不再传递 `url` 与 `object_key`；升级到 2.9.4。

## 触发条件

- Chainlit 版本 `< 2.9.4`，并使用 SQLAlchemy 数据层后端；`create_element` 中存在按 `element.url` 出站拉取的逻辑。
- 攻击者持有有效 Chainlit 会话（`session_id`），能访问 `PUT /project/element`。
- 目标元素类型为 `custom`（服务端仅对该类型放行）。
- 配置了存储提供商，且数据层会把拉取内容持久化并返回可访问 URL（决定响应能否回显）。
- Chainlit 服务端到目标内网/元数据地址网络可达。

## 利用步骤

1. 通过正常登录或会话获取流程拿到有效 `session_id`。
2. 发送 `PUT /project/element`，提交 custom 元素，`url` 指向内网服务或云元数据端点（如 `http://169.254.169.254/latest/meta-data/iam/security-credentials/`）。
3. 服务端 `Element.from_dict()` 保存 URL，`element.update()` → `data_layer.create_element()`，由 aiohttp 发起 GET 并读取响应体。
4. 数据层把响应内容存入配置的存储并生成公开 URL；从响应/数据库/元素事件中取得该 URL。
5. 访问该 URL 读取元数据或内网接口响应；对其它内网地址重复以做资产探测或凭证获取。

## PoC

```http
PUT /project/element HTTP/1.1
Host: target-chainlit.example
Content-Type: application/json
Cookie: session_id=<valid-session-id>

{
  "element": {
    "type": "custom",
    "id": "ssrf-attack",
    "name": "test",
    "display": "inline",
    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "props": {},
    "sessionId": "<valid-session-id>"
  }
}
```

服务端返回 `{"success": true}` 后，从元素记录/存储中取得该响应对应的公开 URL 并访问，即可看到元数据内容。说明：请求包按原文重写，需要有效会话；本卡片未在本机对真实 Chainlit 实例复跑，也未访问任何真实元数据服务。

## 变体与关联

- 变体：目标改为 `http://127.0.0.1:<port>/`、Docker/K8s 内部服务、数据库管理面、云厂商元数据（AWS `169.254.169.254`、GCP `metadata.google.internal`、Azure `169.254.169.254`）等。
- 变体：若目标允许重定向，可先指向攻击者控制的 302 跳转到内网地址；aiohttp 默认跟随重定向，能在“只检查初始 URL”的实现上扩大打击面。
- 变体：同端点同一数据层还信任元素 `path`，可形成任意文件读取（同版本 CVE-2026-22218）；两者修复方式相同，均是不再从客户端字典传递 `path`/`url`。
- 关联：[[ai-security-agent-security-chainlit-custom-element-path-arbitrary-file-read]]（同端点、同数据层的任意文件读取）、[[web-generic-ssrf-dify-remote-files-upload-unauth]]、[[web-generic-ssrf-vllm-media-connector-urlparse-aiohttp-differential]]、[[web-generic-ssrf-lobechat-botmessage-attachment-fetchurl]]（AI 应用 SSRF 同类）。
- 边界：未启用 SQLAlchemy 数据层、使用不按 URL 拉取的其他数据层、端点不可达或无法取得会话时链不成立。

## 检测与防御

- 升级 Chainlit 到 `2.9.4` 或更高；确认 `_sanitize_custom_element()` 不再接收客户端 `url`/`object_key`。
- 服务端对出站 URL 做严格校验：仅允许 `http`/`https`，解析后拒绝回环、私网、链路本地、元数据地址，并在每次重定向后重新校验；最好改为固定白名单。
- 限制 Chainlit 进程的出站网络（egress 策略/安全组），禁止访问云元数据（启用 IMDSv2 并限制跳数）与内部管理网段。
- 认证与会话：不要把 Chainlit 匿名/公开会话直接暴露给不可信用户；收紧会话签发与访问控制。
- 检测：审计 `PUT /project/element` 中 `type=custom` 且 `url` 指向内网、元数据或异常域名/IP 的请求；监控 Chainlit 进程的异常出站连接与 302 跳转链；检查元素记录中外部 URL 及存储中突然出现的内网响应内容。
- 响应：若已利用，轮换可能泄露的云临时凭证/内网服务凭据，排查内网访问日志与存储中的异常对象，升级并限制出站。

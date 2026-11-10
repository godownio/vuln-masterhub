---
id: web-generic-auth-wechat-appid-appsecret-frontend-leak-access-token
title: 小程序/公众号前端源码泄露 AppID+AppSecret：换 client_credential 接口的 access_token 接管官方接口权限
type: scenario
domain: web
path: web/generic/auth
technique: wechat-appsecret-leak-access-token-takeover
tags:
- wechat
- miniprogram
- appsecret
- access-token
- credential-leak
- api-abuse
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:32:01+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文仅有页面源码中 key/secret 泄露与 cgi-bin/token 返回 7200 的文字描述，后续接口越权利用面（模板消息/菜单/业务域名）为按微信接口语义补充，未在原案例中逐一验证；AppSecret 具体值仅在截图中
url: /docs/web/generic/auth/web-generic-auth-wechat-appid-appsecret-frontend-leak-access-token/
draft: false
kb_aliases:
- 微信小程序 AppSecret 泄露
- 公众号 appid secret 泄露
- cgi-bin/token 获取 access_token
- 微信 access_token 被盗用
- 小程序前端硬编码密钥
---

## 一句话结论

微信小程序/公众号把 `AppID` 与 `AppSecret` 打进了前端可读的地方（页面源码、接口配置、注释过的 JS），而 `AppSecret` 是服务端凭证——攻击者用自己的 IP 调 `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=<APPID>&secret=<SECRET>` 就能拿到该账号的全局 `access_token`（响应 `expires_in` 为 7200 秒），随后以账号身份调用所有需要该 token 的官方接口，等于拿到微信侧的业务接口权限，且不需要任何受害者交互。

## 原理

- **凭证分级错了位置**：`AppID` 是公开标识，`AppSecret` 是账号级密钥。微信官方接口只校验 `appid+secret` 这一对是否匹配，不校验调用方是不是"我们自己的服务器"，因此密钥一旦落到前端/公开仓库，任何第三方都能换到 `access_token`。
- **access_token 是账号级全局凭证**：`/cgi-bin/token` 返回的是该小程序/公众号的接口调用凭证，有效期 7200 秒且（在同一时间窗内）可被多处复用；凡是以 `access_token=<token>` 鉴权的官方接口，都以"账号身份"执行，服务端无法区分真实业务方与攻击者。
- **泄露面不只是 JS**：小程序反编译产物（`app-service.js`、`app-config.json`）、公众号网页的页面源码/调试信息、以及被前端直接请求的业务接口 URL 里都可能出现这对 key；原文案例是网页源码里直接出现 `key`/`secret` 两个字段（即改名后的 appid/appsecret）。
- **为什么危害不止"读数据"**：拿到 token 后能做的动作由账号类型与已开通权限决定，包括读取关注者/用户基础信息、发送模板（订阅）消息、操作素材与菜单、配置业务域名与服务器地址等；这些动作是"业务层越权"，通常比单个接口的 IDOR 严重得多。
- **与 session_key 泄露的区别**：`session_key` 是单个用户登录会话的对称密钥，只影响那一个用户（解密/伪造 phoneNumber）；`access_token` 是账号级凭证，影响面是整个小程序/公众号，两者是不同层的两条链。

## 触发条件

- 小程序/公众号的前端产物或页面源码中存在 `AppID`（`wx` 开头的 18 位串）与 `AppSecret`（32 位十六进制）成对出现，或存在业务后端把这对值下发给前端。
- 该 `AppSecret` 未被重置（微信重置 AppSecret 后旧值立即失效）。
- 攻击者能出网访问 `api.weixin.qq.com`（原文用官方在线调试页 `mp.weixin.qq.com/debug` 等价验证）。

## 利用步骤

1. 从小程序反编译产物/页面源码/前端接口配置里提取 `AppID` 与 `AppSecret`（原文场景为页面源码中的 `key`/`secret` 字段）。
2. 直接 GET `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=<APPID>&secret=<SECRET>`；响应里出现 `"expires_in":7200` 即证明凭证有效且已换到 token。
3. 用 `access_token` 依次探测该账号可用的官方接口（用户信息、模板消息、素材、菜单、域名配置等），先做只读调用确认权限范围。
4. 记录返回的账号信息（原始 ID、类型、已开通权限）作为危害证据；不要真正群发消息或改动线上配置。
5. 若目标同时暴露 `session_key` 三要素泄露，是另一条独立链，不要混为一条。

## PoC

```text
# 1) 换取 access_token（成功时返回 access_token 与 expires_in=7200）
GET https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=<APPID>&secret=<APPSECRET> HTTP/1.1
Host: api.weixin.qq.com

# 2) 用 token 调需要账号鉴权的接口（示例：读取账号下的素材/用户类接口）
GET https://api.weixin.qq.com/cgi-bin/<endpoint>?access_token=<ACCESS_TOKEN> HTTP/1.1
Host: api.weixin.qq.com
```

```text
判据：第 1 步返回体含 access_token 且 expires_in 为 7200；第 2 步不再返回 40001/40013
（invalid credential / invalid appid），说明 token 被账号级接口接受。
```

## 变体与关联

- 关联：[[web-generic-auth-wechat-miniprogram-sessionkey-encrypteddata-takeover]]（同生态的另一层：单个用户会话密钥泄露 → 伪造手机号登录；本卡是账号级 access_token，影响面不同）、[[pentest-recon-wechat-miniprogram-official-account-asset-discovery]]（小程序资产与 AppID 的收集入口）、[[cloud-cloud-iam-nacos-config-aliyun-ak-sk-oss-takeover]]（同类思路：配置中心/前端泄露云厂商 AK/SK 后接管资源）。
- 变体：泄露发生在小程序包内时，用 `wxapkg` 解包 + 全局搜索 `appid`/`secret`/`AppSecret`；发生在公众号网页时，优先看页面源码、内联 JSON 与未压缩的前端配置文件。
- 边界：微信侧对同一账号的 `access_token` 有刷新语义，业务方若频繁刷新会使攻击者 token 失效（不稳定但可重取）；`AppSecret` 被重置后本条链立即失效；只泄露 `AppID` 不构成利用。

## 检测与防御

- 检测：前端产物/页面源码中出现 32 位十六进制的 `AppSecret`；`api.weixin.qq.com/cgi-bin/token` 的调用来源 IP 与业务服务器出口 IP 不一致；同一账号短时间内从多个异地 IP 换 token；账号接口调用出现异常的只读遍历（拉全量用户/素材）。
- 防御：`AppSecret` 只存在服务端，前端一律不出现；用微信"重置 AppSecret"处理泄露；把 access_token 的获取与缓存集中在服务端并绑定出口 IP；对敏感接口（群发、域名配置、菜单）做二次确认与操作审计；定期扫描小程序包与公开仓库中的密钥。

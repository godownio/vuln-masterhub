---
id: mobile-android-httpcanary-static-injection-member-response
title: HttpCanary 静态注入改 /inner/user/member 响应：is_vip 等字段改 true 解锁客户端会员状态
type: scenario
domain: mobile
path: mobile/android
technique: android-httpcanary-response-static-injection-member
aliases:
- HttpCanary 静态注入
- 小黄鸟改响应
- 会员接口响应篡改
- is_vip 改 true
- 抓包解锁 VIP
- 响应体替换规则
tags:
- android
- mobile
- mitm
- httpcanary
- response-tamper
- vip
- entitlement-bypass
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V568
  verified_at: '2026-11-12T09:09:24+08:00'
  notes: 已对照原文12951及全部23张图核对：/inner/user/member响应字段is_vip/is_ever_vip/is_knowledge_vip/is_forever_vip与图14一致，HttpCanary静态注入替换Body与'已注入'状态、会员显示'null到期'与图15-17一致；原文未展示服务端二次校验绕过，卡片边界已写明；未本机复现抓包；dedup top候选(smali改会员判断/iOS代理脚本改响应)均为related非同链，理由成立；app版本为测试环境非受影响版本，未设versions。
---

## 一句话结论

App 的会员状态直接取自 `/inner/user/member` 这类接口的 JSON 响应且无签名校验时，可在 HttpCanary（小黄鸟）里建"静态注入"规则，按 URL 匹配并把响应体中的 `is_vip: false` 等字段替换为 `true`，重新登录后客户端即显示 VIP 并播放会员内容，无需 root/改包。

## 原理

- **客户端信任响应**：个人中心/播放权限读取 `/inner/user/member` 返回的 `data.is_vip`、`is_ever_vip`、`is_knowledge_vip`、`is_forever_vip` 等布尔字段直接渲染会员状态，未校验响应完整性（无签名/MAC/加密），中间人改包即可改变客户端认为的权益。
- **HttpCanary 静态注入**：App 内对目标请求创建注入规则，匹配 URL 中的 `inner/user/member`，在"Body/响应"编辑器中设置替换内容（把 `"is_vip":false` 等改为 `"is_vip":true`）；抓包代理在转发响应时按规则替换，客户端收到的就是"会员"数据。
- **HTTPS 条件**：需要让 App 信任 HttpCanary 的用户证书（Android 7+ 默认不信任用户 CA，需目标 App 未做 SSL pinning、或通过 root/模块把证书装入系统信任区、或 App 的 networkSecurityConfig 允许用户证书）。
- **为什么有效**：整条链路（UI 显示、播放器鉴权）都在客户端基于该响应判断；服务端只在真正拉取音频流时可能二次校验，因此该手法通常解锁 UI 与客户端内的会员内容，跨端/服务端强校验的功能可能仍失败。
- 与改代码的区别：静态注入不改包、不重签，验证快；但依赖抓包环境（证书、同网段代理），换设备/离代理即失效。

## 触发条件

- 目标 App 未对会员接口响应做签名/加密校验；
- 能建立 HTTPS 中间人（无 SSL pinning 或可绕过，证书被 App 信任）；
- 会员状态与内容权限由客户端按响应字段决定，服务端未对每个播放动作二次校验。

## 利用步骤

1. 安装 HttpCanary 并安装证书，配置代理抓包，登录 App 触发 `/inner/user/member` 请求。
2. 查看响应 JSON，确认会员字段（`is_vip`、`is_ever_vip`、`is_knowledge_vip`、`is_forever_vip` 等）。
3. 对该请求创建"静态注入"规则：URL 匹配 `inner/user/member`，响应 Body 设为修改后的 JSON（相关字段全部 `true`；注意保持 JSON 结构合法）。
4. 重新登录/重启 App，观察个人中心显示 VIP；`vip_valid_date` 等格式字段未改时可能显示 `null`，属正常现象。
5. 打开需要会员的音频/功能验证解锁；若播放仍被拒，说明服务端有二次校验。

## PoC

```json
// 原始响应（节选）
{"data":{"is_vip":false,"vip_valid_date":null,"is_ever_vip":false,"is_knowledge_vip":false,"is_forever_vip":false,...}}

// HttpCanary 静态注入替换后（节选）
{"data":{"is_vip":true,"vip_valid_date":null,"is_ever_vip":true,"is_knowledge_vip":true,"is_forever_vip":true,...}}
```

## 变体与关联

- 变体：也可用 mitmproxy/Charles 的 rewrite 规则、Frida hook 网络库回调做同样替换；iOS 版本见 [[mobile-ios-proxy-script-response-tamper-feature-unlock]]（代理脚本改响应解锁去广告）。
- 关联：不想依赖抓包环境时改用 smali 改客户端判断 [[mobile-android-smali-vip-check-force-true-repack]]（本文方法二即此思路，已与已有卡重复）；Frida 伪造会员模型 [[mobile-android-frida-vipinfo-constructor-forge-membership]]。
- 边界：服务端签名响应、播放接口二次鉴权、证书 pinning 都会使该手法失效。

## 检测与防御

- 检测：服务端对会员接口做响应签名并在客户端校验；检测同一账号短时间内在多网络/代理环境登录与异常流量；客户端完整性/证书校验告警。
- 防御：会员权益以服务端为准，播放/下载等敏感动作二次鉴权；对响应加 HMAC/签名；启用 SSL pinning 并禁止用户证书；关键逻辑下沉服务端。

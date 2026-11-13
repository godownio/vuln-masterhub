---
id: mobile-ios-proxy-script-response-tamper-feature-unlock
title: iOS 抓包代理脚本注入篡改 API 响应：按 URL 改写 JSON 字段解锁客户端功能限制/去广告
type: scenario
domain: mobile
path: mobile/ios
technique: ios-proxy-script-response-tamper-unlock
aliases:
- Shadowrocket 脚本注入
- Quantumult X 响应改写
- iOS 抓包改响应
- 客户端功能限制绕过
- MITM 脚本 $done
- 校园卡 APP 去广告
- 客户端权限字段篡改
tags:
- ios
- mitm
- proxy
- javascript
- response-tamper
- client-side-trust
- business-logic
- api
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V528
  verified_at: '2026-11-11T15:09:41+08:00'
  notes: 已对照原文与img02/03核对：MITM脚本执行流程、按URL分支改JSON（power=1解锁/清空广告话题data）与原文代码一致，PoC与原文脚本等价。未验证点：原文为作者自述未给目标App截图，服务端二次鉴权时仅改UI，卡片边界已注明。dedup候选为Android降级抓包与Web响应JS鉴权篡改，平台/改写对象不同，非重复。
---

## 一句话结论

iOS 抓包代理工具（Shadowrocket、Quantumult X 等）在用户信任其 CA 后可以对 App 的 HTTPS 响应注入 JS 脚本：脚本按 URL 匹配接口、`JSON.parse` 响应体后修改业务字段（如把功能列表的 `power` 改成 1、清空广告/话题数据）再 `$done` 回写，App 收到的是被篡改的 JSON，从而绕过"必须绑定校园卡手机号才能使用"等仅由客户端依据响应字段执行的功能限制，并去除开屏广告、冗余模块。

## 原理

- **MITM 位置**：代理工具作为 App 与服务器之间的中间人，用户安装并信任代理根证书后，工具可解密 TLS、读取并改写请求/响应。
- **脚本钩子**：Quantumult X/Shadowrocket 提供 `$request`、`$response`、`$done` 等全局对象，脚本在响应交付 App 之前执行；`$response.body` 是响应体字符串，`$done({body: ...})` 返回修改后的响应。
- **客户端信任模型缺陷**：App 依据响应中的业务字段决定 UI 与功能入口。例如业务列表接口 `v2/base/schoolBusinessList` 的每项带 `power` 字段，客户端据此判断该功能是否可用（`power=1` 才开放）；脚本把每项 `power` 置 1 后，App 即认为用户已具备权限。`v2/banner/getBanner` 返回广告位，脚本把 `data` 置空即去广告。
- **为什么能绕过登录限制**：限制逻辑在客户端（或客户端信任服务端下发的开关），而 MITM 脚本可在数据到达客户端前改写；只要服务端在被调用时不再次校验身份/权限，功能即可用。若服务端对关键操作二次鉴权，改响应只能改变 UI、不能真正执行。
- **脚本结构**：先判断 `$response.status != 200` 直接 `$done({})`；`try { body = JSON.parse($response.body) } catch { $done({}) }`；按 `$request.url` 截取路径 `action` 分支处理；最后 `backData()` 用 `$done({status:200, headers:$response.headers, body: JSON.stringify(data)})` 回写。
- **边界**：App 若启用证书固定（SSL Pinning/mTLS）、响应签名校验或关键逻辑在服务端，则改包失败或仅改 UI；代理证书需要用户手动信任，仅影响本机。

## 触发条件

- 目标 App 的 HTTPS 流量可被代理工具解密（未启用证书固定，或已用工具/越狱插件绕过）。
- 功能开关/权限判定字段由服务端响应下发并被客户端直接信任；服务端关键接口未做二次鉴权。
- 使用支持响应脚本重写的代理工具（Quantumult X、Shadowrocket 等），并能编写匹配 URL 的脚本。
- 攻击者控制本机代理环境（自己的设备或可安装证书的设备）。

## 利用步骤

1. 在 iOS 设备安装代理工具与 CA 证书并信任；配置规则让目标 App 流量走代理。
2. 打开 App 触发目标功能，在工具/配套抓包中定位接口：业务列表（如 `v2/base/schoolBusinessList`）、广告位（`v2/banner/getBanner`）、话题/评论/视频等。
3. 对比正常与受限状态下的响应，找出决定功能可用性的字段（本例 `power`）。
4. 编写响应脚本：按 `$request.url` 路径分支，修改 JSON 字段（`power=1`、清空广告 `data={}`、清空话题/评论/视频 `data=[]`），`$done` 回写。
5. 重新打开 App，确认功能入口解锁、广告消失；若 App 仍有服务端校验，操作时会报错，说明限制在服务端，需另寻他路。

## PoC

```javascript
// Quantumult X / Shadowrocket 响应脚本（节选，按目标接口调整）
if ($response.status != 200) $done({});
let body;
try { body = JSON.parse($response.body); } catch (e) { $done({}); }

let action = $request.url.split("?", 2)[0].split("net/", 2)[1];
switch (action) {
  case "v2/banner/getBanner":          // 去广告位
    body["data"] = {};
    backData(body); break;
  case "v2/base/schoolBusinessList":   // 解锁受限业务（power=1）
    body["data"].forEach((item) => { item["power"] = 1; });
    $notification.post("操作已完成", "", "你现在可以关闭代理了");
    backData(body); break;
  case "v2/topic/getTopictList":
  case "v2/topic/getTopicComment2":
  case "v2/topic/getNextTopicVideo":
  case "v2/topic/getTopicDetail":      // 去话题/评论/视频
    body["data"] = [];
    backData(body); break;
}

function backData(data) {
  $done({ status: 200, headers: $response.headers, body: JSON.stringify(data) });
}
```

## 变体与关联

- 变体一：Android 同等能力用 mitmproxy/Charles + 重写规则或 Xposed/Frida hook；原理相同。
- 变体二：改请求同样可行（如给请求增加 `power=1`、伪造会员标识），视服务端信任方向而定。
- 变体三：若 App 有证书固定，可结合 Frida（`ssl_write`/`SSL_CTX_set_verify` hook）或越狱插件绕过后再改包；也可用系统级 VPN + 透明代理。
- 关联：[[code-analysis-reverse-anti-debug-proxy-js-replacement-bypass]]（代理改 JS 绕过前端反调试，同为 MITM 改写思路）、[[web-generic-client-side-score-trust]]（客户端信任上报/下发字段的业务逻辑缺陷）。
- 边界：服务端二次鉴权、响应签名、证书固定、关键逻辑在服务端时，改响应只能改变 UI；只影响本机，不改变服务端数据。

## 检测与防御

- 检测（App/服务端侧）：同一账号出现与客户端 UI 不一致的请求（未解锁功能却直接调用受限接口）；TLS 指纹/证书链异常；请求频率与设备行为异常；响应被改后客户端上报的字段组合不符合业务规则。
- 防御：关键权限与功能开关由服务端在每次调用时校验，不信任客户端状态；对敏感响应做签名或绑定会话；启用证书固定/mTLS；检测代理环境与异常 CA。
- 加固：客户端只做展示与交互，不作为安全边界；服务端对业务操作做对象级鉴权与审计；对异常请求做风控。

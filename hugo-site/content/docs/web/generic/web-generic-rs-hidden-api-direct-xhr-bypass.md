---
id: web-generic-rs-hidden-api-direct-xhr-bypass
title: 瑞数动态防护下的隐藏 API 直连：从混淆业务 JS 提取接口，控制台 XMLHttpRequest 带 Bearer 绕过页面防护
type: scenario
domain: web
path: web/generic
technique: rs-hidden-api-direct-xhr-bypass
tags:
- web
- rs
- bot-defense
- anti-bot
- api-discovery
- xhr
- authorization
- bypass
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V441
  verified_at: '2026-11-09T22:18:24+08:00'
  notes: 已对照幻灯片核对：图13 隐藏入口 /srm/api/person/person-card?id= 与 JS l.prototype.personCard 拼接、图14 rsPost(XHR+X-Requested-With+Content-type+Authorization Bearer) 控制台返回 createdBy/lastModifiedBy/name/phone/email/positions JSON，与卡内步骤/PoC 一致。注意幻灯片中带 RS 参数的直连请求返回 400，而页面上下文 XHR 成功，卡内将其解释为 API 未纳管+页面上下文合法，属合理推断但机制未在幻灯片中明说（confidence medium 已如实标注）；未实测。
url: /docs/web/generic/web-generic-rs-hidden-api-direct-xhr-bypass/
draft: false
kb_aliases:
- 瑞数 bypass
- RS 防护绕过
- 隐藏攻击入口
- 控制台直接 XMLHttpRequest
- person-card 接口直连
- 页面防护绕过
---

## 一句话结论

瑞数（RS）动态防护主要保护 HTML 页面与 JS 挑战流程（首次响应下发 cookie_s、混淆 JS 计算 cookie_t、带齐 Cookie 才能拿到正常页面），但业务 API 往往没有接入同一层防护；从页面混淆 JS 中提取出接口路径（如 `/srm/api/person/person-card`）后，在浏览器控制台用 `XMLHttpRequest` 带上页面已有的 `Authorization: Bearer <token>` 直接请求，即可绕过 RS 拿到 JSON 业务数据。

## 原理

- RS/Botgate 的典型流程是：第一次请求返回带 `Set-Cookie: ...`（cookie_s）的 HTML 和一段自执行混淆 JS；浏览器执行 JS 生成 cookie_t；后续携带 cookie_s+cookie_t 的页面请求才返回 200 正常内容。防护的核心对象是“页面访问”与“JS 环境”。
- 业务 API 的鉴权通常只依赖 `Authorization` 头或会话 Cookie，而 Botgate/WAF 的防护规则常按路径/内容类型配置，API 路由（`/srm/api/...`，返回 JSON）可能不在防护范围内，或被配置为放行。
- 前端业务 JS 里必然包含 API 路径：例如 `l.prototype.personCard = function(){ var t = this.getUrl() + "/person-card"; return this.http.get(t,{params:{id:n}}) ... }`。攻击者从 Sources/搜索中拿到路径与参数名，再在控制台取页面内存中的 Bearer token（localStorage/sessionStorage/JS 变量/请求头），直接发起 XHR。
- 由于请求由页面自身的源发起、携带合法 token、UA/Referer 一致，服务端看到的是“正常登录用户的 API 调用”；RS 的页面挑战没有参与，因此没有被拦截。
- 若接口的授权校验也有缺陷（如按 id 直接返回他人信息），该绕过会进一步放大为 IDOR/越权数据获取；这属于接口自身问题，和 RS 无关。

## 触发条件

- 目标使用瑞数（或类似 Botgate）动态防护，页面访问需要 cookie_s/cookie_t。
- 业务 API 未被同一套防护覆盖，且可以用页面已有的 Bearer token/会话直接访问。
- 测试者能在浏览器中执行 JS（DevTools 未被禁用），且拥有一个有效登录会话或可获取 token。
- 仅对授权目标使用；批量枚举 id 属于越权测试，需在授权范围内。

## 利用步骤

1. 正常访问页面，观察请求次数与 Cookie：首次响应 Set-Cookie（cookie_s），第二次带 cookie 请求 JS，第三次带 cookie_s+cookie_t 返回 200。
2. 在 DevTools → Sources/全局搜索中查找业务 JS，定位 API 路径与参数（如 `/srm/api/person/person-card?id=`、`getUrl()` 拼接、`this.http.get`）。
3. 获取当前会话的 token：搜索 `Authorization`、`Bearer`、`localStorage`、`sessionStorage`，或在 Network 面板复制任一业务请求的头。
4. 在 Console 中定义直接请求函数（同步 XHR 便于取回结果），带 `X-Requested-With`、`Content-Type`、`Authorization` 请求 API。
5. 读取返回 JSON，确认是否为业务数据；如需遍历参数（如 id），先用小范围验证再评估越权影响。
6. 若 API 也要求 RS Cookie，则改用“扣代码补环境生成 cookie_t”的方法（见关联卡）。

## PoC

```javascript
// 浏览器 Console 中执行；token 从当前页面会话获取
function rsPost(path) {
  var x = new XMLHttpRequest();
  x.open("GET", path, false);
  x.setRequestHeader("X-Requested-With", "XMLHttpRequest");
  x.setRequestHeader("Content-type", "application/json");
  x.setRequestHeader("Authorization", "Bearer " + "<当前会话 token>");
  x.send(null);
  if (x.readyState === 4) return x.responseText;
}

rsPost("/srm/api/person/person-card?id=1");
// 返回中包含 createdBy/lastModifiedBy/name/phone/email/positions 等业务字段
```

## 变体与关联

- 变体：POST/PUT 接口把参数放在 JSON body；token 在 Cookie 而非 Authorization 头时，直接带 Cookie 即可（XHR 同源自动携带）。
- 变体：API 路径不在页面 JS 明文出现（动态拼接/加密）时，可在 Network 面板观察页面自身加载数据时的请求，或对 `this.http.get/post` 下断点记录参数。
- 变体：部分接口仍校验 RS Cookie/签名，此时需要 [[code-analysis-reverse-obfuscation-rs-cookie-t-environment-emulation]] 生成 cookie_t，或结合 JS-Forward 在明文点改包。
- 关联：[[pentest-recon-vue-spa-router-service-api-extraction]]（从前端 JS 提取 API 路由）、[[pentest-recon-webpack-apiurlkey-endpoint-extraction]]（webpack 产物提取隐藏端点）、[[web-generic-client-side-score-trust]]（客户端防护不等于服务端校验的同类思路）。
- 边界：API 若真正接入 Botgate、或 token 短时失效、或服务端校验 Referer/签名，则直连失败；该手法绕过的是“页面防护”，不能绕过服务端鉴权。

## 检测与防御

- 把 Botgate/风控规则覆盖到 API 路由，而不是只保护 HTML；对返回敏感数据的接口校验 RS Cookie/签名/一次性令牌。
- 服务端做对象级授权（每个 id 校验归属），不要依赖前端隐藏接口；对批量 id 访问做频率与越权检测。
- 监测：同一会话在未完成页面挑战的情况下直接访问业务 API、无 Referer/无 cookie_s 的 JSON 请求、短时间遍历 id 等行为，可作为风控信号。
- 前端：减少在 JS 中暴露完整接口与参数名只能提高成本，不能替代服务端防护。

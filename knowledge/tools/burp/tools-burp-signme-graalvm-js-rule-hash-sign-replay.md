---
id: tools-burp-signme-graalvm-js-rule-hash-sign-replay
title: Burp SignMe 插件用 GraalVM JS 规则重算 Hash 签名与时间戳：把「签名错误」的支付接口变成可改包可爆破的明文接口
type: scenario
domain: tools
path: tools/burp
technique: burp-signme-graalvm-js-rule-hash-sign-recompute
aliases:
- SignMe 插件
- SignMe 重算签名
- GraalVM JS 规则
- Signature 覆盖 OVERRIDE
- Timestamp 重算
- 支付接口签名绕过
- 参数排序拼接 MD5 签名
- 签名接口爆破
tags:
- burp
- signme
- graalvm
- javascript
- signature
- hash
- md5
- timestamp
- anti-tamper
- pentest
- tooling
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:33:10+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文关键证据（请求包、sign 函数、Repeater 成功回显、插件日志）均以截图呈现，正文仅文字描述，卡内 sign 算法拼接顺序、GraalVM 写法限制、utils API 名称均与正文一致；salt 原文已脱敏，PoC 用占位符；原文未给插件版本区间，未设 affected_versions；未执行文中命令/PoC，未访问文中 URL
---

## 一句话结论

当客户端「签名」只是把参数按键名排序拼接、再拼上时间戳 Base64、Token、硬编码 salt 做一次 MD5（本质是 Hash 校验，不是带私钥的数字签名）时，把这个算法在 Burp 插件 SignMe 的 GraalVM JS 规则里复刻一遍，规则会自动读取每个被拦截请求的参数与 Token、生成当前时间戳、算出并 OVERRIDE 请求头里的 `Signature`/`Timestamp`，于是改金额、改数量、上 Intruder 爆破都不再被「签名错误 / 时间戳过期」挡住。

## 原理

- **前后端同源的「签名」必然可复算**：算法与材料（Token、salt、时间戳、参数）全部在客户端 JS 里，服务端只是用同样材料重算后比对。没有私钥参与，就没有「只有服务端能生成」的性质，任何拿到 JS 的人都能生成合法值；它提供的是完整性（防篡改传输）而非身份认证/不可否认性。
- **为什么手工改包一定失败**：`Signature` 覆盖了业务参数，任何一个字节变化都会让重算的 Hash 不同；同时 `Timestamp` 常参与签名，且服务端有窗口校验（案例中先报「签名错误」，修好签名后又报「时间戳过期」），所以「改包」和「重放」两道闸必须同时处理：签名要重算，时间戳要用当前时间。
- **为什么放在 Burp 插件里做**：手工在 IDE 里跑脚本再回填，一改参数就要重跑一次，无法支撑 Intruder 的大量请求。SignMe 的工作方式是：按规则白名单匹配 URL → 调用规则里的 `main()`，把请求对象交给 JS → `main()` 返回一个「对象数组」声明要改哪里（header/body 参数）、改什么值、用哪种动作（OVERRIDE/ADD/REMOVE 等）；插件在请求发出前统一改写，因此 Repeater、Intruder、Proxy 都能自动带上新签名。
- **GraalVM 的限制决定了写法**：插件内置引擎对 `RegExp` 支持不完整，原 JS 里 `replace(new RegExp(...))` 之类的清洗要换成逐字符/字符串 `replace`；`utils.getTimestamp()` 的高精度参数在实测中不一定生效，需要自己 `String(ts).slice(0,10)` 截取；`utils.getParametersByType(ParameterType.PARAM_JSON)` 返回的是 `{name,value,location}` 结构的参数列表，要先按名排序、再组装成对象，才能复刻原算法的拼接顺序。
- **成立的关键假设**：salt/Token 可获取（Token 在请求头里、salt 硬编码在 JS 中），且服务端不额外绑定一次性 nonce 或设备指纹。只要满足这两点，复算出的签名被服务端视为合法。

## 触发条件

- 目标接口的请求头/请求体带 `Signature`（或 `sign`）与 `Timestamp` 字段，改动业务参数后返回「签名错误」「非法请求」之类。
- 签名算法可在浏览器 DevTools 里定位到（通常是 `sign(e, t)` 形态的打包函数），且材料全部来自客户端：参数、时间戳、Token、硬编码 salt。
- Token 可稳定获取：已在请求头里、或可固定从某个登录响应中取出。
- 能安装 Burp 扩展并访问插件的规则管理页（默认本地端口）。
- 服务端仅做「重算比对 + 时间窗校验」，未把签名与一次性 nonce/会话/设备指纹绑定。

## 利用步骤

1. **确认签名点**：抓一个正常请求（案例是支付下单，含 `orderAmount`、`vip` 等字段和 `Signature`、`Timestamp`），只改金额重放，确认返回「签名错误」。
2. **定位算法**：在 DevTools 的 Sources/搜索里找 `Signature`/`sign` 关键字，读到 `sign(e,t)`：先取 `Token`，对参数按 key 排序、拼接 `key+value`、去掉括号引号，再把 `Base64(时间戳前 10 位) + Token + salt + 拼接串` 交给 `js-md5` 的 `md5`。
3. **离线验证一次**：把该函数抠出来，在本地用 Node/浏览器跑一遍，喂同一个请求的参数与时间戳，确认算出的 Hash 与抓包中的 `Signature` 完全一致（不一致就说明还有隐藏材料或字段顺序差异）。
4. **建规则**：安装插件后进入规则管理页，新建规则，填 URL 白名单（只匹配目标接口），勾选生效范围（Proxy、Repeater，需要爆破再勾 Intruder）。
5. **写 `main()`**：GET 直接返回空数组跳过；POST 时取 `request.headers['Token']`、`utils.getTimestamp()`、`utils.getParametersByType(ParameterType.PARAM_JSON)`，按名 ASC 排序拼成对象，按第 3 步的顺序拼串、`utils.md5` 求值。
6. **声明改写**：`return` 两个动作——`Signature`（HEADER, OVERRIDE）与 `Timestamp`（HEADER, OVERRIDE），值分别为算出的签名与当前 13 位时间戳。
7. **验证**：在 Repeater 里只改 `orderAmount`，直接 Send；插件控制台应打印 `Edit header Signature finished`、`Edit header Timestamp finished`，响应正常返回业务数据。再改一次参数确认可重复生效。
8. **扩展**：勾上 Intruder 即可对登录、遍历类接口做爆破/枚举，签名与时间戳由规则自动跟随每个 payload 重算。

## PoC

```javascript
// SignMe 规则 main()：复刻 sign(e, t) = md5(base64(ts[0:10]) + token + salt + sortedParams)
// 说明：salt 在原文中脱敏；utils 为插件内置工具库
let salt = '<js 中的硬编码 salt>';

function main() {
  if (request['HTTPMethod'] !== 'POST') {
    return [];
  }
  let token = request.headers['Token'];
  let ts = utils.getTimestamp();               // 13 位毫秒时间戳

  // 取出 JSON 参数并按名字升序；getParametersByType 返回 [{name,value,location}]
  let params = utils.getParametersByType(ParameterType.PARAM_JSON);
  let e = {};
  utils.sortParameters(params, SortType.ASC).forEach(it => { e[it.name] = it.value; });

  // 原算法：key+value 依次拼接（GraalVM 不支持 RegExp，用字符串 replace 清洗）
  let a = '';
  Object.keys(e).sort().forEach(k => {
    if (typeof e[k] !== 'undefined') {
      a += k + e[k];
    }
  });
  a = a.replace('[', '').replace(']', '').replace('"', '');

  // 时间戳只取前 10 位参与签名，再 base64
  let s = utils.base64encode(String(ts).slice(0, 10)) + token + salt + a;
  let signature = utils.md5(s);

  // 未指定时间戳时插件用当前时间，避免「时间戳过期」
  return [
    {name: 'Signature', value: signature, location: ParameterType.HEADER, action: EditAction.OVERRIDE},
    {name: 'Timestamp', value: ts,        location: ParameterType.HEADER, action: EditAction.OVERRIDE}
  ];
}
```

验证要点：先在本地对「抓包时的参数 + 抓包时的 Timestamp」算出签名，必须与抓包值逐字符一致，再放进规则；否则规则会稳定地发出非法签名，表现为一直「签名错误」而不是偶发。

## 变体与关联

- **签名材料变体**：`md5(sortedParams + token + timestamp)`、`HmacSHA256(body, key)`、`sha1(ts + nonce + params)`、参数值做 URL 编码后再拼、只取参数名不取值；差别只在拼接顺序与编码，写法不变。
- **防重放变体**：时间戳换成一次性 `nonce`/`requestId`，规则里改为随机串并写回；若服务端把 nonce 与上次值比对，则需要每次生成递增/随机值并写回请求头。
- **同层工具替代**：浏览器侧代算签名（JsRpc 之类，让页面原函数生成签名再回填）、双层 mitmproxy 加解密代理；本卡的区别是完全在 Burp 插件内用 GraalVM JS 复算，不需要挂浏览器、不需要额外代理端口，适合只有 Hash 签名而无请求体加密的接口。
- **关联**：[[tools-burp-galaxy-jsrpc-auto-encrypt-decrypt-sign]]（签名依赖浏览器运行时状态时改用页面代算）、[[tools-burp-encrypted-api-proxy-decrypt-resign]]（同时存在请求体加密与签名时的双层代理方案）。
- **边界**：若 salt 由服务端每次下发且与会话绑定、或签名覆盖了服务端独有的一次性挑战，复算路线不成立，需要先拿到挑战值；若服务端把签名与设备指纹/证书绑定，插件改包会被识别。

## 检测与防御

- **服务端防御**：把完整性校验换成服务端签发的一次性 nonce/挑战并绑定会话，校验后立即失效；对支付等敏感金额做服务端权威计价，客户端传来的金额只作参考；关键参数（金额、商品 ID、天数）在服务端做合理性校验。
- **不要依赖客户端 Hash 当安全边界**：硬编码 salt、内置 Token、前端 md5 都属于公开信息；混淆只能提高复算成本。
- **检测信号**：同一账号短时间大量请求且签名合法但业务参数异常（金额、数量跳变）；`Timestamp` 与服务端时间偏差极小但请求频率异常；同一 `Signature` 复用（说明重放而非重算）；Burp 类代理 UA/证书指纹。
- **审计侧**：接口若只校验「签名正确」而不校验业务规则，等价于只校验了报文完整性，应视为可任意改包的业务逻辑风险。

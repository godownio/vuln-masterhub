---
id: web-generic-auth-frontend-aes-key-iv-sessionstorage-localstorage-ua-stability
title: 前端 AES key/iv 存 sessionStorage 刷新即失效：把 UA 改成 QQ 浏览器触发 localStorage 分支，让 JSRPC/Burp 加解密链路保持动态密钥稳定
type: scenario
domain: web
path: web/generic/auth
technique: frontend-aes-key-sessionstorage-localstorage-ua-switch
aliases:
- bqzt_randomRequest
- 前端随机密钥刷新失效
- sessionStorage key iv 重置
- UA 切 localStorage 固定密钥
- mqqbrowser UA 分支
- 动态 AES 密钥稳定化
tags:
- javascript
- frontend-encryption
- aes
- key-iv
- sessionstorage
- localstorage
- user-agent
- jsrpc
- autodecoder
- pentest
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V509
  verified_at: '2026-11-11T04:54:45+08:00'
  notes: 已对照原文 content.md 与 16 张截图核对：图02 UA 为 HeyTapBrowser（非 mqqbrowser），图11-14 证实 b.dfg/b.cvb 来自 Object(h["o"])("randomRequest",!0)，取数函数按 /mqqbrowser/i 在 sessionStorage/localStorage 间切换；图15 存储面板显示 localStorage 的 bqzt_randomRequest 含 dfg/cvb 与 count，会话存储另有 bqzt_get_rz_token；图16 autoDecoder 生效。修正机制表述：sessionStorage 刷新本身不清空而是按标签页隔离，原文现象来自页面每次加载重新生成 key/iv 及注入页/测试页不同标签页，已改为与原文“同一浏览器”语境一致的表述。dedup：与 frontend-js-random-key-fixation-autodecoder（固定 Math.random）及 JWT SecretKey/SecretIV 卡机制不同，非重复。非组件问题，无 affected_versions。
---

## 一句话结论

目标前端把 AES 的 key/iv 存在 `sessionStorage["bqzt_randomRequest"]`（JSON 的 `dfg`/`cvb` 字段），页面每次加载会重新生成/下发 key/iv 并写入，刷新或新开标签页后值即变化，导致 Burp/JSRPC 链路里硬编码的 key/iv 立即失效；而读取该值的 `f(e,t)` 用 `/mqqbrowser/i.test(navigator.userAgent)` 决定存 `sessionStorage` 还是 `localStorage`——把浏览器 UA 改成 QQ 浏览器，应用就会把 key/iv 写进持久化的 localStorage，刷新不再丢失，注册的 action 每次从 localStorage 动态取 key/iv 即可持续加解密。

## 原理

- **key/iv 不在代码里，而在浏览器存储里**：加密调用形如 `Object(r["b"])(e.data, b.dfg, b.cvb)`，其中对象 `b` 由 `Object(h["o"])("randomRequest", !0)` 生成。跟进 `Object(h["o"])` 得到取数函数（示例）：

  ```javascript
  function f(e, t) {
      e = "bqzt_" + e;
      var a = "sessionStorage";
      if (/mqqbrowser/i.test(window.navigator.userAgent) && (a = "localStorage"),
      window[a]) {
          var i = window[a][e] || "";
          return t && i && (i = JSON.parse(i)), i
      }
      console.log("当前浏览器不支持sessionStorage")
  }
  ```

  即先拼前缀 `bqzt_`，默认从 `sessionStorage` 读取 `bqzt_randomRequest`，UA 匹配 QQ 浏览器时改用 `localStorage`；第二个参数为真时 `JSON.parse` 返回值。
- **两处调用同一个分支**：加密时 `b.dfg`/`b.cvb` 作为 key/iv 传入；`b` 从存储读出后，写回时也走同一分支——所以存储介质由 UA 决定，key/iv 的“生命周期”也随之改变。
- **存储介质的生命周期差异**：sessionStorage 按标签页隔离，关闭/新开标签页即新建，注入页与测试页不在同一标签页时 key/iv 必然不一致；localStorage 按源（origin）持久存储，同源标签页共享且刷新不丢失。本例页面刷新时还会重新生成/覆盖 key/iv，硬编码进一步失效——这就是“调试时可用、刷新后失效”的根因。
- **JSRPC 链路为什么需要稳定 key/iv**：autoDecoder/Flask 调 Sekiro/浏览器 action 时，若每次调用都带着 Flask 里硬编码的 key/iv，而页面实际使用刷新后的新 key/iv，加解密结果与服务端不一致；让 action 每次从 localStorage 动态读取当前 key/iv，则注入页与目标页处于同一浏览器、同一 origin 时始终一致。
- **UA 修改要真正影响 `navigator.userAgent`**：只改 HTTP 请求头不会改变页面 JS 的 `navigator.userAgent`；需用 DevTools 的设备模拟/自定义 UA、UA 切换扩展，或在中间人处把 JS 判断改为恒真（如 Burp 响应替换 `/mqqbrowser/i.test(...)`）。改后刷新页面，让应用按新分支重新写入存储。
- **为什么成立**：key/iv 的生成与存储完全由客户端控制，存储位置分支只是前端兼容逻辑；测试者拥有浏览器与页面执行环境，必然能改变它。

## 触发条件

- 目标前端加密 key/iv 非硬编码，而是运行时生成/下发后存入浏览器存储（sessionStorage/localStorage）。
- 读取函数内的存储介质选择受 UA（或其他可被测试者改变的环境信号）分支控制。
- 测试者能以合法账号打开页面，并能修改 `navigator.userAgent`（DevTools 自定义 UA、扩展或中间人改 JS）。
- JSRPC/autoDecoder 注入脚本与目标操作页面在浏览器中可保持同一 origin/会话（localStorage 是 per-origin）。
- 登录会话本身不因 UA 突变被服务端风控拦截（必要时配合正常 UA 的其他请求或仅在本地 JS 环境生效）。

## 利用步骤

1. 在加密调用处下断点，确认 key/iv 来自对象 `b`（`b.dfg`/`b.cvb`），控制台跟进 `b` 的生成函数（`Object(h["o"])("randomRequest", !0)`）。
2. 跟进取数函数，确认存储键名（如 `bqzt_randomRequest`）、JSON 结构（如 `{"dfg":"<key>","cvb":"<iv>"}`）与 UA 分支：默认 `sessionStorage`，UA 匹配 `/mqqbrowser/i` 时用 `localStorage`。
3. 在 DevTools Application/存储面板查看 `sessionStorage`，确认当前 key/iv 值；刷新页面观察值变化，验证“硬编码失效”现象。
4. 把浏览器 UA 改为 QQ 浏览器形态（DevTools 设备模拟自定义 UA、UA 扩展，或在 Burp 中替换 JS 使分支恒真），刷新页面。
5. 再次查看存储，确认 `bqzt_randomRequest` 已写入 localStorage；刷新页面验证值不再变化。
6. 修改 Sekiro/JSRPC 注册的 action，从动态存储取 key/iv：

   ```javascript
   client.registerAction("aes_enc", function (request, resolve, reject) {
       var cfg = JSON.parse(localStorage.getItem("bqzt_randomRequest"));
       resolve(enc(request["enc_par"], cfg.dfg, cfg.cvb));
   });
   ```

7. 在 Burp/autoDecoder 中持续加解密、改包重放，刷新页面后链路仍可用。
8. 若服务端对 UA 与请求指纹做一致性校验，注意恢复常规 UA 或只在本机 JS 环境内使用该分支。

## PoC

```javascript
// 目标取数函数（还原）：UA 决定存储介质
function f(e, t) {
    e = "bqzt_" + e;
    var a = "sessionStorage";
    if (/mqqbrowser/i.test(window.navigator.userAgent) && (a = "localStorage"),
    window[a]) {
        var i = window[a][e] || "";
        return t && i && (i = JSON.parse(i)), i
    }
    console.log("当前浏览器不支持sessionStorage");
}

// 存储内容示例
// sessionStorage/localStorage["bqzt_randomRequest"] =
//   {"dfg":"<16 字节 key>","cvb":"<16 字节 iv>","count":0}

// 加密调用：key/iv 来自存储
// e.data = Object(r["b"])(e.data, b.dfg, b.cvb);

// JSRPC action 动态读取（刷新后仍有效）
client.registerAction("aes_enc", function (request, resolve, reject) {
    var cfg = JSON.parse(localStorage.getItem("bqzt_randomRequest"));
    resolve(enc(request["enc_par"], cfg.dfg, cfg.cvb));
});
```

UA 切换方式（任选其一，目的是让页面 JS 的 `navigator.userAgent` 命中 `/mqqbrowser/i`）：DevTools 命令菜单/设备模拟中的自定义 UA、浏览器 UA 切换扩展、Burp 响应替换把 JS 中 UA 判断改为恒真。

## 变体与关联

- **与“固定随机密钥”的区别**：另一条路线是用 Burp Match/Replace 把 `Math.random()` 表达式改为恒 0，使 key 固定（[[web-generic-auth-frontend-js-random-key-fixation-autodecoder]]）；本卡不动密钥生成，而是改变 key/iv 的存储介质与生命周期，适用于密钥由服务端下发或由非 `Math.random` 逻辑生成、无法简单固定的场景。
- **配套链**：本卡服务于 [[tools-burp-autodecoder-flask-sekiro-jsrpc-body-encrypt-decrypt]] 一类 JSRPC 透明加解密链路；也适用于 Galaxy + JsRpc、Hlclient + autoDecoder 等需要 key/iv 在页面刷新后保持稳定的方案。
- **变体**：若存储键名/结构不同，按实际函数调整；若 UA 分支改为其他条件（如浏览器特性检测），替换对应信号；若 key/iv 由服务端接口下发，可尝试重放该初始化请求刷新本地存储，或直接调用页面函数重新生成。
- **边界**：localStorage 按 origin 隔离，注入页与目标页必须同源；页面若校验 UA 与服务端会话一致性，改 UA 可能导致登录失效；key/iv 仅是客户端加密参数，解密≠越权，仍需服务端业务校验。

## 检测与防御

- **检测**：同一会话的密文出现可预测的密钥模式（如刷新前后 key 变化而密文结构固定）；客户端 UA 与设备指纹、其他请求头不一致（声称 QQ 浏览器但 WebGL/字体/时区不符）；JSRPC 本地 WebSocket 长连接与异常自动化流量。
- **防御**：不要把客户端加密与密钥存储当作安全边界；密钥由服务端下发并在服务端校验请求完整性与权限；关键操作加时间戳/nonce/签名与频控；对 UA 与设备指纹一致性做风控，对异常密钥复用与重放行为告警。
- **测试侧注意**：改 UA 与注入脚本仅用于授权测试环境；保存的 key/iv、localStorage 内容按敏感信息处理，测试结束清理。

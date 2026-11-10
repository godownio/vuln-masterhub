---
id: code-analysis-reverse-obfuscation-js-sign-execjs-dependency-patch
title: 扣 JS 复现前端签名：execjs 报 ReferenceError 时逐个补齐 IQ（CryptoJS MD5 工厂）与 TQ（crypto polyfill），并按页面逻辑两次调用签名函数
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: js-sign-extract-execjs-dependency-patch
aliases:
- 前端 sign 签名破解
- 扣 JS 补依赖
- execjs ReferenceError 定位依赖
- CryptoJS MD5 工厂 IQ
- crypto polyfill TQ
- g5 两次调用签名
- 参数排序拼接双 MD5 固定盐
tags:
- javascript
- reverse
- frontend-sign
- execjs
- cryptojs
- md5
- devtools
- debugging
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V462-fix
  verified_at: '2026-11-10T15:11:46+08:00'
  notes: V462 指出『第二次调用把上次 sign 纳入签名』与图10/14 矛盾：sign 在黑名单中、排序前已 delete，第二次实际只算 {username,ver,mt}，单次调用亦等价。已改写一句话结论/原理/步骤5/PoC 注释为『两次调用只是复刻页面流程，非算法必需』。
---

## 一句话结论

把前端 `sign` 生成函数 `g5` 扣到本地 `sign.js` 用 Python `execjs` 调用时，`ReferenceError: IQ is not defined`、`TQ is not defined` 不是障碍而是依赖清单：按 `IQ(`/`IQ =`、`TQ(`/`TQ =` 两种定义写法在同一 JS 文件里搜索并补齐 CryptoJS 风格 MD5 工厂与 crypto polyfill，即可离线复现服务端认可的 32 位大写签名。页面流程中 `g5` 被调用两次（先签 `{username}`，再随 `ver`/`mt` 整体签），但第二次调用时上一次的 `sign` 会被键黑名单剔除、不参与计算；两次调用只是忠实复刻页面，单次用 `{username, ver, mt}` 也能得到相同最终 sign。

## 原理

- **签名函数本身是纯 JS，可在本地重放**：目标接口 `/api/member/getMobile` 的 `sign` 由前端 `g5(e)` 生成：`JSON.parse(JSON.stringify(e))` 深拷贝后遍历键，跳过 `coLicensePic/cardPic1/cardPic2/cardPic3/reject_reason/sign` 等黑名单字段，把剩余键按字典序 `sort()`，拼成 `key=>value@key=>value@...` 并去掉末尾 `@`，`IQ(o).toString()` 得第一次 MD5，再拼固定盐 `^_*#06@!@6#_^`，第二次 `IQ` 后 `toUpperCase()`。算法只依赖前端代码里的固定盐，没有服务器端密钥，因此一旦还原即可对任意参数重签。
- **`IQ` 是 CryptoJS 式 MD5 工厂**：搜索 `IQ =` 找到 `IQ = PQ.exports = function(e) { return function(t) { var n=e, o=n.lib, a=n.algo, l=a.MD5=i.extend({_doReset:...}) ... } }`——它把 CryptoJS 的 `WordArray`/`Hasher` 作为参数传入并返回 MD5 哈希构造函数，属于“工厂函数 + 闭包依赖”结构；只扣 `g5` 时 `IQ` 不在作用域，execjs 直接抛 `ReferenceError`。
- **`TQ` 是运行环境 crypto polyfill**：搜索 `TQ =` 找到 `TQ = {exports:{}}` 与 `TQ.exports = (_Q = _Q || function(e,t){ ... window.crypto / self.crypto / globalThis.crypto / window.msCrypto / require("crypto") ... getRandomValues/randomBytes ... })`——这是给 MD5 工厂提供随机数/加密能力的浏览器兼容层；在 Node/V8 里执行时若缺失，`IQ` 内部初始化会再次报 `ReferenceError`。
- **ReferenceError 是确定的依赖解析顺序**：execjs 在干净上下文里从 `g5` 入口开始求值，第一次真正用到未定义标识符时才抛错；因此“报什么补什么”，反复运行即可沿调用链把依赖逐个补齐，比人工通读整个打包文件高效。
- **页面为什么调用两次 `g5`**：页面 `_e` 里先 `sign: M({username})` 生成一次签名并写入请求对象，随后请求对象又带上 `ver`、`mt` 再整体发送，因此页面上出现两次调用。但 `g5` 的键黑名单包含 `sign`，第二次调用时上一次的 `sign` 会在字典序排序前被 `delete`，实际参与计算的只有 `{username, ver, mt}`；所以两次调用只是忠实复刻页面流程，并非算法必需，单次用 `{username, ver, mt}` 调用可得到相同最终 sign。
- **验证闭环**：把生成的 sign 填入原始请求，同时修改 `ver`/`mt`/`username`；若服务端从“签名错误”变为业务错误（如“账号不存在”），说明签名已通过校验，逆向成功。

## 触发条件

- 目标 Web 应用的签名逻辑在前端 JS 中可读/可调试，签名函数可被 DevTools 断点捕获并扣出。
- 攻击者能使用 Python `execjs`（或 Node）在本地执行 JS，且 JS 不含强环境绑定（如必须依赖浏览器 DOM 的代码——本例只有 crypto polyfill，可在 Node 中降级运行）。
- 签名算法只依赖前端固定盐/常量，服务端用同一算法重算比对；没有 nonce、时间窗、一次性 token 或服务端密钥参与的 HMAC。
- 服务端错误信息可区分“签名错误”和业务错误，便于验证；接口未做严格频率限制。

## 利用步骤

1. 抓包确认参数：请求含 `ver`、`mt`、`username`、`sign`；改动任意一个都会返回“签名错误”，说明 `sign` 由三者共同生成。
2. 先试 XHR 断点（URL 包含 `/api/member/getMobile`）；若断在 `l.send(r)` 时 `sign` 已生成，改用请求的 Initiator/调用栈，找到可疑组件（如 `LoginForm`）与 `sign: M({...})` 行。
3. 在 `sign:` 处下断点，单步进入 `g5`；观察第一次调用参数只有 `username`，继续“跳过下一个函数调用”可看到第二次调用参数包含 `username`、`sign`、`ver`、`mt`，确认同一函数被调用两次且生成值就是最终请求的 `sign`。
4. 把 `g5` 复制到 `sign.js`，用 `execjs.compile()` 调用；按报错依次搜索并补齐依赖：`IQ is not defined` → 搜 `IQ(`/`IQ =` 补 MD5 工厂；`TQ is not defined` → 搜 `TQ(`/`TQ =` 补 crypto polyfill（连同其 `{exports:{}}` 模块壳）。
5. Python 中复刻页面调用（第二次传入的 `sign` 会被黑名单剔除，可省略）：先 `{"username": i}` 调用得 `enc1`，再 `{"username": i, "ver": ver, "mt": mt}`（或连同 `sign: enc1`）调用得最终 sign；直接单次传 `{username, ver, mt}` 亦等价。
6. 用最终 sign 发请求验证；注意 Python 里的 `ver`、`mt` 必须与请求包一致（`mt` 通常是毫秒时间戳），签名对参数值敏感。

## PoC

```python
import execjs

with open('sign.js', 'r', encoding='utf-8') as f:
    jscode = f.read()

ctx = execjs.compile(jscode)
mt  = '1712311751166'   # 与请求包保持一致
ver = '2.0'
i   = 'test'

e = {"username": i}
enc1 = ctx.call('g5', e)                       # 第一次：仅 username（复刻页面）
e = {"username": i, "sign": enc1, "ver": ver, "mt": mt}
enc2 = ctx.call('g5', e)                       # 第二次：sign 在黑名单中会被 delete，不参与计算
print(enc2)                                    # 32 位大写 MD5 签名
```

`sign.js` 中的 `g5` 结构（按原文调试结果还原）：

```javascript
function g5(e) {
  const t = JSON.parse(JSON.stringify(e));
  for (const r in t) {
    if (["coLicensePic","cardPic1","cardPic2","cardPic3","reject_reason","sign"].includes(r) ||
        (typeof t[r] !== "string" && typeof t[r] !== "number")) {
      delete t[r];
    }
  }
  const n = Object.keys(t).sort((a, b) => a < b ? -1 : 1);
  let o = "";
  n.forEach(k => { o += `${k}=>${t[k]}@`; });
  o = o.substring(0, o.length - 1);
  o = IQ(o).toString();
  o += "^_*#06@!@6#_^";
  o = IQ(o).toString().toUpperCase();
  return o;
}
```

`IQ`/`TQ` 需按报错从原 JS 文件中原样扣出；上式黑名单与盐值来自该目标案例，换目标需重新调试。

## 变体与关联

- `web-generic-auth-js-signature-jsrpc-autodecoder`：同样是“排序参数 + 固定密钥 + MD5”的签名逆向，但走 JSRPC/autoDecoder 运行时动态代签，不需要静态扣码；本卡是静态扣码 + 依赖补齐路线。
- `code-analysis-reverse-frontend-request-response-encryption-automation`：给出 XHR/fetch 断点 → Initiator/调用栈 → 扣 JS → PyExecJS 的通用流程；本卡聚焦该流程中“断点晚于签名生成”与“ReferenceError 驱动的依赖补齐 + 两次调用”的具体操作。
- `tools-burp-burpcrypto-execjs-webpack-md5-function-extract-sign`：面向 webpack/ESM 产物按 import 别名定位导出函数；本卡面向经典 CryptoJS 全局工厂（`IQ`/`TQ`）的扣取。
- 其他前端加密逆向卡（AES/RSA/JWT 等）见 `code-analysis/reverse/obfuscation` 同层；移动端同类“排序+盐+MD5 大写”签名见 `mobile-android-sign-treemap-salts-both-ends-md5-uppercase`。

## 检测与防御

- 服务端不要把前端固定盐当秘密：签名应由服务端下发的 nonce/一次性 token + 时间窗 + HMAC（服务端密钥）组成，签名与请求一次性绑定，重放/改写参数即失效。
- 对同一账号/会话的签名请求做频率限制与参数枚举检测（大量不同 `username` 使用同一签名算法重签）。
- 前端代码混淆只能提高逆向成本，不能替代服务端校验；不要把完整用户数据查询接口仅靠 sign 保护。
- 蓝队排查：短时间大量 `sign` 合法但业务参数变化的请求、来自脚本化客户端的固定 UA/请求头组合、以及 `ver`/`mt` 与服务端时间明显不一致的请求。

---
id: tools-burp-burpcrypto-execjs-webpack-md5-function-extract-sign
title: BurpCrypto ExecJs 搭配 webpack/ESM 产物抠取 md5 函数：按 import 别名定位 export 真名，逐请求重算签名并整体构造请求体
type: scenario
domain: tools
path: tools/burp
technique: burpcrypto-execjs-webpack-hash-function-extract
aliases:
- BurpCrypto Exec Js
- webpack md5 函数抠取
- import 别名 export 真名
- JS 加密函数提取复用
- 签名请求体自动构造
- ts 每次请求现取
tags:
- tools
- burp
- burpcrypto
- execjs
- webpack
- esm
- md5
- signature
- javascript
- intruder
- tooling
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V452
  verified_at: '2026-11-10T01:54:30+08:00'
  notes: 已对照原文与 17 张截图核对：import {m as oe}、export {md5 as m}、删除 export 行后 Console md5('123')=202cb962...、BurpCrypto ExecJs 与 Intruder 批量成功均有截图；次要问题：Console 示例 md5(salt+1712889931755+phone+1234) 与截图成功请求实际 ts=1712889983175 不符（示例值偏差，不影响手法），且原截图中 const o 在函数外、卡片建议函数内现取更稳妥；未被验证点：未在目标环境复跑
---

# 一句话结论

当前端使用 webpack/ESM 打包的加密库（如 js-md5）对参数签名时，先在业务 chunk 搜索签名参数名定位调用行，按 `import {m as oe} from "./md5-xxxx.js"` 找到别名、再到被引用 chunk 的 `export {md5 as m}` 确认真名；美化后删除 `export` 行即可把纯函数粘贴进 BurpCrypto 的 Exec Js 处理器（或浏览器 Console），由脚本对每个请求现取时间戳、重算签名并返回完整请求体，实现改包/Intruder 爆破时的自动代签。

# 原理

- **webpack/ESM 产物中导出名与本地别名分离**：库 chunk 末尾写 `export {md5 as m}`，业务 chunk 写 `import {m as oe} from "./md5-bfdebcc6.js"`，调用点只用压缩后的别名 `oe(...)`。因此直接在业务 chunk 搜函数本名可能 0 匹配，但搜参数名或别名可以定位调用行，再沿 import 语句找到库 chunk，即可确认真实函数名。
- **纯函数可直接抠出复用**：js-md5 这类库无外部依赖、纯计算，整段复制即可在任意 JS 引擎运行；不需要重写算法，避免复刻出错。
- **ESM 语法限制**：`export {md5 as m};` 出现在非模块顶层环境（DevTools Console、BurpCrypto 的 JS 引擎）会报 `SyntaxError: export declarations may only appear at top level of a module`，删除该行（或改为普通赋值）后函数即可调用。
- **动态材料必须在脚本内经时取**：签名常含时间戳/nonce，服务端有时间窗口校验（案例先报“签名错误”，签名修好后又报“时间戳过期”），若把 ts 写成常量，批量请求会全部过期；正确做法是在生成函数内每次 `new Date().getTime()`，保证同一个请求体内的 ts 与参与签名的 ts 完全一致。
- **BurpCrypto Exec Js 的工作方式**：在插件“Exec Js”页粘贴抠出的库代码与业务包装函数，设定方法名（如 `ens_md5`）；处理器把 Intruder/Repeater 选中的 payload 作为入参调用该函数，用返回值整体替换请求体/参数值，因此每个请求都能得到新的合法签名，无需人工回填。

# 触发条件

- 前端加密/签名逻辑在可下载 JS 中，且为纯 JS 可复算（无原生代码、无服务端私钥参与）。
- 算法依赖的常量（salt/key/固定前缀）硬编码在 JS 中。
- 签名材料包含时间戳/nonce，需在脚本中动态生成。
- 使用 Burp + BurpCrypto（Exec Js 处理器）；也可用浏览器 Console、PyExecJS、JSRPC 等替代载体。

# 利用步骤

1. 抓包记录待伪造字段（如 `key`、`sign`、`ts`）及所在请求体结构，确认签名覆盖哪些字段。
2. DevTools Sources 全局搜索签名参数名（如 `verifyCode`），定位业务 chunk 中的计算行：`key = oe("hardcodedSalt" + o + phone + b)`、`ts: o`。
3. 在该行下断点并触发请求，单步步入 `oe`；若进入 `md5-*.js`，说明别名指向该库。回到业务 chunk 搜索 `import`，找到 `import {m as oe} from "./md5-*.js"`；到库 chunk 搜索 `export`，确认 `export {md5 as m}`（即 oe 的真身为 md5）。
4. 美化库 chunk，删除末尾 `export {md5 as m};` 行，全选复制到浏览器 Console；执行 `md5('123')`，结果应为 `202cb962ac59075b964b07152d234b70`，确认抠取成功。
5. 在 BurpCrypto 的 Exec Js 中粘贴库代码，追加业务包装函数（方法名 `ens_md5`）：函数内现取时间戳，按原公式计算 `key`，并返回完整 JSON 请求体；注意时间戳变量必须在函数体内生成，保证每个请求的 `ts` 与签名一致。
6. 在 Repeater/Intruder 中选中手机号字段，调用 BurpCrypto 处理器生成新请求体，确认服务端返回成功；随后挂到 Intruder 上批量运行，验证无独立频控。

# PoC

```js
// 粘贴在 BurpCrypto Exec Js：前半部分为从目标 webpack 库 chunk 抠出的 js-md5（已删除 export 行）
var md5 = /* ... js-md5 完整代码 ... */;

function ens_md5(word) {
  var ts = new Date().getTime();            // 每次调用现取，避免时间戳过期
  var key = md5("Aw@XcsjiwWD" + ts + word + 1234);
  return '{"phone":"' + word + '","key":"' + key +
         '","ts":' + ts + ',"verifyCode":"1234","productId":""}';
}
```

```js
// 浏览器 Console 快速验证签名算法（库已抠出）
md5("Aw@XcsjiwWD" + 1712889931755 + "18512341234" + "1234")
// 与抓包的 key 比对一致即说明算法复刻正确
```

# 变体与关联

- **变体**：CryptoJS、jssha 等其他库同样可整段抠取；函数依赖多个子模块时按 import 链顺序拼接代码；也可不抠函数，改用 JSRPC/autoDecoder 在运行时直接调用原站函数，或用 SignMe 规则只重算个别字段。
- **识别信号**：压缩产物中 `export {x as y}` 与 `import {y as z}` 成对出现；业务 chunk 搜函数本名无结果但搜别名/参数名可命中；Console 粘贴报 `export declarations may only appear at top level of a module`。
- **关联**：[[tools-burp-signme-graalvm-js-rule-hash-sign-replay]]（插件规则式重算字段签名，不抠原函数）；[[web-generic-auth-js-signature-jsrpc-autodecoder]]（JSRPC 运行时代签）；[[pentest-recon-vue-webpack-module-export-alias-api-params]]（webpack 模块/导出别名追踪定位参数）；[[code-analysis-reverse-frontend-request-response-encryption-automation]]（PyExecJS 自动化复算）；[[web-generic-auth-client-generated-captcha-md5-key-signature-forge]]（本手法的验证码绕过实战场景）。

# 检测与防御

- 服务端不应把安全校验建立在客户端可复算的哈希上：关键签名需引入服务端私钥或动态挑战（challenge/nonce 由服务端签发并一次性使用）。
- 对签名接口实施服务端风控与频控（账号、设备、IP、业务对象多维），限制批量枚举与重放。
- 检测特征：同一客户端短时间大量请求且签名始终合法；请求携带的 ts/nonce 与业务参数同步变化；自动化工具流量特征。
- 隐藏 JS、混淆加密逻辑只能提高逆向成本，不能替代服务端校验；前端代码公开可下载时须假定攻击者已掌握全部算法与常量。

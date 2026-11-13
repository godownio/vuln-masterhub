---
id: code-analysis-reverse-obfuscation-webpack-runtime-module-loader-extract
title: webpack 运行时 loader 抠取与“缺啥补啥”：把打包站点中的加密函数离线复现
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: webpack-runtime-module-loader-extract-execjs
aliases:
- webpack 抠代码
- webpack 模块装载器提取
- test_module 抠取法
- 缺啥补啥 JS 抠取
- webpackJsonp 模块定位
- 前端加密函数离线复现
tags:
- javascript
- webpack
- reverse
- execjs
- deobfuscation
- module-loader
- crypto
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V557
  verified_at: '2026-11-12T00:35:51+08:00'
  notes: 已对照原文与15张截图核对：图09/13 的 webpack 运行时 IIFE（u 缓存、f(c) require、e[c].call(n.exports,n,n.exports,f)、f.e chunk 映射）与卡片装载器代码一致；入口在索引页面搜索 call 定位、导出 test_module、console.log(c) 观察模块 id（图13 红框）、模块 4b2a 导出 sm2/sm3/sm4、7c74 为 sm-crypto（图03/11/12）、i("d3b7") 无返回值可注释、h=i("7c74") 必须保留、调用 test_module("7a74").encrypt(t,e,{mode:'cbc',iv:i}) 与原文一致；图14 Burp 上游代理 9090、图15 明文请求/响应验证工程化成立。卡片为方法卡，webpack4/webpackJsonp 表述属对观察结构的合理概括。dedup 首候选为自身，其余 webpack API 提取/模块别名等候选为不同目标（端点/别名），工具卡 BurpCrypto 为不同提取方法，非同链；本卡与同篇 d1d2d3 信封卡为『方法↔应用』关系而非重复。保留。未执行 PoC。
---

## 一句话结论

对于 webpack 打包（尤其带 `webpackJsonp`/模块 id 映射）的站点，与其逐个函数硬抠，不如把 HTML 里的 webpack **运行时模块装载器**整体抠出来、导出为 `test_module`，再把加密逻辑依赖的模块函数按 `moduleId: function(module, exports, require){...}` 形式贴进模块表；运行时给装载器加 `console.log(moduleId)` 或直接调用触发 `ReferenceError`，按报错「缺啥补啥」，即可在 Node/PyExecJS 中离线调用页面原生的加密/解密函数。

## 原理

- webpack 4 时代的产物结构：一个 IIFE 定义模块缓存 `u` 与 require 函数 `f(c)`：
  ```js
  (function (e) {
      var u = {};
      function f(c) {
          if (u[c]) return u[c].exports;
          var n = u[c] = { i: c, l: !1, exports: {} };
          return e[c].call(n.exports, n, n.exports, f), n.l = !0, n.exports;
      }
      test_module = f;   // 人为导出，便于外部调用
  })({ /* moduleId: function(t,e,i){...} */ });
  ```
  外部用 `test_module("<moduleId>")` 即可取到该模块的 `exports`。
- 为什么整段移植可行：模块函数通过参数拿到 `module/exports/require`，不依赖打包器的其他运行时状态；只要把被依赖的模块一并贴进模块表，装载器就能按 id 解析，效果与页面里一致。
- 定位入口：在主 HTML 中搜索 `call`/`.call(`/`webpackJsonp`，找到装载器 IIFE；打包器生成的入口通常在 `<script>` 内联或首个 chunk 里。
- 定位目标模块：在浏览器里给加密函数下断点，从调用栈或 `webpackJsonp.push([[chunkId], {moduleId: function...}])` 的注册处拿到 chunk/module id；也可在执行装载器时打印 `console.log(c)` 观察运行时请求了哪些模块。
- “缺啥补啥”：
  - 运行本地脚本，`ReferenceError: X is not defined` 就说明缺模块/缺全局变量，回到原始 JS 搜索 `X(` 或 `X =`，把对应模块函数贴入；
  - `i("d3b7")` 这类只调用、不接收返回值的 require 多为副作用模块（polyfill/样式），可直接注释掉；
  - `h = i("7c74")` 这类有赋值的必须保留，否则后续 `h.encrypt` 为空；
  - 依赖库（如 sm-crypto/CryptoJS）整段复制比手写等价实现更可靠，避免填充/编码细节不一致。
- 调用形态：拿到模块后包一层业务函数，如
  ```js
  function test_enc(t, e, i) {
      var test = test_module("7a74");
      return test.encrypt(t, e, { mode: 'cbc', iv: i });
  }
  ```
  再用 PyExecJS `ctx.call("test_enc", plaintext, key, iv)` 调用。
- 为什么比逐函数抠更稳：保留原库实现与模块间依赖关系，避免“算法都对但填充/前缀/编码不同导致密文对不上”的常见问题；代价是需要把依赖闭包补全。

## 触发条件

- 目标前端使用 webpack（含 webpackJsonp 或 IIFE 模块表）；加密/签名函数是纯 JS、可在本地复算。
- 能获取页面 JS（浏览器缓存/DevTools Sources/直接下载）。
- 本地具备 Node 或 PyExecJS 运行环境；允许调试页面以取得模块 id 与参数。

## 利用步骤

1. 在 Sources 中搜索 `d1:`、`encrypt`、`sign` 等业务特征，断点定位加密调用与所属模块 id。
2. 从主页面/入口 chunk 抠出 webpack 运行时装载器，导出 `test_module`；给 `f(c)` 加 `console.log(c)` 观察模块请求顺序。
3. 把加密函数所在模块按原 `moduleId: function(t,e,i){...}` 形式贴入模块表；运行并观察报错。
4. 按 `ReferenceError`/`undefined` 逐个补齐依赖模块（sm-crypto、CryptoJS、工具函数等）；无返回值的副作用 require 可注释。
5. 在本地调用目标模块的导出方法，用浏览器中取得的同一组明文/密钥/IV 对比密文，确认完全一致。
6. 将包装函数接入 execjs/mitmdump/Burp 处理器，对每个请求现算密文或签名（时间戳/nonce 需函数内实时生成）。

## PoC

```javascript
// test.js：webpack 运行时 + 目标模块（节选）
var test_module;
(function (e) {
    var u = {};
    function f(c) {
        if (u[c]) return u[c].exports;
        var n = u[c] = { i: c, l: !1, exports: {} };
        // console.log(c);  // 调试：观察被请求的模块 id
        return e[c].call(n.exports, n, n.exports, f), n.l = !0, n.exports;
    }
    test_module = f;
})({
    "7c74": function (t, e, i) { /* sm-crypto：sm2/sm3/sm4 实现（从页面原样复制） */ },
    "4b2a": function (t, e, i) { /* 加密封装模块（从页面原样复制） */ },
    // "d3b7": function (t, e, i) { ... }  // 无返回值的副作用模块可注释
});

function test_enc(t, e, i) {
    var test = test_module("7a74");   // 业务模块 id 以实际调试为准
    return test.encrypt(t, e, { mode: 'cbc', iv: i });
}
```

```python
import execjs
ctx = execjs.compile(open('test.js', encoding='utf-8').read())
cipher = ctx.call('test_enc', plaintext, key, iv)
# 与浏览器同参数生成的密文逐字节比对，一致后再接入代理
```

## 变体与关联

- 变体：webpack 5 使用 `__webpack_require__` 与 chunk 加载器，思路相同——移植 require 运行时与模块表，按 chunk 映射补模块。
- 变体：Vite/Rollup 产物不是模块表结构，直接按 ESM import 链提取（见 [[tools-burp-burpcrypto-execjs-webpack-md5-function-extract-sign]]）。
- 关联：[[code-analysis-reverse-frontend-request-response-encryption-automation]]（断点定位与本地复现的通用流程）；[[code-analysis-reverse-obfuscation-js-sign-execjs-dependency-patch]]（execjs 下按报错补依赖的另一实例）。
- 关联：[[code-analysis-reverse-obfuscation-frontend-d1d2d3-sm4-sm2-envelope]]（本文用该方法抠出 sm-crypto 与 d1/d2/d3 封装函数）。
- 边界：模块表可能引用打包器内部变量（如 `i.p`、`i.n`），需一并补齐或替换；代码量大时可用 AST 抽取目标模块及其依赖闭包。

## 检测与防御

- 认知：前端打包/压缩只是提高阅读成本，不保护密钥与算法；任何在浏览器执行的加密都可被完整复现。
- 防御：敏感逻辑放服务端；前端加密仅用于传输层配合 TLS，不作为鉴权/防篡改依据；对批量自动化行为做风控与限速。
- 检测：针对接口的密文重复度、请求频率、客户端指纹异常做检测；服务端校验时间戳/nonce 与一次性签名，降低重放和批量利用空间。

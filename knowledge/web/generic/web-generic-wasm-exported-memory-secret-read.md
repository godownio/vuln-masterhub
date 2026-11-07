---
id: web-generic-wasm-exported-memory-secret-read
title: Wasm 导出线性内存中的密钥与敏感常量可被同源 JS 读取
type: scenario
domain: web
path: web/generic
technique: wasm-exported-memory-secret-read
aliases:
- Wasm 内存取密钥
- WebAssembly.Memory 读取
- wasm2wat data 段
- 前端 Wasm 密钥泄露
- 线性内存敏感数据提取
tags:
- web
- wasm
- webassembly
- client-side
- memory
- secret
- key-extraction
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:06:54+08:00'
  notes: 已对照原文核对 wasm2wat data 段、导出 memory 的 Uint8Array 视图与常量密钥提取；已确认原文“沙箱逃逸/函数表劫持”链不成立并被作者排除；未验证点：未在本机编译/执行，卡片明确限定为同源 JS 前提下的客户端密钥提取
---

## 一句话结论

当 Wasm 模块导出了 `memory`（或宿主为它传入可访问的 `WebAssembly.Memory`），且把 AES 密钥、API Secret 等常量存放在线性内存中时，同源 JS 可直接创建 `Uint8Array` 视图读取整段内存，配合 `wasm2wat` 定位 data 段偏移即可提取密钥；这不是沙箱逃逸，而是前端秘密无法对已执行 JS 的客户端保密。

## 原理

- Wasm 的线性内存是一段连续的、可从 JS 侧以 `ArrayBuffer` 访问的字节数组。模块若在导出表中暴露 `memory`（Emscripten 常导出 `instance.exports.memory`），JS 可以 `new Uint8Array(memory.buffer)` 得到覆盖全部内存的读写视图。
- C 源码中的 `const uint8_t aes_key[16] = {...}` 等静态常量会被编译进 Wasm 的 data 段，在实例化时被复制到线性内存的固定偏移；编译不会加密这些常量，它们以明文存在于内存中。
- 用 `wasm2wat module.wasm` 可以把二进制还原为文本格式，data 段形如 `(data (i32.const 4096) "\00\01...")`，其中的常量值就是密钥；`i32.const` 的值即线性内存偏移。即使看不到源码，也能从 `.wat` 恢复。
- 知道偏移后，`memoryView.slice(offset, offset + 16)` 即可取出 AES-128 密钥；也可以扫描内存中的高熵字节或已知明文特征来定位。
- 边界：如果模块既不导出 memory，宿主也没有把 memory 对象暴露给当前 JS，则 JS 无法直接访问；但 Emscripten 默认胶水代码通常会暴露它。该手法只能读取 Wasm 自身可见的内存，不能读取浏览器进程其他内存或突破同源策略。

## 触发条件

- Wasm 模块导出 `memory`，或页面 JS 自己创建 `WebAssembly.Memory` 并作为 import 传入（此时页面本就持有该对象）。
- 模块把敏感常量（密钥、盐、API Token）存放在线性内存的 data 段或全局变量中。
- 攻击者能在同源页面执行 JS（XSS、被篡改的第三方脚本、恶意浏览器扩展等），且能获取模块实例或 `memory` 对象。
- 密钥在客户端被实际使用（例如前端加密、签名），而不是仅由服务端持有。

## 利用步骤

1. 获取目标 `.wasm` 文件（页面网络请求、缓存、打包产物），运行 `wasm2wat` 转为 `.wat`。
2. 在 `.wat` 中搜索 `(data (`、`aes`、`key`、长十六进制/字符串常量，记录 `i32.const` 偏移与数据长度。
3. 在页面上下文中获取模块实例的 `memory`：`instance.exports.memory`，或从页面的 import 对象中取宿主传入的 memory。
4. 创建 `Uint8Array(memory.buffer)`，按偏移 `slice` 出目标字节。
5. 若偏移未知，可全内存扫描高熵区间、已知明文头（如 PEM、JSON、密钥前缀）或与加密输出做已知明文比对定位。
6. 用提取出的密钥解密前端加密数据、伪造签名，或进一步分析协议。

## PoC

```c
/* encrypt.c：密钥作为静态常量存于 Wasm 线性内存 */
#include <stdint.h>
#include <string.h>

const uint8_t aes_key[16] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};
static uint8_t out[1024];

__attribute__((visibility("default")))
uint8_t* encrypt_data(uint8_t* input, int len) {
    for (int i = 0; i < len; i++) out[i] = input[i] ^ aes_key[i % 16];
    return out;
}
```

```bash
emcc encrypt.c -s EXPORTED_FUNCTIONS='["_encrypt_data"]' \
  -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' -o encrypt.js
wasm2wat encrypt.wasm > encrypt.wat
# 在 encrypt.wat 中搜索 data 段，例如：
# (data (i32.const 4096) "\01\23\45\67\89\ab\cd\ef\fe\dc\ba\98\76\54\32\10")
# 4096 = 0x1000 仅为示例，实际偏移以 wat 为准
```

```javascript
async function stealWasmKey() {
    const bytes = await (await fetch('encrypt.wasm')).arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes);

    // 只有模块导出 memory 时可直接访问；Emscripten 胶水通常可用
    const memory = instance.exports.memory;
    const view = new Uint8Array(memory.buffer);

    // 偏移从 wasm2wat 的 data 段读取，不要写死 0x1000
    const keyOffset = 0x1000;
    const key = view.slice(keyOffset, keyOffset + 16);
    const hex = Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('extracted key:', hex);
}
```

## 变体与关联

- 变体：若模块只暴露加密函数而不导出 memory，可 hook `WebAssembly.instantiate`/`instantiateStreaming` 在实例化前拿到 `memory` 或 import 对象；也可包装宿主传入的 memory。
- 变体：不依赖已知偏移，直接扫描整段内存的高熵 16/32 字节块，或用已知明文（如 `{"`、`-----BEGIN`）定位。
- 变体：同样的思路适用于 Emscripten 的 `Module.HEAPU8`、`Module.wasmMemory` 等全局对象。
- 关联：[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]（前端 AES 参数还原与密钥提取的 JS 侧方法）。
- 边界：这不是浏览器沙箱逃逸，也不能读取跨源数据；它是“前端秘密对客户端不可保密”的具体体现。服务端签名/加密的密钥若只存在于服务端，则本手法无效。

## 检测与防御

- 修复：不要把长期有效的密钥、API Secret 放在前端 Wasm/JS 中；加密与签名移到服务端，或使用 WebCrypto 的不可导出（non-extractable）密钥与服务端会话绑定。
- 加固：前端密钥仅作为短期、低权限、可轮换的会话材料；使用 CSP、Trusted Types、SRI 降低 XSS 与第三方脚本篡改风险。
- 检测：审计 `.wasm` 的 data 段与 `Module.HEAP*` 使用，确认是否存在硬编码秘密；监控异常的全内存读取/高熵扫描行为（前端检测能力有限，主要靠代码审计）。
- 说明：内存清零、字符串混淆只能提高分析成本，无法阻止已执行 JS 在清零前读取；不要将其视为安全边界。

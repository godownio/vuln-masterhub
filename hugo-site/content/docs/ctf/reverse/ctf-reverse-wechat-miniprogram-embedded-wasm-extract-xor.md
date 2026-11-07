---
id: ctf-reverse-wechat-miniprogram-embedded-wasm-extract-xor
title: 微信小程序包内嵌 WASM 段提取：按 00 61 73 6D 魔数 dump，IDA 9 解析后 XOR 0x99 解出 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: miniprogram-embedded-wasm-extract-xor
tags:
- ctf
- reverse
- wasm
- miniprogram
- webassembly
- xor
- ida
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V238
  verified_at: '2026-11-07T09:10:21+08:00'
  notes: 已对照原文与图 28-31 核对：包内 0061736D 区段 dump 为 wasm、IDA 9 解析、逻辑为 i32.load8_u ^ 0x99 与目标比较；已按原文 IDA data 段与 CyberChef 输入修正 PoC 密文十六进制（38 字节），XOR 0x99 复算得到 flag{fae0b27c451c728867a567e8c1bb4e53}。
url: /docs/ctf/reverse/ctf-reverse-wechat-miniprogram-embedded-wasm-extract-xor/
draft: false
kb_aliases:
- 小程序 wasm 逆向
- 0061736D
- wasm 魔数提取
- IDA 9 wasm
- XOR 0x99
- WeChat mini program reverse
---

## 一句话结论

微信小程序包中若有一段以 `00 61 73 6D`（`\0asm`）开头的二进制区段，把它从魔数处 dump 出来另存为 `.wasm`，IDA 9.0 可直接解析；本题的校验逻辑是对每个字节与 `0x99` 异或后比较，因此对密文逐字节 XOR `0x99` 即可还原 `flag{fae0b27c451c728867a567e8c1bb4e53}`。

## 原理

- **WASM 魔数**：WebAssembly 二进制以 4 字节魔数 `\0asm`（十六进制 `00 61 73 6D`）开头，紧跟 4 字节版本号（通常 `01 00 00 00`）。在小程序包/JS bundle 中，WASM 可能被整段嵌入或经简单封装，但魔数通常保留，可作为定位锚点。
- **为什么能直接 dump**：WASM 是自描述的长度前缀格式；只要从魔数开始截取到模块结束（或先截到文件末尾），IDA 9.0 的 WASM loader 就能解析类型、函数、代码段和线性内存。即使前后有壳/包装数据，从魔数处开始的字节仍是合法模块。
- **校验逻辑**：反编译可见循环读取线性内存中的输入/密文字节（`i32.load8_u`），与 `0x99` 做 `i32.xor`，再与目标值比较或作为输出。XOR 是自逆运算，加密与解密是同一操作；因此对密文逐字节 XOR `0x99` 即得明文。
- **密文定位**：IDA 中在 data 段可见一串 `0xFF,0xF5,0xF8,0xFE,...` 的字节；`0xFF^0x99=0x66('f')`、`0xF5^0x99=0x6C('l')`、`0xF8^0x99=0x61('a')`、`0xFE^0x99=0x67('g')`，开头即可确认是 flag 的 XOR 密文。
- **为什么这条链成立**：客户端校验必须把目标/密钥放在本地，WASM 只是把逻辑换成字节码，无法隐藏常量；XOR 单字节密钥可被已知明文（`flag{`）直接推出。

## 触发条件

- 拿到微信小程序包（`.wxapkg` 或已解包目录），其中某个文件包含 `00 61 73 6D` 开头的区段。
- 有 IDA 9.0+（支持 WASM）或 wasm2wat/wasm-decompile 等工具；能定位并截取 WASM 模块。
- 校验逻辑使用固定单字节 XOR/简单可逆变换，密文在模块 data 段或线性内存中可见。
- 已知明文前缀（如 `flag{`）可用于确认密钥/变换。

## 利用步骤

1. 解包小程序（`wxapkg` 解包工具或直接在小程序缓存目录找文件），对每个文件扫描 `00 61 73 6D`。
2. 从魔数偏移开始 dump 到模块结束（可先 dump 到文件末尾，再用 IDA/wasm 工具验证），保存为 `chunk.wasm`。
3. 用 IDA 9.0 打开 `chunk.wasm`，查看导出函数、`i32.load8_u`/`i32.xor`/`i32.eq` 等指令，定位校验循环与 data 段密文。
4. 提取密文字节，逐字节与 `0x99` 异或；用 `flag{` 前缀验证密钥。
5. 得到 flag；若逻辑是“输入 XOR 0x99 后与密文比较”，则直接把密文 XOR 0x99 作为正确输入。

## PoC

```python
# 1) 在解包后的小程序文件中定位并 dump WASM
data = open('app.wxapkg', 'rb').read()
off = data.find(b'\x00asm')
assert off != -1
open('chunk.wasm', 'wb').write(data[off:])

# 2) XOR 0x99 还原密文（字节来自 IDA data 段）
ct = bytes.fromhex(
    'fff5f8fee2fff8fca9fbabaefaadaca8faaeab'
    'a1a1afaef8acafaefca1faa8fbfbadfcacaae4'
)
print(bytes(b ^ 0x99 for b in ct))
# b'flag{fae0b27c451c728867a567e8c1bb4e53}'
```

原文在 IDA 中确认逻辑为 XOR `0x99` 后，用 CyberChef 的 XOR 操作解出同一 flag。上例十六进制取自原文 IDA data 段与 CyberChef 输入（38 字节），可直接 XOR 0x99 得到 flag。

## 变体与关联

- **WASM 被 Base64/数组封装**：先在 JS 中找 `base64`、`Uint8Array`、`WebAssembly.instantiate`，解码后再扫描 `00 61 73 6D`。
- **多字节密钥/滚动 XOR**：用 `flag{` 已知明文推出前几字节密钥，再根据重复周期或 PRNG 扩展。
- **校验逻辑在 JS 而不是 WASM**：WASM 只做辅助计算；应同时检查 `app-service.js`/`app.js` 中的调用与常量。
- 关联：[[ctf-reverse-wasm-login-fnv1a-feistel-xorshift-keystream]]（WASM 登录校验 + 密钥流）、[[ctf-reverse-wasm-login-date-now-timestamp-bruteforce]]（WASM 时间校验）、[[web-generic-wasm-exported-memory-secret-read]]（WASM 线性内存读密钥）。

## 检测与防御

- **客户端不可信**：小程序/WASM 只是分发形式，密钥、目标值与校验逻辑都在客户端；敏感判定必须放到服务端，客户端只做体验优化。
- **混淆不等于保护**：XOR/常量表/控制流混淆可被已知明文和动态调试还原；不要把 flag、密钥或授权判定硬编码在包内。
- **检测**：小程序包中出现 `00 61 73 6D` 嵌入段、异常大的二进制 blob、`i32.xor` 固定常量循环、data 段高熵字节串，都是可疑特征。

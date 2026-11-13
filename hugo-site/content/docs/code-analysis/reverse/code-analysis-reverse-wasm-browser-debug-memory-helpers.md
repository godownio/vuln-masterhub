---
id: code-analysis-reverse-wasm-browser-debug-memory-helpers
title: WebAssembly 逆向双路径：wabt/IDA/JEB 静态反编译 + 浏览器 devtools 调 wat 并注入内存辅助函数
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: wasm-static-dynamic-reverse-workflow
tags:
- wasm
- webassembly
- reverse
- ctf
- wabt
- ida
- jeb
- devtools
- memory
- go
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V535
  verified_at: '2026-11-11T17:45:30+08:00'
  notes: '已对照原文全文与21张截图(img_small)核对：图01 010Editor output.wasm魔数与Data段字符串(syscall/js.*等)；图02/03 wat2wasm在线工具simple与三参数add；图04 wasm2c生成hello.c/hello.h；图05/06/07 JEB wasmbc加载output.wasm、函数列表与反编译，伴随Instruction cannot be converted报错；图08 Network面板Wasm过滤；图09 Settings-Experiments勾选WebAssembly Debugging: Enable DWARF support；图10 Sources以wat展示$resume.command_export；图11 $global2值为78060；图12 Scope中memories/$memory.buffer；图13 Console memories[0].buffer.slice(78060, 78060+16)；图14 viewChar(78060,78060+16)返回原始字节串(原文即如此调用，viewChar第二参数为size，故返回长串，卡内忠实记录)；图15 加解密示例页明文dsasa；图16 Overrides本地替换index.html注入辅助函数与WebSocket reload；图17 断点于call $Crypto/aes.NewCipher；图18 hover $var1=144768且viewChar(144768)=''newstarTrealstar''；图19 IDA加载output.o(w2c_*函数、Input SHA256)；图20/21 strings中crypto/aes、cipher.cbcEncrypter、cbcDecrypter等。卡中静态/动态双路径、工具命令、$global偏移、辅助函数与AES key实例均与原文/截图一致；IDA getKey的v4^0x0A与原文代码块一致。原文未涉及组件版本，未设affected_versions正确。dedup候选为具体wasm题(FNV/Feistel、Date.now签名)、wasm导出内存读密钥、堆快照搜flag等具体技巧，本卡为通用逆向方法论，非同链；dup-scan无涉及pair。卡片主题单一、原子，保留verified。未运行wasm或浏览器调试。'
url: /docs/code-analysis/reverse/code-analysis-reverse-wasm-browser-debug-memory-helpers/
draft: false
kb_aliases:
- wasm 逆向
- WebAssembly 逆向手法
- wat 调试
- wasm2c IDA 分析
- 浏览器 wasm 断点
- wasm 内存辅助函数
- viewChar viewString search
- Go wasm AES key
---

## 一句话结论

CTF 中的 wasm 题可以走两条互补路径：静态上用 010 Editor 看二进制段与字符串、用 wabt `wasm2c` 把 wasm 转成 C 再编译成 `.o` 交给 IDA/JEB 反编译（可直接看到 Go/Rust 导出的函数与 AES 等算法符号）；动态上在浏览器 devtools 打开 WebAssembly DWARF 调试，把 `.wasm` 以 wat 形式下断点单步，并通过本地替换页面脚本注入 `viewChar`/`viewString`/`search` 等内存辅助函数，按指针 dump 出运行时字符串与密钥（示例从 Go wasm 的 AES 流程中读出 16 字节 key `newstarTrealstar`，并用 IDA 里 `v4 ^ 0x0A` 的 getKey 逻辑还原密钥）。

## 原理

- **wasm 二进制结构**：文件以魔数 `00 61 73 6D`（`\0asm`）和版本号 `01 00 00 00` 开头，之后是若干段：Type（函数签名）、Import（外部函数/表/内存）、Function（函数声明）、Table、Memory、Global、Export（对外暴露的函数/内存）、Code（字节码）、Data（初始化数据）；自定义段可带名字/调试信息。字符串常量（如 `crypto/aes`、`syscall/js`）常直接出现在 Data 段/字符串区，是定位算法的第一线索。
- **wat 文本格式**：wasm 可反汇编为人类可读的 `.wat`，本质是 S-表达式：`(module ...)` 下每个 `(func (param i32) (result i32) ...)` 是函数，`local.get`/`i32.add`/`call` 等是栈式指令。浏览器 devtools 调试 wasm 时展示的就是 wat，而不是二进制。
- **静态路径**：`wabt` 的 `wasm2c` 把 wasm 转成 C（`wasm2c hello.wasm -o hello.c`），再用 gcc 编译成 `.o` 交给 IDA，可恢复出 `w2c_*` 函数与内存读写 helper；JEB 的 wasmbc 反汇编器可直接加载 `.wasm`，但在部分指令上会报 “Instruction cannot be converted”。010 Editor 适合快速看段结构和字符串。
- **动态路径**：Chromium devtools 的 Sources 面板可把 wasm 以 wat 展示并下断点；Settings → Experiments 勾选 “WebAssembly Debugging: Enable DWARF support” 可增强变量/源码映射。wat 里的 `$global` 常是内存偏移指针（示例 `$global2=78060`），但看不到字符串内容，需要按 `memories[0].buffer` 读内存。
- **本地替换注入辅助函数**：用 DevTools 的 Overrides（本地替换）改写加载 wasm 的 HTML/JS，在 `WebAssembly.instantiateStreaming(...).then(...)` 回调里把 `result.instance.exports` 赋给全局 `wasm`、`wasm.memory` 赋给 `memories`，再挂上 `viewDWORD/viewChar/viewHEX/viewHexCode/dumpMemory/viewString/search`；页面通过 WebSocket 自动 reload，之后在 Console 里就能按地址查看内存字符串。
- **示例还原**：Go 编译的 `output.wasm` 实现 AES 加解密；在 wat 中断在 `$Crypto/aes.NewCipher` 附近，看到 `$var1=144768`，`viewChar(144768)` 得到 16 字节 `newstarTrealstar`；IDA 反编译 wasm2c 产物后，`getKey` 中 `v4 = i32_load8_u(a1+8, loc_12B28+v13); i32_store8(..., v4 ^ 0x0A)` 表明密钥字节是常量表逐字节 XOR 0x0A，异或回来即得 key。配合 strings 中的 `crypto/aes`、`cbcEncrypter` 可确认算法为 AES-CBC。

## 触发条件

- 目标是浏览器加载的 `.wasm`（CTF 题/前端加密），能拿到 wasm 文件与加载它的 JS。
- 浏览器为较新版本 Chromium（支持 wasm 调试），允许修改页面/使用 Overrides。
- 具备 wabt、IDA/JEB 等静态工具；Go/Rust 编译的 wasm 可能保留较多符号/字符串，便于定位。

## 利用步骤

1. 从 Network 面板过滤 Wasm 拿到 `.wasm`，或用 `fetch`/缓存导出；同时保存加载页面的 HTML/JS。
2. 010 Editor 看魔数、段、字符串，记录 `crypto/aes`、`cbcEncrypter`、`syscall/js` 等线索。
3. 静态：`wasm2c output.wasm -o output.c`，`gcc -c output.c` 得 `.o` 丢进 IDA；或用 JEB 直接打开 `.wasm`。在函数列表找导出函数（`$cmd_export`/`encrypt`/`getKey`）并反编译。
4. 动态：devtools → Settings → Experiments 勾选 WebAssembly DWARF 支持；Sources 打开 `output.wasm`，在导出函数/`$Crypto/aes.NewCipher` 等处下断点，单步观察 `$global` 指针与栈。
5. 用 Overrides 替换加载脚本，注入内存辅助函数（见 PoC），刷新后在 Console 用 `viewChar(addr)`/`viewString(addr)`/`search("...")` 读取指针处字符串、搜内存中的常量。
6. 结合静态反编译与动态内存：确认算法（AES-CBC）、key（`newstarTrealstar`）、IV/填充方式，按需写解密脚本或调用页面函数。
7. 复原 flag/明文，记录 key、算法、偏移与 wasm hash。

## PoC

本地替换注入的辅助函数（原文 `code.js`）：

```javascript
wasm = i.instance.exports;
memories = [wasm.memory];
viewDWORD = (addr) => new Uint32Array(memories[0].buffer.slice(addr, addr + 16));
viewChar = (addr, size = 16) => {
  const arr = new Uint8Array(memories[0].buffer.slice(addr, addr + size));
  return String.fromCharCode.apply(null, arr);
};
viewHEX = (addr, size = 16) => {
  const arr = new Uint8Array(memories[0].buffer.slice(addr, addr + size));
  return Array.from(arr, x => x.toString(16).padStart(2, '0')).join(' ');
};
viewString = (addr, size = 16) => {
  const arr = new Uint8Array(memories[0].buffer.slice(addr, addr + size));
  let max = size;
  for (let i = 0; i < size; i++) { if (arr[i] === 0) { max = i; break; } }
  return String.fromCharCode.apply(null, arr.slice(0, max));
};
search = function (str) {
  const m = new Uint8Array(memories[0].buffer);
  const k = Array.from(str, x => x.charCodeAt());
  const match = (j) => k.every((b, i) => m[i + j] === b);
  const max = Math.min(10_000_000, m.byteLength || m.length);
  for (let i = 0; i < max; i++) if (match(i)) console.info(i);
  console.info('done');
};
```

加载处注入（原文片段）：

```javascript
const go = new Go();
WebAssembly.instantiateStreaming(fetch("output.wasm"), go.importObject).then((result) => {
  go.run(result.instance);
  wasm = result.instance.exports;
  memories = [wasm.memory];
  /* 挂载上面的 viewChar/viewString/search ... */
});
```

运行时观察（原文）：

```text
$global2 = 78060
viewChar(78060, 78060+16)      -> 内存原始字节
$var1 = 144768
viewChar(144768)               -> "newstarTrealstar"   // AES key
IDA getKey:
  v4 = i32_load8_u(a1 + 8, (unsigned int)&loc_12B28 + v13);
  i32_store8(a1 + 8, v10, v4 ^ 0x0A);   // 常量表逐字节 XOR 0x0A 得到 key
```

## 变体与关联

- **静态工具变体**：`wasm2wat`/`wasm-decompile` 直接反汇编；`wasm2c` + IDA 适合恢复 C 逻辑；JEB 适合快速预览，但部分指令不支持。
- **动态工具变体**：除 Overrides 外，也可用 Chrome 的 `WebAssembly.instantiate` 断点、`wasm` 运行时 hook、或在 Node.js 里 `require` wasm 后用 `--inspect` 调试。
- **语言/符号变体**：Go wasm 保留 `syscall/js`、`crypto/aes` 等字符串与 `$cmd_export` 命名；Rust/C++ wasm 可能被 strip，需靠内存/行为定位。
- **相似 CTF 卡**：Android UE pak 中加密 wasm 与 native VM 联合仿真见 [[ctf-reverse-android-ue-pak-encrypted-wasm-native-vm-co-simulation]]；Electron asar 内 wasm 许可校验见 [[ctf-reverse-electron-asar-wasm-license-hash-collision-z3]]。
- **wasm 漏洞方向**：导出内存越界读写见 [[web-generic-wasm-unchecked-index-linear-memory-write]]、[[web-generic-wasm-exported-memory-secret-read]]（与本卡逆向方法论互补）。

## 检测与防御

- **防御方视角**：wasm 不是保密或安全边界，客户端 wasm 里的密钥/算法都可被静态反编译与动态 dump；不要把服务端密钥、授权判断只放在 wasm 中。
- **提高逆向成本（非根治）**：strip 符号/DWARF、混淆控制流、自定义解释器/VM、把关键逻辑放服务端；校验 wasm 完整性/签名，防止本地替换调试。
- **检测**：页面加载的 wasm hash 变化、DevTools Overrides 注入、运行时对 `WebAssembly.instantiate` 的 hook；CTF 之外可用于前端加密方案的取证与算法恢复。

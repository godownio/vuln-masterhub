---
id: code-analysis-reverse-obfuscation-zig-comptime-string-xor-encryption
title: Zig comptime 编译期字符串异或加密：build.zig 每次编译生成随机 key，运行时在栈上解密
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: zig-comptime-string-xor-encryption
aliases:
- Zig 字符串加密
- comptime 编译期加密
- zigxorstr
- Zig XOR 字符串混淆
- 动态 key 字符串加密
tags:
- obfuscation
- string-encryption
- zig
- comptime
- xor
- edr-evasion
- static-detection
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T11:40:30+08:00'
  notes: 已对照原文与图01核对：Zig 0.11 comptime encrypt/x 代码、.L__unnamed_1 密文、16字节 key 值、vmovups+逐字节 xor 循环、zig build -Doptimize=ReleaseSmall 后 strings 无明文均与原文一致；已修正正文 key 简写（原误写为 \001\002...\016）并改写『任何线程调用前』措辞。未在本机编译复现；动态 key 需 build.zig 版本适配
---

## 一句话结论

Zig 的 `comptime` 可以在编译期对字符串常量逐字节异或加密，把密文直接嵌入二进制；运行时 `x()` 每次调用都把密文复制到栈缓冲区再异或还原，因此 `.rdata` 中不再出现敏感明文，且解密后的明文只在栈上短暂存在；再通过 `build.zig` 的 `addOptions` + `std.os.getrandom` 每次编译生成随机 key，可避免固定密钥成为编译产物特征。

## 原理

- **compile-time 求值**：Zig 的 `comptime` 关键字让函数/变量在编译期执行。`encrypt(comptime str)` 在编译期生成 `[str.len]u8` 密文数组并返回；`export fn main()` 中调用 `x("...")` 时，编译器把密文作为只读数据放入 `.rdata`，不会保留源码明文字面量。
- **密文形态**：原文反汇编中 `.L__unnamed_1` 是 `.ascii "`cbegdejjcbag`ab...::131266"`（明文 `aaaa...` 与 key 异或后的结果），`.L__unnamed_2` 是 16 字节 key `\001\002\003\004\005\006\007\b\t\000\001\002\003\004\005\006`；`main` 先用 `vmovups` 把两段数据搬到 `[rsp-56]`，再进入循环 `xor byte ptr [rsp+rax-56], cl` 逐字节解密。
- **为什么栈上解密更安全**：与 LLVM pass 原地解密不同，栈缓冲区在函数返回后很快被覆盖，内存扫描窗口更小；不存在“多个线程同时解密同一份全局字符串”的竞争问题（每次调用各自解密到自己的栈）。
- **与 C++ constexpr/xorstr 的差异**：思路相同（编译期加密、运行时解密），但 Zig 用 `comptime` 函数 + 切片/数组返回，代码更短；原文还演示了构建期随机 key，使每次编译的密文不同，降低基于固定字节序列/YARA 的命中率。
- **动态 key 的实现**：`build.zig` 中
  ```zig
  var options = b.addOptions();
  var key: [16]u8 = undefined;
  std.os.getrandom(&key) catch unreachable;
  options.addOption([16]u8, "key", key);
  exe.addOptions("option", options);
  ```
  然后在 `main.zig` 里 `const key = @import("option").key;`。key 在构建时生成并写入编译产物（通常仍在 `.rdata`），因此它不是“密钥保密”，而是“每次构建特征不同”。
- **边界**：key 与密文都在二进制中，逆向者仍可提取二者还原明文；该手法只对抗静态字符串扫描/签名，不能对抗运行时内存扫描、API hook 或行为检测。原文示例中 `strings` 已看不到明文，但反汇编可看到密文和 key。

## 触发条件

- 目标为 Zig 项目（原文使用 Zig 0.11），编译器支持 `comptime`，能以 ReleaseSmall/ReleaseFast 等优化构建。
- 需要隐藏的是编译期已知的字符串（API 名、URL、注册表路径、User-Agent、命令等）；运行时拼接/用户输入字符串不适用。
- 攻击者能修改 `build.zig` 与源码，控制构建链（用于每次生成随机 key）。
- 防护方主要依赖 `.rdata` 明文字符串/签名/YARA，且没有做运行时内存扫描或 API 参数 hook。
- 运行时解密缓冲区应尽量短命（栈上、用后不保留）。

## 利用步骤

1. 在项目中定义 16 字节 key（固定或从 `@import("option").key` 读取）和 `encrypt(comptime str)` 函数：编译期逐字节 `str[i] ^ key[i % key.len]`，返回密文数组。
2. 定义 `inline fn x(comptime str)`：编译期调用 `encrypt` 得到 `e`，运行时 `var buf = e.*` 复制到栈，再逐字节异或还原，返回 `buf[0..str.len]`。
3. 把敏感字符串字面量替换为 `x("...")`，在 `main`/业务函数中使用返回值（文件路径、URL、API 名等）。
4. 在 `build.zig` 中加入 `addOptions` + `std.os.getrandom` 生成随机 key，并 `exe.addOptions("option", options)`；源码改为 `const key = @import("option").key;`。
5. 构建后用 `strings <binary>` 检查目标明文是否消失（原文截图显示 `strings` 只输出导入表符号，没有测试字符串）；再反汇编确认密文/解密循环形态。
6. 叠加 API 哈希/PEB 动态解析、直接系统调用等，避免运行时解密后的 API 名在调用点重新成为 hook 特征；评估内存扫描风险。
7. 若需要更强隐藏，考虑把 key/密文拆分到不同段、运行时派生 key、解密后清零栈缓冲区。

## PoC

```zig
const std = @import("std");
const key = [16]u8{1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6};
const string = []const u8;

fn encrypt(comptime str: string) *[str.len]u8 {
    comptime var enstr: [str.len]u8 = undefined;
    for (0..str.len) |i| {
        enstr[i] = str[i] ^ key[i % key.len];
    }
    return enstr[0..str.len];
}

inline fn x(comptime str: string) []u8 {
    comptime var e = encrypt(str);
    var buf = e.*;
    for (0..buf.len) |i| {
        buf[i] ^= key[i % key.len];
    }
    return buf[0..str.len];
}

export fn main() void {
    var s1 = x("aaaabbbbccccddddaaaabbbbccccdddd123123123123123");
    _ = std.io.getStdOut().write(s1) catch unreachable;
}
```

```zig
// build.zig：每次编译生成随机 key
var options = b.addOptions();
var key: [16]u8 = undefined;
std.os.getrandom(&key) catch unreachable;
options.addOption([16]u8, "key", key);
exe.addOptions("option", options);
```

```zig
// main.zig：改用构建期 key
const key = @import("option").key;
```

```text
# 原文反汇编形态：
# .L__unnamed_1: .ascii "`cbegdejjcbag`ab`cbegdejjcbag`ab0005756::131266"   ; 密文
# .L__unnamed_2: .ascii "\001\002\003\004\005\006\007\b\t\000\001\002\003\004\005\006" ; key
# main: vmovups 密文到栈 → 循环 xor byte ptr [rsp+rax-56], cl → 使用

# 原文验证：zig build -Doptimize=ReleaseSmall 后 strings 产物无明文测试字符串。
```

未在本机编译/运行；原文代码与反汇编为佐证。

## 变体与关联

- 变体：固定 key（原文第一版）vs 构建期随机 key（`addOptions` + `getrandom`）；后者让每次产物密文不同，但 key 仍随产物分发。
- 变体：key 从编译期常量改为运行时派生（如从时间/环境/PE 字段派生），或使用多字节滚动 key/RC4/ChaCha 等算法替代简单 XOR。
- 变体：把字符串拆成多段、异或后 Base64/十六进制存储，运行时拼接；或与 API 哈希/PEB 解析结合，避免解密后的 API 名出现在调用点。
- 关联：[[code-analysis-reverse-obfuscation-constexpr-compile-time-string-encryption]]——C++ `constexpr`/xorstr 的同类方案；本卡是 Zig `comptime` 实现 + build.zig 动态 key，语言/构建方式/产物形态不同。
- 关联：[[code-analysis-reverse-obfuscation-rust-chacha20poly1305-string-decrypt-idapython]]（Rust 字符串解密）、[[code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt]]（.NET XORStrings 自动解密）、[[code-analysis-reverse-obfuscation-obfuscar-dnlib-string-auto-decrypt]]（.NET 混淆器字符串解密）。
- 边界：key+密文都在二进制中，静态逆向可还原；对内存扫描/hook/ETW 无效；过度使用解密 stub 本身也可能成为特征。

## 检测与防御

- 检测：反汇编中寻找“读取只读数据到栈 + 逐字节 XOR 循环”的 stub；扫描高熵/异或密文常量与紧随其后的 16 字节 key；对 `strings` 干净但行为可疑的样本做内存扫描。
- 检测：运行时 hook `GetProcAddress`/`LoadLibrary`/网络 API，捕获解密后的参数；ETW/EDR 监控栈上短暂明文与异常解密循环。
- 防御：静态检测结合行为链、内存扫描与控制流分析，不只依赖字符串签名；对解密 stub/高熵数据提高评分。
- 加固：发布构建 strip 符号；避免在 `.rdata` 保留明文；对敏感字符串使用更强的运行时保护（内存加密、按需解密、用后清零）；评估 EDR 内存扫描覆盖。

## 附：原文要点

- LLVM pass 方案需要临界区/标志位防止多线程竞争，且原地解密无法绕过内存查杀；C++17 constexpr/xorstr 将解密放栈上，解决了竞争并缩小内存窗口。
- Zig 用 `comptime` 实现同样效果，代码短；原文在 Zig 0.11 验证，反汇编可见密文与 key 都在只读数据中。
- 动态 key 通过 `build.zig` 的 `addOptions` + `std.os.getrandom` 生成，源码用 `@import("option").key` 读取。

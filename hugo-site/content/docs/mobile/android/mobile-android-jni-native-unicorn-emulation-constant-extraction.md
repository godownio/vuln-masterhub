---
id: mobile-android-jni-native-unicorn-emulation-constant-extraction
title: Android JNI native 校验链模拟执行：ARM64 机器码常量提取 + Unicorn hook 调用
type: scenario
domain: mobile
path: mobile/android
technique: jni-native-unicorn-emulation-constant-extraction
tags:
- android
- reverse
- jni
- native
- arm64
- unicorn
- emulation
- apk
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:21:10+08:00'
  notes: 已对照原文核对：JNI 方法列表、k3y_j4va_k3y!!!! 掩码异或用户名 zkp_master、Zkp_+M_as+t3er 密码、MOVZ/MOVK/ADRP 提取 CH1 seed/4 常量/target 与 CH3 64 位常量、Unicorn PT_LOAD+hook 调用、state 计数与三个位标记、generateFlag 输出 ISCC{610e...}，均与卡片一致。未验证点：PoC/Unicorn 脚本未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/mobile/android/mobile-android-jni-native-unicorn-emulation-constant-extraction/
draft: false
kb_aliases:
- JNI native 校验
- libzkpcore.so
- Unicorn 模拟执行
- ARM64 MOVZ MOVK ADRP
- 提取 native 常量
- 补 ChallengeState 位
- 按步取匙
---

## 一句话结论

Java 层只负责串 JNI，真实校验在 `libzkpcore.so`；从 `.rodata` 用标记异或还原用户名/密码，从 `.text` 的 MOVZ/MOVK/ADRP 指令提取第一关 seed、4 个 round key、target 与第三关 64 位异或常量，再用 Unicorn 映射 PT_LOAD、hook 常用 libc 函数并直接调用 native 校验/生成函数，补齐 `ChallengeState` 计数与三个位标记后即可生成 flag。

## 原理

- **JNI 只是参数转换**：`MainActivity` 暴露 `nativeInit`、`nativeLogin`、`nativeVerifyChallenge1/2/3WithToken`、`nativeGenerateFlag` 等方法，核心逻辑都在 `.so`；静态分析应先定位 JNI 入口，再跟到内部 `*_core` 函数。
- **ARM64 常量提取**：32 位常量由 `MOVZ`（低 16 位）+ `MOVK`（高 16 位）组合；全局指针由 `ADRP`（页基址）+ `ADD`（页内偏移）定位。按固定函数偏移读指令字并解码，就能在不跑程序的情况下拿到 seed、round key、target、xor 常量与 token 缓冲区地址。
- **凭据恢复**：用户名不是明文，而是 `marker = "k3y_j4va_k3y!!!!"` 与其后 10 字节 mask 异或；密码由 `Zkp_ + M_as + t3er` 三段拼接。这类“标记 + 掩码”是 native 题常见写法。
- **Unicorn 模拟**：把 ELF 的 `PT_LOAD` 段按 vaddr 映射到 Unicorn，另映射 heap/stack 和返回地址页；对 `calloc`、`memset`、`memcpy`、`strcmp`、`strlen`、`strcpy`、`strcat`、`strtoul`、`vsnprintf`、`sha256`、`hex` 等导入/内部调用注册 hook，用 `emu_start(address, RET_ADDR)` 调用函数并在 hook 里模拟返回值。
- **状态机**：JNI wrapper 维护 `state[0:4]` 已通过关卡计数与 `state[4:7]` 三个位标记；只调 core 不补状态位时 `generateFlag` 会失败，因此要按通过顺序写 `state`。

## 触发条件

- APK 含 `lib/arm64-v8a/*.so`，Java 层有多个 native 校验方法。
- `.so` 未加壳/未强混淆，函数偏移可静态确定；或可先脱壳再分析。
- 校验逻辑由固定模板 + 附件内嵌常量组成，常量随附件变化。
- 允许本地模拟执行（无强反调试/环境检测）。

## 利用步骤

1. 解压 APK，取 `lib/arm64-v8a/libzkpcore.so`；用 pyelftools 读 `.rodata` 与 `.text` 的 vaddr/内容。
2. 在 `.rodata` 搜索标记字符串，按标记后的 mask 异或还原用户名；按三段常量拼出密码。
3. 用 `MOVZ/MOVK` 解码第一关 seed、4 个 round key 与 target；用 `ADRP+ADD` 定位第三关 token 缓冲区与全局状态指针。
4. 实现第一关的 Feistel/LFSR 逆运算（或直接枚举 `.rodata` 中 4 字节常量作为 target 候选），把候选交给真实 `CHECK_CH1` 复验。
5. 调用 `FN_MAKE_CH2` 生成第二关答案，再交给 `CHECK_CH2`；通过后从全局 token 缓冲区读中间 token。
6. 按 `pack(token[:8]) ^ xor_const` 计算 mixed，`sha256(mixed.to_bytes(8,"little")).hex()[:16]` 得第三关答案，交给 `CHECK_CH3`。
7. 依次写 `state = 1/2/3 + 位标记`，调用 `FN_GEN_FLAG_CORE(state, auth, flag_buf, 0x80)`，读回 flag。

## PoC

```python
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_LR, UC_ARM64_REG_X0

def decode_mov_w(instr):
    return ((instr >> 5) & 0xFFFF) << (((instr >> 21) & 3) * 16)

def is_movz_w(i): return (i & 0x7F800000) == 0x52800000
def is_movk_w(i): return (i & 0x7F800000) == 0x72800000

# seed = decode_mov_w(word_at(FN_CHECK_CH1_CORE + OFF_CH1_SEED_MOV)) & 0xFFFF
# const = (decode_mov_w(movz) | decode_mov_w(movk)) & 0xFFFFFFFF
# emu.call(FN_CHECK_CH1_CORE, emu.alloc_str(candidate), state) == 1
```

## 变体与关联

- **架构变体**：x86_64 `.so` 用 `mov eax, imm32`/`lea rip-relative`；ARM32 用 `movw/movt`；需按 ELF `e_machine` 选择解码器。
- **入口变体**：JNI 函数可能通过 `RegisterNatives` 动态注册，静态符号缺失；可从 `JNI_OnLoad` 或导出表定位。
- **保护变体**：OLLVM 控制流平坦化、字符串加密、反调试、Frida 检测；可改用 Qiling/Frida 或先脱壳。
- **关联卡片**：[[ctf-reverse-android-ue-pak-encrypted-wasm-native-vm-co-simulation]]（Android 多引擎协同逆向）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（加固 APK 脱壳）、[[ctf-reverse-apk-native-tea-gf256-matrix-lcg]]（APK native 多段校验）。
- **边界**：Unicorn 只模拟用户态指令，遇到 syscall/未 hook 的导入会失败；函数偏移随模板变化，不能写死。

## 检测与防御

- **CTF 验证**：先用 `nativeLogin` 验证凭据恢复正确，再用真实 `CHECK_CH1/2/3` 复验每个候选，最后确认 `generateFlag` 返回值与 flag 格式。
- **防御**：不要把 flag 生成逻辑放在客户端 native；对关键校验做服务端验证；使用代码混淆/加固/反调试；native 中避免明文常量与固定模板。
- **检测信号**：APK 含大量 JNI 校验方法；`.so` 中出现固定标记字符串与 MOVZ/MOVK 常量表；运行时出现 Unicorn/Frida 特征。

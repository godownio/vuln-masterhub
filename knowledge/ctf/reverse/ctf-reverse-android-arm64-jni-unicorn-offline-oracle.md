---
id: ctf-reverse-android-arm64-jni-unicorn-offline-oracle
title: Unicorn 用户态仿真 Android ARM64 JNI .so：伪造 JNIEnv/Java String 与导入桩，构建离线加解密 oracle
type: scenario
domain: ctf
path: ctf/reverse
technique: android-arm64-jni-unicorn-offline-oracle
aliases:
- Flag Shop
- libflagshop.so
- NativeBridge.encryptFlag
- JNIEnv 伪造
- Unicorn JNI 仿真
- 离线 oracle
tags:
- ctf
- reverse
- android
- arm64
- unicorn
- jni
- elf
- emulation
- oracle
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:24:32+08:00'
  notes: 已对照原文核对：Flag Shop 四元参数顺序（商品/候选 flag/账号/密码）、admin/FlagShopAdmin2026、PT_LOAD 映射、R_AARCH64_RELATIVE(1027)、JNIEnv vtable +0x538、短/长 Java String 布局、导入桩列表、fakeflag1 校准、realflag 结果 ISCC{7H15_1$_r431_f146_4nd_17_h45n'7_501d_0u7?!} 均与卡片一致。未验证点：Unicorn PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

把 Android ARM64 `libflagshop.so` 抽出来，在 Unicorn 里映射 PT_LOAD、补 `R_AARCH64_RELATIVE` 重定位、伪造最小 JNIEnv/函数表和 Java String 布局、给导入函数打桩，就能直接调用 `NativeBridge.encryptFlag(item, candidate, user, pass)` 的 native 实现，把“必须真机跑 APK”的校验变成可批量试参的离线 oracle。

## 原理

- **JNI 调用约定**：native 方法第一个参数是 `JNIEnv*`，第二个是 `jobject/jclass`，之后才是 Java 参数。`encryptFlag(String a, String b, String c, String d)` 在 ARM64 上对应 `X0=JNIEnv*`、`X1=this`、`X2..X5=四个 jstring 指针`。
- **Java String 布局**：ART 的 `mirror::String` 短字符串（≤22 字节）首 4 字节为 `length << 1`（低位置 0），随后是压缩字符串数据；长字符串首 4 字节为 1（高位置 1），`+8` 为长度，`+16` 为数据指针。伪造时必须按目标 so 实际读取方式写。
- **JNIEnv 是函数表指针**：`*JNIEnv = &vtable`，`vtable[offset]` 是函数指针。只需把目标用到的槽位（本例 `0x538`）指向自己的返回桩；桩里读取参数/返回值并记录。
- **导入函数打桩**：`.rela.plt` 中每个符号分配一个 stub 地址，stub 写入 `ret` 指令；执行到 stub 时在 code hook 里按符号名实现 `strlen/strcmp/strncmp/memcmp/memcpy/memset/malloc/realloc/free/__system_property_get/strstr/getpid/syscall/abort/__stack_chk_fail` 等，并模拟返回值。
- **重定位**：`.rela.dyn` 中的 `R_AARCH64_RELATIVE`（type 1027）可直接把 `r_addend` 写到 `r_offset`；其余动态符号按导入桩处理。`PT_LOAD` 段要按页对齐映射，`p_memsz > p_filesz` 的 BSS 部分补零。
- **参数语义**：四个参数实际是商品编号、候选 flag、管理员账号、管理员密码；顺序错位会让 native 读到错误字符串，表现为“环境坏了”。本题管理员为 `admin`，密码在初始化路径写入，正确值 `FlagShopAdmin2026`（容易少看最后一个 `6`）。
- **用 fake 商品校准**：`fakeflag1` + `ISCC{fakeflagfake}` + `admin/FlagShopAdmin2026` 应进入正常路径；确认 oracle 可信后，再换 `realflag` + 目标密文跑出结果。本题最终 flag 为 `ISCC{7H15_1$_r431_f146_4nd_17_h45n'7_501d_0u7?!}`。

## 触发条件

- 目标校验在 ARM64 `.so` 中，JNI 入口可通过导出符号或 `JNI_OnLoad` 里的 `RegisterNatives` 定位。
- so 的宿主依赖有限（libc 内存/字符串函数、JNI 回调），可以逐个打桩。
- 有目标密文、商品表、管理员凭据等输入。
- 本机有 Unicorn + pyelftools；不需要 root 或真机。

## 利用步骤

1. 解包 APK，取 `lib/arm64-v8a/libflagshop.so`；用 jadx 找 `System.loadLibrary`、`native` 声明或 `RegisterNatives`，确认 JNI 函数地址/符号。
2. 用 pyelftools 遍历 `PT_LOAD` 段映射；对 `.rela.dyn` 的 type 1027 写 addend；对 `.rela.plt` 每个符号分配 stub 并写 `ret`。
3. 在 Unicorn 中映射栈、JNIEnv、vtable、stub、返回桩、参数缓冲和堆；写 `*JNIEnv = vtable`，把用到的 vtable 槽指向返回桩。
4. 写 `place_args`：四个 Java String 指针指向伪造的 String 结构；短串用 `[len<<1]+bytes`，长串用 `[1][len][ptr]`。
5. 注册 code hook：命中导入 stub 时按符号名实现；命中 JNI 返回桩时读取返回值/输出字符串并记录；命中字符串构造等特定地址时跳过或修正。
6. 先跑 fake 样本确认 oracle 正常；再换 `realflag` 输入，读取输出/比较结果；必要时 hook 比较函数直接取期望值。
7. 用输出或密文反推 flag；本题 realflag 直接跑出 `ISCC{7H15_1$_r431_f146_4nd_17_h45n'7_501d_0u7?!}`。

## PoC

核心骨架（导入桩的完整实现按原文脚本补齐；未在本库复跑）：

```python
import struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_PROT_ALL
from unicorn.arm64_const import *

RET = b"\xc0\x03\x5f\xd6"
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# 1) 映射 PT_LOAD
elf = ELFFile(open("libflagshop.so", "rb"))
for seg in elf.iter_segments():
    if seg["p_type"] != "PT_LOAD":
        continue
    va, ms, fs = seg["p_vaddr"], seg["p_memsz"], seg["p_filesz"]
    base = va & ~0xfff
    mu.mem_map(base, ((va + ms + 0xfff) & ~0xfff) - base)
    mu.mem_write(va, seg.data())
    if ms > fs:
        mu.mem_write(va + fs, b"\x00" * (ms - fs))

# 2) R_AARCH64_RELATIVE
for name in (".rela.dyn", ".rela.plt"):
    sec = elf.get_section_by_name(name)
    if not sec:
        continue
    for rel in sec.iter_relocations():
        if rel["r_info_type"] == 1027:
            mu.mem_write(rel["r_offset"], struct.pack("<q", rel["r_addend"]))

# 3) 地址布局与假 JNIEnv
STACK, JNI, VTAB, STUB, JNIRET, BUF, HEAP = (
    0x02000000, 0x03000000, 0x03001000, 0x03100000,
    0x03200000, 0x03300000, 0x03400000)
for base, size in ((STACK, 0x200000), (JNI, 0x30000), (STUB, 0x10000),
                   (JNIRET, 0x1000), (BUF, 0x40000), (HEAP, 0x40000)):
    mu.mem_map(base, size, UC_PROT_ALL)
mu.mem_write(JNI, struct.pack("<Q", VTAB))
mu.mem_write(JNIRET, RET)
mu.mem_write(VTAB + 0x538, struct.pack("<Q", JNIRET))  # 目标用到的 JNI 槽

def jstring(dst, text):
    raw = text.encode()
    mu.mem_write(dst, b"\x00" * 0x20)
    if len(raw) <= 22:
        mu.mem_write(dst, bytes([len(raw) << 1]) + raw)
    else:
        ptr = HEAP + 0x1000
        mu.mem_write(ptr, raw + b"\x00")
        mu.mem_write(dst, struct.pack("<Q", 1) + struct.pack("<Q", len(raw)) + struct.pack("<Q", ptr))

# 4) 导入桩
imports = {}
rela = elf.get_section_by_name(".rela.plt")
symtab = elf.get_section(rela["sh_link"])
for slot, rel in enumerate(rela.iter_relocations()):
    sym = symtab.get_symbol(rel["r_info_sym"]).name if rel["r_info_sym"] else ""
    if sym not in imports:
        imports[sym] = STUB + slot * 0x80
        mu.mem_write(imports[sym], RET)
    mu.mem_write(rel["r_offset"], struct.pack("<Q", imports[sym]))

# 5) 四个 Java String 参数
args = ("fakeflag1", "ISCC{fakeflagfake}", "admin", "FlagShopAdmin2026")
for i, s in enumerate(args):
    jstring(BUF + i * 0x100, s)

def cstr(addr, limit=0x1000):
    out = bytearray()
    for i in range(limit):
        ch = mu.mem_read(addr + i, 1)[0]
        if ch == 0:
            break
        out.append(ch)
    return bytes(out)

def hook(mu, addr, size, _):
    if addr == 0x5007C:  # const char* -> Java String（X1 源，X8 目的）
        jstring(mu.reg_read(UC_ARM64_REG_X8), cstr(mu.reg_read(UC_ARM64_REG_X1)).decode())
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR)); return
    if addr == JNIRET:   # JNI 返回桩：记录输出
        out = mu.reg_read(UC_ARM64_REG_X1)
        print(cstr(out))
        mu.reg_write(UC_ARM64_REG_X0, out)
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR)); return
    if addr in imports.values():
        # 按符号名实现 strlen/strcmp/memcpy/malloc/__system_property_get...
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR)); return

mu.hook_add(UC_HOOK_CODE, hook)
mu.reg_write(UC_ARM64_REG_SP, STACK + 0x1f0000)
mu.reg_write(UC_ARM64_REG_LR, JNIRET)
mu.reg_write(UC_ARM64_REG_X0, JNI)     # JNIEnv*
mu.reg_write(UC_ARM64_REG_X1, 0x1234)  # this
for i, reg in enumerate((UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)):
    mu.reg_write(reg, BUF + i * 0x100)
mu.emu_start(0x517A8, 0x56000, count=10_000_000)
```

原文脚本在 `0x6E1AC` 还有一处直接返回桩；若目标路径命中该地址，同样把 `PC` 设为 `LR`。

## 变体与关联

- **仿真器变体**：Unicorn、Qiling、angr 均可；核心是“映射镜像 + 伪造宿主接口 + 只保留目标状态机”。
- **JNI 变体**：`GetStringUTFChars`/`GetStringCritical`/`NewStringUTF` 的返回值布局不同；ART 压缩字符串与 UTF-16 字符串要区分；`RegisterNatives` 动态注册时按函数指针找入口。
- **导入桩变体**：libc 内存/字符串函数、`__system_property_get`、`getpid`、`syscall`；反调试/完整性函数可直接返回成功。
- **关联卡片**：[[ctf-reverse-ios-macho-unicorn-mach-ipc-rc4]]（Unicorn 替换 Mach IPC）、[[mobile-harmony-hap-arkts-native-sbox-affine-unicorn]]（Unicorn 黑盒求逆）、[[ctf-reverse-apk-chacha20-counter-one-native]]（APK native 校验）。
- **边界**：so 若依赖 Android 特有 libc/JNI 全局引用/系统属性，需逐个打桩；有反调试或签名校验时先 patch；PoC 未在本库复跑。

## 检测与防御

- **保护方**：关键校验放服务端或设备绑定；native 加反调试、完整性校验、JNI 调用者校验；不要把管理员口令硬编码在初始化路径。
- **分析方**：先用 fake 样本校准 oracle，再换真实输入；记录参数顺序、String 布局和导入符号，避免把逻辑失败误判成环境问题。
- **检测**：Unicorn/Qiling 仿真、异常 JNI 调用序列、进程映射非系统 so；离线仿真本身难以被目标感知。

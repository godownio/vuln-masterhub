---
id: code-analysis-reverse-windows-crackme-volume-serial-hypotenuse-keygen
title: CrackMe 卷序列号绑定注册码：GetVolumeInformationA 取 C/D 盘序列号算平方和开方，Name 乘法折叠+ROL 1+OR+AND 后按 mod16 查表生成 Serial，lstrcmpA 比较
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: volume-serial-hypotenuse-name-keygen
aliases:
- 卷序列号注册码
- GetVolumeInformationA 断点
- 硬盘序列号绑定注册机
- C/D 盘卷序列号
- 平方和开方 hypotenuse
- 乘法折叠 hash
- lstrcmpA 校验
- NOP JNZ 爆破
tags:
- reverse
- windows
- crackme
- keygen
- ollydbg
- volume-serial
- fpu
- serial
- x86
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T12:20:36+08:00'
  notes: '已对照原文与图09-20核对：GetVolumeInformationA C:/D: 卷序列号 A833742F/DC171869、FILD/FMULP/FADDP/FSQRT/FISTP 平方和开方=0x5EDBD5A9、Name Step1 MUL+折叠、ROL1/OR/AND 0FFFFFFF、mod16 查表 071362de9f8ab45c、lstrcmpA 与 75 18 NOP 均一致；复算 hypot=0x5edbd5a9、ReCrackMe→f85e4cccccca53 与截图一致。未运行样本'
---

## 一句话结论

该 CrackMe 先用 `GetVolumeInformationA` 读取 `C:\` 与 `D:\` 的卷序列号，把二者按有符号 32 位转成浮点做 `sqrt(C²+D²)` 并取整，作为环境绑定值；再把 `Name` 逐字节做“乘法后高低 32 位相加折叠”的 hash，对该值 `ROL 1`、与卷序列号派生值 OR、`AND 0x0FFFFFFF`，最后循环取 `num % 16` 查表 `071362de9f8ab45c`、`num /= 4` 生成 Serial，用 `lstrcmpA` 与输入比较；注册机必须在目标机读取同一卷序列号复算，或直接把比较后的 `JNZ` 补成 NOP。

## 原理

- **卷序列号来源**：程序导入 `GetVolumeInformationA`，在 0x004010C2 的包装函数内两次调用它，`RootPathName` 分别为 `C:\` 与 `D:\`，第 4 个参数 `pVolumeSerialNumber` 指向栈上 DWORD。OllyDbg 在 `GetVolumeInformationA` 下断，命中后 `Ctrl+F9` 执行到返回再 `F8`，可从 `EAX`（或参数指向的内存）读到卷序列号；文章样本环境为 `C: A833742F`、`D: DC171869`。卷序列号由文件系统在格式化时生成，通常随机器/分区变化，因此 Serial 天然绑定本机。
- **平方和开方（hypotenuse）**：0x00401056 的函数把两个 DWORD 用 `FILD DWORD` 压入 x87 浮点栈（**有符号** 32 位解释），各自 `FLD ST`+`FMULP` 求平方，`FADDP` 相加，`FSQRT` 开方，`FISTP DWORD [EBP-4]` 按 FPU 当前舍入模式取整回 32 位。结果 `round(sqrt(int32(C)²+int32(D)²))` 即两卷序列号的“斜边”，作为后续 Name-Step2 的 OR 掩码值；文章样本中为 `0x5EDBD5A9`（等价于其 C++ 注册机里的 `CalculateHypotenuse`）。
- **Name-Step1（乘法折叠）**：0x00401036 的函数以 `EAX=1` 开始，对 `Name` 每个字节 `c` 执行 `MUL ECX` 得到 `EDX:EAX = EAX*c`，再 `ADD EAX,EDX`，即每轮把 64 位乘积的低 32 位与高 32 位相加后截断回 32 位，作为下一轮的乘数；循环到字符串结尾。它不是简单的逐字符乘积累加，而是每步都做一次“进位折叠”，等价于一种 32 位乘法 hash。
- **Name-Step2（卷序列号混入）**：0x00401253–0x00401263：把 Step1 结果 `ROL EAX,1`，再与上面的卷序列号派生值 `[EBP-10]` 做 OR，最后 `AND EAX,0x0FFFFFFF`，结果存入 `[EBP-14]`。掩码把高位清零，保证后续为 28 位非负值（也使得 Step3 的除法可用有符号/无符号一致解释）。文中还计算过 `(C+D)<<5` 再 `ROL 0x0D` 的中间值，但最终参与 OR 的是 hypotenuse 值（按文章注册机与验证截图复算可确认）。
- **Name-Step3（查表生成 Serial）**：0x00401273–0x0040129F 的循环：`num % 0x10` 作下标，从 0x00402073 的表 `071362de9f8ab45c`（16 个字符）取一字节写入 Serial 缓冲区；`num /= 4`；若商为 0 结束，否则 `ESI++` 继续。由于每轮除以 4，Serial 长度约 `ceil(log4(num))`，字符只可能来自该 16 字符表。
- **比较**：最后 `GetDlgItemTextA` 读入 Serial，`lstrcmpA(计算出的 Serial, 输入 Serial)`，0x004012D5 处 `JNZ SHORT 0x004012EF` 决定成功/失败；Name 在进入算法前还有 `长度 >= 4` 的检查（`CMP EAX,4; JL`）。
- **为什么 keygen 必须绑定环境**：Step2 的 OR 值来自本机卷序列号，换机器/重装系统后卷序列号变化，原 Serial 失效；这也是程序用卷序列号做“机器绑定”的典型做法。补丁路径则完全绕过该绑定。

## 触发条件

- 目标为本地 Windows 32 位 GUI 注册校验程序，使用 `GetVolumeInformationA` 读取 `C:\`/`D:\` 卷序列号参与算法，且无壳/未强反调试。
- 可运行 OllyDbg/IDA，能对 `GetDlgItemTextA`、`GetVolumeInformationA` 下断并读取返回参数。
- keygen 场景要求运行环境存在与目标一致的 `C:\` 和 `D:\` 卷（或已知其卷序列号，可离线代入）；若目标机无 D 盘，`GetVolumeInformationA` 失败时 D 序列号保持 0，算法结果会不同，需要按实际返回值复算。
- 只做本地绕过时不需要卷序列号，直接补丁比较后的跳转即可。

## 利用步骤

1. PEiD 确认 32 位 GUI、TASM/MASM、无壳；导入 OllyDbg，`Ctrl+N` 查看导入表，对 `GetDlgItemTextA` 与 `GetVolumeInformationA` 下 `BPX` 断点。
2. F9 运行，输入 `Name/Serial` 点 Check；命中 `GetVolumeInformationA` 后查看栈参数（`RootPathName` 为 `C:\`），`Ctrl+F9` 到返回再 `F8`，记录 `pVolumeSerialNumber` 的 DWORD；继续运行到第二次调用取 `D:\` 的值。文章样本为 `A833742F` / `DC171869`。
3. 在 0x004010C2 包装函数内跟随：0x00401098 为 `SHL EAX,CL`、0x00401081 为 `ROL EAX,CL`、0x004010AF 为 `ADD`、0x00401056 为 `FILD/FMULP/FADDP/FSQRT/FISTP` 的平方和开方；确认最终进入 `[EBP-10]` 的是 hypotenuse 值。
4. 继续单步到 Name 算法：确认长度 ≥4；Step1 的 `MUL ECX` + `ADD EAX,EDX` 折叠；Step2 的 `ROL 1`、`OR [EBP-10]`、`AND 0x0FFFFFFF`；Step3 的 `%16` 查表 `071362de9f8ab45c` 与 `/4` 循环。
5. 在 0x004012C2–0x004012D5 确认 `lstrcmpA` 比较及 `JNZ` 跳转；记录 Name/Serial 输入控件与成功提示分支。
6. 写 keygen：在目标机用 `GetVolumeInformationW/A` 读取 C/D 卷序列号，按上述步骤复算 Serial；用计算值登录验证。
7. 补丁替代：把 0x004012D5 的 `75 18` 改为 `90 90`，保存为新文件；输入任意非空 Name（长度 ≥4）/Serial 即顺序走到成功分支（文章用 `ReCrackMe/R123456e` 验证）。

## PoC

无漏洞利用 PoC；以下为按汇编重写的 keygen（未对目标程序实跑；用文章样本的卷序列号与 Name 复算，结果与文章截图 `f85e4cccccca53` 一致）。

```python
import ctypes, math, struct

def volume_serial(root: str) -> int:
    k = ctypes.windll.kernel32
    vol = ctypes.create_unicode_buffer(261)
    fs  = ctypes.create_unicode_buffer(261)
    serial = ctypes.c_uint()
    maxlen = ctypes.c_uint()
    flags  = ctypes.c_uint()
    ok = k.GetVolumeInformationW(root, vol, 261, ctypes.byref(serial),
                                 ctypes.byref(maxlen), ctypes.byref(flags), fs, 261)
    if not ok:
        return 0
    return serial.value

def as_i32(x: int) -> int:
    return x - 0x100000000 if x & 0x80000000 else x

TABLE = "071362de9f8ab45c"

def keygen(name: str, c_serial=None, d_serial=None) -> str:
    C = volume_serial("C:\\") if c_serial is None else c_serial
    D = volume_serial("D:\\") if d_serial is None else d_serial
    vol = round(math.sqrt(as_i32(C) ** 2 + as_i32(D) ** 2)) & 0xFFFFFFFF

    n = 1                                   # Step1: 每轮 (low32 + high32)
    for c in name.encode("ascii"):
        p = n * c
        n = ((p & 0xFFFFFFFF) + (p >> 32)) & 0xFFFFFFFF

    n = ((n << 1) | (n >> 31)) & 0xFFFFFFFF # Step2: ROL 1
    n = (n | vol) & 0x0FFFFFFF

    out = []                                # Step3: %16 查表, /4
    while True:
        out.append(TABLE[n % 16])
        n //= 4
        if n == 0:
            break
    return "".join(out)

assert keygen("ReCrackMe", 0xA833742F, 0xDC171869) == "f85e4cccccca53"
print(keygen("ReCrackMe"))  # 在目标机运行，读取本机 C:/D: 卷序列号
```

## 变体与关联

- 变体：若程序只读取 `C:\` 单个卷序列号，则把 hypotenuse 退化为该值本身；若 `GetVolumeInformationA` 失败（无 D 盘/权限），失败分支常把序列号保留为 0，keygen 需按 0 复算或先确认程序实际取值。
- 变体：文章 C++ 注册机里 Step1 用 64 位累积后再折叠，汇编则是每轮折叠；对某些 Name 两者会不一致，PoC 按目标汇编逐轮折叠实现。
- 变体：不写 keygen，直接 NOP 掉 `lstrcmpA` 后的 `JNZ`（`75 18` → `90 90`），可绕过卷序列号绑定；但换机器/重打包后偏移可能变化，需重新定位。
- 关联：[[code-analysis-reverse-windows-keygenme-name-4byte-serial-keygen]]（同文另一例：Name→4 字节小端 Serial 的枚举式 keygen）、[[code-analysis-reverse-windows-winhex-license-crc32-keygen]]（商业程序注册算法与 keygen）、[[code-analysis-dynamic-debugging-crackme-password-check-patch]]（调试器改标志位/补丁绕过）、[[code-analysis-reverse-windows-qt-license-qlineedit-text-breakpoint]]（API 断点回溯注册码输入）。

## 检测与防御

- 检测：程序侧可检测调试器与下断（`IsDebuggerPresent`、PEB、硬件断点寄存器）、校验关键函数/表（如 `071362de9f8ab45c`）与比较跳转字节是否被改；授权服务端可要求 Serial 由服务端签发，避免客户端仅凭本机可读的卷序列号自算。
- 防御：不要把卷序列号等本机可读值当作唯一信任根；使用服务端验签/在线激活、非对称签名或硬件安全模块；对二进制做签名与完整性校验，提高 keygen/补丁成本。
- 说明：本文是 CrackMe 逆向学习场景，针对本地授权校验，severity 记为 low；仅用于授权的逆向分析。

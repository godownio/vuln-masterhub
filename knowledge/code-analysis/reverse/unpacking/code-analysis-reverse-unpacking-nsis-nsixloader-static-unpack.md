---
id: code-analysis-reverse-unpacking-nsis-nsixloader-static-unpack
title: NSIXloader（NSIS 恶意封包器）静态解包：7-Zip 提取 + DLL 密钥正则 + shellcode 逐字节运算模拟还原载荷
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: nsis-nsixloader-static-unpack
aliases:
- NSIXloader
- NSIS 恶意壳
- NSIS 静态解包
- NSIS 插件 DLL 解密
- shellcode 逐字节解密模拟
- Packer.Win.NSISCrypter
tags:
- reverse
- unpacking
- malware-analysis
- nsis
- shellcode
- xor
- rc4
- windows
- static-analysis
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:51:08+08:00'
  notes: 已对照 content.md 全文与图01-16核对：$PLUGINSDIR/rnthgfcoj.dll 与 pvynjhnv.oh 6026 字节（图02）、key=510501002024（图03/09）、ror al,3 + xor key（图05）、API 哈希 0x7FD6A366/0x7FE63623/0x7FB47ADD/0x7FE7F840（图06）、逐字节 not/xor/neg/add/sub 序列（图07/08）、C7 85/C6 85 内嵌 shellcode（图13/14）、RCDATA ID 993/Type 10 的 FindResourceW（图11）、RC4 栈 key 与 rc4+xor（图15/16）均与原文一致。未实际解包样本；原文为英文翻译，IOC 表未写入卡片属可接受取舍。
---

## 一句话结论

搭载 NSIXloader 的 NSIS 恶意样本可在不运行的情况下静态解包：用 7-Zip 解出 `$PLUGINSDIR` 中的恶意 DLL 与加密文件，按正则从 DLL 的 `.data/.rdata` 提取文本 XOR 密钥，尝试 8 种循环移位后 XOR 还原 shellcode；再反汇编 shellcode 中针对 EAX/ECX 的逐字节运算序列（`not/dec/inc/sar/shl/or/add/sub/neg/xor/movzx`），按字节模拟即可解密最终 payload（XLoader/Remcos/AgentTesla/Formbook 等）。

## 原理

- **NSIS 是可静态解压的自解压安装包**：NSIS 包内含压缩文件与 NSIS 脚本指令，7-Zip/7z 能识别 NSIS 格式并解压，无需执行安装程序。恶意软件作者利用这一点，让样本外观像合法安装程序，同时把解包/解密逻辑放进脚本和插件 DLL。
- **典型结构**：包根目录放两个加密二进制文件，`$PLUGINSDIR` 放一个导出函数的 DLL（原文样本 `rnthgfcoj.dll`）。NSIS 脚本用 `<DLL名>::<函数名>` 调用插件，例如：

```nsis
InstallDir $TEMP
Function .onGUIInit
    InitPluginsDir
    SetOutPath $INSTDIR
    SetOverwrite off
    File tiejkfis.yp
    File pvynjhnv.oh
    rnthgfcoj::HvDeclY
```

- **DLL 解密 shellcode**：DLL 读取较小的加密文件（文件名硬编码，原文 `pvynjhnv.oh`，6026 字节），用文本密钥做 XOR。密钥是 10–20 位小写字母/数字、以 NUL 结尾，位于 `.data` 或 `.rdata` 段开头，可用正则 `([a-z\d]{10,20})\x00` 提取（原文样本 `510501002024`）。部分变体在 XOR 前还会对每个字节做循环移位（如 `ror al, 3`）。
- **shellcode 解析 API**：解密后的 shellcode 是位置无关代码，不存 API 名称，而是存 4 字节哈希（原文样本 `LoadLibraryW=0x7FD6A366`、`CreateFileW=0x7FE63623`、`VirtualAlloc=0x7FB47ADD`、`ReadFile=0x7FE7F840` 等）；加载器解析 `kernel32.dll` 导出表，对每个导出名计算哈希并比对，取得函数地址。
- **payload 逐字节解密**：shellcode 读取另一个加密文件并按每个样本独有的运算序列逐字节变换。原文观察到的运算集中在 EAX/ECX，第二个操作数可以是寄存器、立即数或内存变量；内存操作数映射为 `b`（当前字节，`0xFF`）或 `i`（当前索引，`0xF8`），逐字节模拟这些指令即可还原 payload。
- **自动化解法**：7z 解包 → malduck `procmempe` 读段找 key → 对 8 种移位逐一 XOR 并用 shellcode 正则验证 → YARA/正则定位解密代码 → malduck 反汇编过滤 `op1 in (eax,ecx)` 且助记符在白名单的指令 → 生成操作列表 → 逐字节执行操作列表得到明文。
- **变体**：DLL 内嵌 shellcode（写入栈上数组，`C7 85 ...`/`C6 85 ...` 指令块）；用 EXE 代替 DLL（`ExecWait "$INSTDIR\pnmess.exe" $INSTDIR\xxx.ge"`）；shellcode 存在 `RT_RCDATA` 资源（`FindResourceW/LoadResource`）；payload 用 RC4（`System.dll` 调 `VirtualProtect` 0x40、`ReadFile` 后跳转），且是"RC4 后再与 RC4 key XOR"的变体。

## 触发条件

- 已获得 NSIS 封装的恶意样本，且允许在离线环境做授权分析（不运行样本）。
- 样本符合 NSIXloader 家族特征：`$PLUGINSDIR` 中存在导出函数的 DLL、根目录有加密二进制、NSIS 脚本在 `.onGUIInit/.onInit` 调用插件或 `System::Call`。
- 分析机有 7-Zip/7z、Python 与 malduck（以及 YARA/正则工具）；能反汇编 32 位 shellcode。
- 变体可能有自定义/修改的算法，自动化脚本需按样本调整。

## 利用步骤

1. `7z x sample.exe -oout` 解出 NSIS 内容；查看根目录加密文件与 `$PLUGINSDIR` 下的 DLL/EXE。
2. 对 DLL 用 PE 工具/`malduck.procmempe` 读取 `.data`、`.rdata` 段，按 `([a-z\d]{10,20})\x00` 提取候选 key（密钥通常在段首）。
3. 读取加密 shellcode 文件，对 shift=0..7 做 `(b >> shift) | (b << (8-shift))` 后再与 key 循环 XOR，用 shellcode 特征正则筛选正确 shift。
4. 将解密后的 shellcode 载入 IDA/Ghidra 或 malduck 反汇编，定位 API 哈希解析与 payload 解密循环；提取解密指令序列（过滤 EAX/ECX 操作数，映射 `0xFF→b`、`0xF8→i`）。
5. 按指令语义实现逐字节模拟：`eax=b; ecx=0; b=b; i=index;` 依次执行操作，输出 `eax` 即明文字节；对 `not/dec/inc/sar/shl/or/add/sub/neg/xor/movzx` 全部实现并保持 8 位截断。
6. 验证输出：明文应为 PE/Shellcode/配置；用 DIE/PEview 检查 `MZ`，或继续跟踪下一阶段。
7. 其他变体：DLL 内嵌 shellcode 用 `\xC7\x85(..\xFF\xFF)(.{4})...` 定位并提取；EXE 变体按 `ExecWait` 参数找加密文件；资源变体用 `FindResourceW` 的 ID/类型定位 `RT_RCDATA`；RC4 变体按 `rc4(key, data)` 后再 `xor(key, data)` 解密。

## PoC

```python
import re
from malduck import procmempe, procmem, xor

dll_key_re = re.compile(br"([a-z\d]{10,20})\x00")

def dll_extract_keys(dll_data):
    p = procmempe(dll_data)
    for section in filter(lambda s: b"data" in s.Name, p.pe.sections):
        data = p.readp(section.PointerToRawData, section.SizeOfRawData)
        for found in dll_key_re.finditer(data):
            yield found.group(1)

def decrypt_loader(data, dll_key):
    for shift in range(8):
        if shift:
            shifted = [((b >> shift) | (b << (8 - shift))) & 0xFF for b in data]
        else:
            shifted = data
        dec = xor(dll_key, shifted)
        if shellcode_validation_re.search(dec):
            return dec

mem_vars_map = {0xFF: "b", 0xF8: "i"}
ops = []
for ins in filter(
    lambda _ins: _ins.op1.value in ("eax", "ecx") and _ins.mnem in supported_instructions,
    procmem(data).disasmv(0, size=len(data))
):
    if not ins.op2:
        op2 = None
    elif ins.op2.is_reg or ins.op2.is_imm:
        op2 = ins.op2.value
    elif ins.op2.is_mem:
        op2 = mem_vars_map.get(ins.op2.value & 0xFF)
    else:
        continue
    ops.append(get_operation(ins.mnem, ins.op1.value, op2))

def decrypter(enc_data):
    dec_data = []
    for _i, _b in enumerate(enc_data):
        var_list["eax"] = _b
        var_list["ecx"] = 0
        var_list["b"] = _b
        var_list["i"] = _i
        for _op in ops:
            _op()
        dec_data.append(var_list["eax"])
    return bytes(dec_data)
```

```text
# 变体定位片段
# DLL 内嵌 shellcode：C7 85 <disp32> <imm32> ... 或 C6 85 <disp32> <imm8>
shellcode_block = re.search(b"\xC7\x85(..\xFF\xFF)(.{4})(\xC7(\x85..\xFF\xFF|\x45.)(.{4})){32,}.*\x8D..\\1", dll_data, re.DOTALL)
shellcode = b"".join(re.findall(b"\xC7(?:\x85..\xFF\xFF|\x45.)(.{4})", shellcode_block, re.DOTALL))

# RC4 变体
decrypted_data = rc4(rc4_key, enc_data)
decrypted_data = xor(rc4_key, decrypted_data)
```

说明：以上为原文简化版脚本，`get_operation`/`shellcode_validation_re`/`supported_instructions` 需补全；不同样本的 key 与解密指令序列不同，不能一套脚本通杀。

## 变体与关联

- 变体一：DLL 加载器 + shellcode 单独文件（主流）。
- 变体二：shellcode 内嵌在 DLL 的栈数组（`C7 85`/`C6 85` 指令块）。
- 变体三：EXE 代替 DLL，NSIS 用 `ExecWait` 把加密文件路径作为参数传入。
- 变体四：shellcode 存放在 `RT_RCDATA` 资源（`FindResourceW(hModule, ID, 10)`）。
- 变体五：payload 用 RC4（`System.dll` 调 `Alloc/VirtualProtect/ReadFile/GetCurrentProcess` 后跳转），且 RC4 后再 XOR key。
- 关联：[[code-analysis-reverse-unpacking-agenttesla-stage-dll-xor-subtract-archive]]（AgentTesla 阶段 DLL 的 XOR/压缩包还原）、[[code-analysis-reverse-unpacking-writeprocessmemory-memory-block-pe-carve]]（静态解不开时断点抓内存载荷）、[[code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation]]（用 Unicorn 模拟壳 stub 的另一模拟解包思路）。
- 边界：样本使用更强加密/每个样本不同的算法、key 运行时生成、或 shellcode 走 VM/混淆时，静态脚本需要按样本逆向；仅用于授权恶意软件分析。

## 检测与防御

- 检测：NSIS 样本中出现 `$PLUGINSDIR` 下的非标准 DLL、`File` + `<DLL>::<函数>` 调用、`.data/.rdata` 段首出现 10–20 位 `[a-z0-9]` 字符串；shellcode 中 API 哈希解析与逐字节运算循环；AV 命名可参考 `Packer.Win.NSISCrypter.*`、`Trojan.Win.Shellcode.F/G`。
- 防御：终端/邮件网关对 NSIS 自解压包做静态解包与信誉检查；监控 `$PLUGINSDIR` 插件加载、临时目录释放与后续 shellcode 行为；启用 AMSI/EDR 对内存中未签名代码与 `VirtualProtect 0x40` 的监控。
- 加固：限制普通用户执行自解压安装包；对下载的安装程序做数字签名校验；威胁情报侧维护 NSIXloader 家族 YARA 与样本哈希库。

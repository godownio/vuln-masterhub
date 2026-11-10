---
id: code-analysis-reverse-firmware-zkteco-updatepackage-xor-keysize-decrypt
title: ZKTeco 固件更新包静态还原：DataX 十六进制转字节 + zkfp_ExtractPackage 以包尾/包长派生 XOR 密钥解密
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: zkteco-updatepackage-xor-keysize-decrypt
tags:
- reverse
- firmware
- unpacking
- zkteco
- xor
- update-package
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V322
  verified_at: '2026-11-08T15:55:20+08:00'
  notes: 已对照 img17-28 与原文核对 DataX 十六进制、zkfp_ExtractPackage 0x1a88、key 由包尾/包长派生、key[i%20] XOR 与 0x1F88 包头修补；PoC 为结构化伪代码，未复跑。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-zkteco-updatepackage-xor-keysize-decrypt/
draft: false
kb_aliases:
- zkfp_ExtractPackage
- ZKTeco 固件解密
- DataX 固件转换
- FirmwareData
- libdlcl.so
- 固件更新包 XOR
---

## 一句话结论

ZKTeco 生物识别终端的固件更新包不是标准压缩包：分发文件是含 `[Upgrade]`/`[FirmwareData]` 的文本，其中 `DataX=` 行是固件字节的十六进制；转成字节后仍是密文。设备端 `standalonecomm` 调用 `libdlcl.so` 的 `zkfp_ExtractPackage` 解密，密钥由更新包尾部数据与包大小派生，按字节循环 XOR 并修补头部后，才能得到可 `tar xzvf` 解包的服务/库/配置。

## 原理

- **分发格式**：更新目录中的文本文件包含 `FWVersion`、`FirmwareLength=72600039`、`FirmwareProtype=push`、`FirmwareCheckSum` 等字段；`[FirmwareData]` 段以 `Data0=1B55E57F...` 的形式给出十六进制文本。把每个 `DataX` 的十六进制串按字节拼接即得到固件二进制；原文用十六进制编辑器查看 `fw.bin` 发现高熵、不可直接识别，说明仍被加密。
- **调用链**：`standalonecomm` 处理固件更新命令时调用外部函数 `zkfp_ExtractPackage((int)UpdateFileBuffer, 0, UdiskLength)`，该符号在 `libdlcl.so` 中导出（`readelf -s` 可在 0x1a88 找到），头文件声明为 `int zkfp_ExtractPackage(char *Package, char *Data, int *DataLen);`。
- **密钥派生**：原文反编译 `zkfp_ExtractPackage` 可见其把包大小写入 key 数组（`*(_DWORD *)&key[16] = PackageSize`），对 key 前 10 字节做一次带索引的混合（`tmp1 = *v11 ^ idx2; tmp2 = key[idx2++]; *pKey = (tmp1 + tmp1 % 0xF) ^ tmp2`），然后从偏移 2 起逐字节 `Package[i] ^= key[i % 20]`；原文文字概括为"密钥由更新文件最后 16 个字节和文件大小组成"。解密后函数还会修补包头的 `0x1F 0x88` 与 key 相关字段。
- **为什么需要静态还原**：更新包只包含部分可执行文件/库/配置（部分更新），设备端解密后再 `tar xzvf`；分析者若只拿文本包，必须先复现 `zkfp_ExtractPackage` 才能看到 `service/standalonecomm`、`lib/libzkdbpushconvert.so`、`lib/libcjson.1.0.so` 等文件并继续逆向。
- **另一条路**：直接从 eMMC 读全盘固件可绕过更新包加密，见关联卡；但更新包分析成本更低，且能拿到特定版本的 `standalonecomm` 与服务配置。

## 触发条件

- 已获得 ZKTeco 固件更新包（厂商/分销商下载，或从设备更新缓存/流量中提取），且允许离线分析。
- 能与设备固件版本对应，或至少拿到 `libdlcl.so`/`standalonecomm` 用于核对 `zkfp_ExtractPackage` 实现。
- 分析机有十六进制/文本处理脚本、`readelf`、IDA/Ghidra、`tar`/binwalk。

## 利用步骤

1. 打开更新文本，读取 `FirmwareLength`、`FirmwareCheckSum`，把所有 `DataX=` 的十六进制串按出现顺序拼成一个字节串，得到 `fw.bin`。
2. 用 `file`/binwalk/熵分析确认其为密文；从更新包或固件中取 `libdlcl.so`，`readelf -s libdlcl.so | grep zkfp_ExtractPackage` 确认符号存在。
3. 在 IDA/Ghidra 中定位 `zkfp_ExtractPackage`，还原 key 数组的初始化（包尾 16 字节/包头字段）与 key schedule，确认 XOR 的起始偏移与 `key[i % 20]` 的循环周期。
4. 按反编译逻辑实现解密：复制包字节、构造 20 字节 key、执行 key schedule、从偏移 2 起逐字节 XOR、修补头部字段。
5. 校验输出：`file` 识别为 `tar`/ELF/配置；`tar xzvf` 解出 `service/standalonecomm`、`lib/*.so`、`data/*.xml` 等。
6. 对解出的 `standalonecomm` 继续做 4370/TCP 协议命令处理器逆向（见关联卡）。

## PoC

```python
# 伪代码：按原文反编译结构复现，具体 key 初始化字段需按目标版本调整
def decrypt_update_package(pkg: bytearray) -> bytes:
    size = len(pkg)
    key = bytearray(20)
    # 原文文字：密钥由更新文件最后 16 个字节和文件大小组成
    key[0:16] = pkg[-16:]
    key[16:20] = size.to_bytes(4, "little")
    # key schedule（原文反编译片段）
    v11 = 19
    idx = 0
    while idx < 10:
        tmp1 = key[v11] ^ idx
        tmp2 = key[idx]
        key[idx] = ((tmp1 + tmp1 % 0xF) ^ tmp2) & 0xFF
        idx += 1
        v11 -= 1
    out = bytearray(pkg)
    for i in range(2, size):
        out[i] ^= key[i % 20]
    out[0] = 0x1F
    out[1] = 0x88
    return bytes(out)
```

```text
# 提取 DataX 十六进制（示意）
grep '^Data[0-9]*=' update.txt | cut -d= -f2 | tr -d '\n' | xxd -r -p > fw.bin
# 解密后
file fw.bin && tar xzvf fw.bin -C out/
```

说明：原文的 key 初始化/包头修补未完整列出，PoC 为按反编译片段的结构化伪代码，confidence 记为 medium；不同固件版本可能改 key 布局。

## 变体与关联

- 变体：部分更新包只含少数文件；不同版本可能改 key 周期、包头字段或压缩方式，需重新反编译 `libdlcl.so`。
- 变体：从设备更新流量中截获同样的文本包，或直接从 eMMC 读全盘固件绕过。
- 关联：[[iot-hardware-zkteco-emmc-dump-binwalk-shadow-ssh]]（eMMC 全盘固件提取）、[[iot-protocol-zkteco-standalonecomm-download-picture-path-traversal]]（解出 `standalonecomm` 后的协议漏洞）、[[code-analysis-reverse-firmware-aes-ecb-key-xor-header-decrypt]]（其他固件 XOR/头部解密的对比）。
- 边界：更新包使用非 XOR 的更强加密、key 运行时生成或固件签名校验时，静态还原需要更多逆向或走设备端解密。

## 检测与防御

- 检测：设备/网络中传输 `[FirmwareData] DataX=` 文本更新包；`standalonecomm` 调用 `zkfp_ExtractPackage` 解密后执行 `tar xzvf`；固件更新来源非官方/无签名。
- 防御：固件更新包使用签名与强加密，设备端验签后再解密；不要使用可逆 XOR/固定派生 key。
- 加固：限制固件更新入口（4370 命令、U 盘、云服务）的认证与来源；保护 `libdlcl.so` 与更新包不被离线分析（仅提高门槛，不替代加密签名）。

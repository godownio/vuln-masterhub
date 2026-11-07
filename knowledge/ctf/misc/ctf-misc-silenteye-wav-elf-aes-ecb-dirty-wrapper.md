---
id: ctf-misc-silenteye-wav-elf-aes-ecb-dirty-wrapper
title: JPEG SilentEye + WAV 内嵌 ELF + AES-128-ECB 脏串包裹：多层 Misc 提取与解密
type: scenario
domain: ctf
path: ctf/misc
technique: silenteye-wav-elf-aes-ecb-dirty-wrapper
aliases:
- SilentEye JPEG 隐写
- WAV 内嵌 ELF
- 音频多格式文件
- AES-ECB 前后脏串
- EVP_aes_128_ecb 密钥截断
- 多层 Misc 题
tags:
- ctf
- misc
- stego
- silenteye
- jpeg
- wav
- elf
- aes-ecb
- base64
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V182
  verified_at: '2026-11-06T20:13:46+08:00'
  notes: 已对照原文核对（含11张图片）；未运行附件；SilentEye 隐写、WAV 提取 ELF、EVP_aes_128_ecb 取前16字节 ASCII key、脏串与 flag 均有图文印证
---

## 一句话结论

题目把密钥藏在 JPEG 的 SilentEye 隐写里、把加密程序藏在 WAV 音频里；从 WAV 提取出的 ELF 用 OpenSSL `EVP_aes_128_ecb()` 加密一段文本，并在输出前后拼接 `VeHb8c2b4` 与 `e2HmCvW10` 两个脏串。按“SilentEye 取密钥 → WAV 提取 ELF → 逆向确认 AES-128-ECB 与密钥 → 去掉脏串、base64 解码、ECB 解密”即可拿到 flag。

## 原理

### JPEG：SilentEye 取隐藏消息

- SilentEye 是一款把数据嵌入图片（JPEG/PNG/BMP）的隐写工具，支持设置亮度间隔（luminance interval）、头部位置（top/bottom）、可选的 passphrase，并可选择压缩/加密。
- 题目 JPEG 在 SilentEye 中用对应参数解码，得到字符串 `JnzJcwoi23nDmx`；该字符串可能是后续步骤的线索/口令（案例中用于提示或作为中间密钥，最终 AES key 来自 ELF 内的硬编码）。
- 识别方法：`file`/`exiftool`/`binwalk` 看图片结构；用 SilentEye 或 `steghide`/`outguess` 尝试常见隐写；注意 JPEG 的量化表/LSB 异常。

### WAV：音频中内嵌 ELF

- WAV 是容器格式，`RIFF` 块之后可以附加任意数据；题目在音频数据后/块间隙嵌入了一个 ELF 可执行文件，属于“polyglot/多格式文件”。
- 用 `binwalk -e`、`foremost`、`dd` 按偏移提取，或用 `Audacity` 查看波形/频谱寻找异常段；提取后用 `file` 确认 ELF、`checksec` 看保护。
- ELF 是加密器：`asoutput()` 先 `printf("VeHb8c2b4")`，调用 `asenc()` 加密一段长文本，最后 `printf("e2HmCvW10")`；所以最终密文文本两端各有一段随机脏串。

### ELF：AES-128-ECB 与密钥长度陷阱

- IDA 反编译 `asenc(char *a1)`：
  ```c
  strcpy(v8, "2e9a4dcb55be306bdb136d86b8e6ee82");
  v13 = EVP_CIPHER_CTX_new();
  v7 = strlen(a1) + 1;
  EVP_EncryptInit_ex(v13, EVP_aes_128_ecb(), 0, v8, 0);
  EVP_EncryptUpdate(v13, ptr, &v6, a1, v7);
  EVP_EncryptFinal_ex(v13, (char *)ptr + v6, &v7);
  // 再用 BIO_f_base64 输出
  ```
- `EVP_aes_128_ecb()` 只使用 **128-bit（16 字节）** 密钥；虽然 `v8` 是 32 个十六进制字符的字符串，OpenSSL 只读取前 16 个字节（ASCII 字符 `2e9a4dcb55be306b`），不是把 32 个 hex 字符解码成 16 字节。CyberChef 中 Key 选 UTF8、填 `2e9a4dcb55be306b` 即可。
- `strlen(a1)+1` 把结尾的 NUL 也加密进去，所以解密结果末尾可能带 `\x00`；明文本身还包含题目作者写的多行“废话”，flag 在其中一行。
- Base64 输出由 OpenSSL BIO 生成，可能带换行；去脏串后要先去空白/换行再解码。

### 去脏串与解密

- 完整输出形如 `VeHb8c2b4<base64>e2HmCvW10`；两个脏串是 `asoutput()` 单独 `printf` 的，不属于 base64 内容。
- 去掉前缀/后缀后 base64 解码，得到 AES-128-ECB 密文；用 `b"2e9a4dcb55be306b"` 解密，再按 UTF-8 解码/按行查找 flag。
- 如果先 base64 解码再删脏串会失败；必须在 base64 解码前剥离脏串。

## 触发条件

- 题目提供 JPEG/WAV 等多媒体文件，且文件尾/块间隙存在额外数据或 LSB 异常。
- JPEG 使用 SilentEye（或同类工具）隐藏了消息，且参数/口令可猜或题目给出。
- WAV 是 polyglot，内嵌 ELF/PE 等可执行文件；提取后可静态分析。
- 加密程序使用标准库（OpenSSL）且密钥/模式硬编码；密文有可识别的 base64 字母表与前后脏串。
- 攻击者能运行 SilentEye、binwalk/foremost、IDA/Ghidra、Python 加密库。

## 利用步骤

1. 对 JPEG 做 `file`/`exiftool`/`binwalk`，用 SilentEye 以默认/题目参数解码，得到隐藏消息（案例 `JnzJcwoi23nDmx`）。
2. 对 WAV 做 `binwalk -e`/`foremost`/`dd`，提取尾部或块间的 ELF；`file`/`checksec` 确认。
3. 用 IDA/Ghidra 打开 ELF，定位入口与 `asoutput`/`asenc`；记录 AES 模式、密钥字符串、是否包含 `strlen+1`、base64 封装与脏串。
4. 从题目输出/附件中取出完整密文，按脏串前缀/后缀剥离；去除 base64 中的换行/空白。
5. base64 解码得到密文；用 `EVP_aes_128_ecb` 对应的 16 字节 ASCII 密钥做 AES-ECB 解密。
6. 解码明文（忽略 `\x00` 与废话行），提取 flag；用 CyberChef 复核（From Base64 → AES Decrypt ECB/UTF8 key）。

## PoC

```python
from base64 import b64decode
from Crypto.Cipher import AES

raw = open("cipher.txt", "r", encoding="utf-8").read().strip()
raw = raw.removeprefix("VeHb8c2b4").removesuffix("e2HmCvW10")
raw = "".join(raw.split())              # 去掉 base64 中的换行/空白
ct = b64decode(raw)

key = b"2e9a4dcb55be306b"               # ELF 中 32 字符密钥的前 16 个 ASCII 字节
pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
print(pt.decode("utf-8", "ignore"))
```

案例明文中的 flag 为 `DASCTF{23w89c2n2g-8cr57t6bv92-213vf3vb9-13cyn23vb}`。

## 变体与关联

- **SilentEye 参数**：亮度间隔、header position（top/bottom）、passphrase、是否 compressed/encrypted 都会影响解码；逐个尝试或用题目提示。
- **其他音频隐写**：DeepSound、steghide、频谱图、LSB、Morse/FSK；`ctf/forensics` 下已有 DeepSound/音频频谱等卡。
- **其他多格式文件**：JPEG+ZIP、PNG+ELF、WAV+PE、PDF+ZIP；用 `binwalk`/`foremost`/`file` 逐层剥离。
- **AES 密钥长度陷阱**：`EVP_aes_128_ecb` 只读 16 字节；`EVP_aes_256_ecb` 读 32 字节；字符串形式的“hex 密钥”常被误当二进制 hex 解码。看到 32 个 hex 字符时，先确认代码用的是 ASCII 字符串还是 `bytes.fromhex`。
- **前后脏串**：除 `printf` 拼接外，还可能用固定 magic、随机长度、多段拼接；先定位 base64 字母表，再剥离非字母表字符。
- **关联：AES-ECB 块特征**：ECB 相同明文块产生相同密文块；可用于确认模式、识别重复块，但不能直接恢复密钥。

## 检测与防御（CTF/取证视角）

- **文件识别**：不要只看扩展名；`file`、`binwalk`、`trID`、`exiftool` 交叉验证；对“图片/音频”检查尾部追加数据与块结构异常。
- **隐写检测**：JPEG 量化表/LSB、PNG IDAT 异常、WAV 数据块后的高熵段；SilentEye/steghide/outguess 逐个尝试。
- **逆向确认算法**：不要凭密文长度猜 AES 模式；在二进制中找 `EVP_*`、`AES_*`、密钥字符串、base64 BIO，确认 key 长度与 padding。
- **解密顺序**：先剥外层脏串/编码，再解密；每层用 `file`/magic/长度校验，避免把脏串当密文。
- **防御/设计**：不要把密钥硬编码在可执行文件中；使用 KDF/密钥管理；对敏感数据使用认证加密（AES-GCM）而非 ECB；但 CTF 中这些正是可攻击点。

---
id: code-analysis-reverse-des-3des-identification-decrypt
title: DES/3DES 逆向识别与解密：8 个 S 盒/IP/PC 表与 OpenSSL DES_* API 指纹、key 派生陷阱、ECB/CBC 试解与 3DES EDE 组合
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: des-3des-identification-key-recovery-decrypt
tags:
- reverse-engineering
- crypto
- des
- 3des
- openssl
- findcrypt
- ecb
- cbc
- key-schedule
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V681
  verified_at: '2026-11-13T14:01:53+08:00'
  notes: 已对照原文与19张图核对：图01-04 DES 流程/两轮 Feistel/E 表/加解密结构；图05 babyre FindCrypt 命中 AES；图06 栈上真实 key AD 52 F2 4C E3 2C 20 D6；图07/08 3DES EDE 加解密示意；图09-15 AES 阶段、SMC 方程 (xmmword_405018[esi*4]+edi)^(esi+eax)、rdtsc、OD 中 WriteProcessMemory 与 0x60 字节补丁；图16(OD)/17 IDA 调试；图18/19 3DES 工具（ECB/pkcs7，key 框被裁显示 AFSAFCEDYCXCX…，密文 507C…A4E8，结果 0dcc509a6f75849b）。主要修正：1) DES PoC 密文 hex 漏写 E0 字节（15 字节，会抛对齐异常），已改为 byte_6040C0 的完整 16 字节 0af4eec8428a9bdba2266feeeee0d8a2，并实测 ECB 前8字节 th1s1sth + CBC 后8字节 3n1c3k3y 拼出 th1s1sth3n1c3k3y；2) 3DES key 长度结论修正——原文贴出的 MakeKey 片段看似只 memcpy 16 字节，但实测 24 字节 AFSAFCEDYCXCXACNDFKDCQXC 按 DES-EDE3 ECB 才能解出 0dcc509a6f75849b+PKCS7(0x08)，前16字节解出乱码，故删除原“16 字节双密钥”表述与 PoC，改为 24 字节并在正文说明原文片段不完整、须以实际调用验证。原文未标注组件版本，未设 affected_versions；severity low 合理。dedup 推荐 new，候选为 AES/通用加密识别/移动端 3DES，非同一链；dup-scan 无本卡 pair。3DES/工具输出已本机复算验证，其余 PoC 未复跑。
url: /docs/code-analysis/reverse/code-analysis-reverse-des-3des-identification-decrypt/
draft: false
kb_aliases:
- DES 逆向
- 3DES 逆向
- DES_string_to_key
- DES_set_key_checked
- DES_ncbc_encrypt
- DESede
- 3DES EDE
- FindCrypt DES
---

## 一句话结论

在二进制中命中 8 组 `4×16` S 盒、IP/IP⁻¹/PC1/PC2/E/P 置换表或导入 `DES_string_to_key`/`DES_set_key_checked`/`DES_ncbc_encrypt`/`DES_ede*` 等 OpenSSL API 即可判定 DES/3DES；还原时要意识到 DES 的 key 未必是字面字符串（`DES_string_to_key` 会派生、`DES_set_key_checked` 会校验奇偶/弱密钥），需从寄存器或内存 dump 取真实 8 字节，并对同一密文分别按 ECB/CBC 试解；3DES 按 EDE 用 k1/k2/k3（常见 k3=k1 双密钥）逆序解密；若校验函数被 SMC/rdtsc 保护，则动调到 `WriteProcessMemory` 打补丁后 dump 真实代码再分析。

## 原理

- **DES 结构指纹**：64 位分组、64 位密钥（56 位有效 + 8 位奇偶校验）；加密为 IP → 16 轮 Feistel（E 扩展 32→48、与 48 位子密钥异或、8 个 S 盒各 6→4 位、P 置换 32→32、与 L 异或）→ FP（IP⁻¹）。密钥编排 PC1（64→56）→ 左右 28 位循环左移（移位表 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1）→ PC2（56→48）。
- **常量/表识别**：`S_Box[8][4][16]` 的 S1 首行 `14,4,13,1,2,15,11,8...`、IP 表 `58,50,42,34,26,18,10,2...`、IP⁻¹ `40,8,48,16...`、PC1 `57,49,41,33,25,17,9...`、PC2 `14,17,11,24,1,5...`、E 表 `32,1,2,3,4,5,4,5...`、P 表 `16,7,20,21...` 任一命中即可定位；IDA FindCrypt 插件对 DES 表也有签名。
- **OpenSSL API 识别**：导入 `DES_string_to_key`、`DES_set_key_checked`、`DES_set_key`、`DES_ncbc_encrypt`、`DES_ecb_encrypt`、`DES_ede3_cbc_encrypt` 等即可确认；`DES_string_to_key(str, key_out)` 把任意字符串扩展/折叠成 8 字节 key（不是直接截断），`DES_set_key_checked` 会拒绝奇偶校验错误或弱密钥并返回非零，程序通常在返回值非零时走失败分支。
- **key 陷阱（实例）**：羊城杯 babyre 的反编译看起来是 `DES_string_to_key("this is my key", v6)`，但 `v6` 不是最终 key；原文在 `DES_set_key_checked` 前断点，从寄存器/栈读到真实 8 字节 key `AD 52 F2 4C E3 2C 20 D6`。仅按字面字符串解密会失败。
- **模式/IV 陷阱（实例）**：反编译显示 `memset(v7,0,8)` 后 `DES_ncbc_encrypt(s, v9, 60, key_schedule, v7, 1)`，IV 为 8 字节零；原文对同一密文分别用 ECB 与 CBC（Python 里以 key 作 IV）解密，把可用结果拼接得到 16 字节输入。实际应以函数参数中的 IV/模式为准，同时试 ECB/CBC，用可打印字符/`flag{` 之类已知格式验证。
- **3DES（DESede）**：加密 `C = E_k3(D_k2(E_k1(M)))`，解密按 `D_k1(E_k2(D_k3(C)))`；密钥长度 168 位（3×56），常见双密钥 `k1=k3`（DES-EDE2，16 字节 key 材料）；三密钥都相同时退化为单 DES。程序里可看到同一块数据连续调用 3 次 DES（`DES(Out,In,k1,enc)` → `DES(Out,Out,k2,dec)` → `DES(Out,Out,k1,enc)`），或调用 `DES_ede3_*`。
- **key 材料长度陷阱（实例）**：强网杯 just re 的 3DES 包装 `MakeKey` 原文片段为 `memset(deskey,0,16); memcpy(deskey, Key, len>16?16:len); MakeSubKey(&SubKey[1], &deskey[8]);`，静态看像只取前 16 字节且只给一个子密钥表赋值；但原文实际用在线 3DES 工具以完整 24 字符 `AFSAFCEDYCXCXACNDFKDCQXC` 作 key 才解出 `0dcc509a6f75849b`。核对结论：密文 `507C...A4E8` 用 24 字节 key 按 DES-EDE3 ECB 解出 ASCII `0dcc509a6f75849b` + 8 字节 PKCS#7 填充；改用前 16 字节 `AFSAFCEDYCXCXACN` 解出的是乱码，说明原文贴出的 MakeKey 片段不完整（静态阅读会误判），3DES key 长度必须以实际调用/工具结果验证，不能只看 `memset` 长度。
- **SMC/反调试配套**：just re 在主函数校验通过后用 `WriteProcessMemory(GetCurrentProcess(), sub_4018A0, &xmmword_405018, 0x60, 0)` 把计算出的 96 字节写入 `sub_4018A0`，下一次调用才执行真实校验体；同时用 `__rdtsc` 计算耗时，超过 `0xFFFFFF` 就写 0 使程序崩溃。绕过：在写入后/调用前断点，NOP 掉 rdtsc 与异常的写检查，运行到 `retn`，用 OD/x64dbg dump 出被补丁的函数体再反编译。
- **配套约束求解**：just re 的输入校验是 8 个 32 位方程 `(a[i] + y*0x1010101) ^ (i+0x10+x) == b[i]`，用 z3 解出 `y=0x25, x=0x13242208`，组合成前 10 个十六进制字符 `1324220819`，再与 3DES 解出的后半段拼接。

## 触发条件

- 二进制/样本中存在 DES/3DES 表、常量或 OpenSSL DES API 导入，输入经过变换后与固定密文比较。
- 密钥硬编码、字符串派生或在运行时计算，且可从寄存器/内存取得。
- 模式/IV/密钥材料长度不明确，需要试解（ECB/CBC、16/24 字节 3DES key、奇偶校验）。
- 校验函数可能被 SMC（WriteProcessMemory/VirtualProtect/mprotect）或 rdtsc 等反调试保护，需要动态调试还原。

## 利用步骤

1. 用 FindCrypt 或手工搜索 DES 表/常量，结合导入表定位 `DES_*`/`DES_ede*`，确认是单 DES 还是 3DES（数密钥编排次数/EDE 调用次数）。
2. 在 `DES_set_key_checked`/`DES_set_key` 入口或调用前断点，dump 真实 8 字节 key 与 key_schedule；不要直接采信字符串常量，`DES_string_to_key` 的输出需从内存读取。
3. 确认模式与 IV：查看 `DES_ncbc_encrypt` 参数（输入、输出、长度、key_schedule、IV、enc 标志）；对同一密文分别尝试 ECB 与 CBC，取可打印结果。
4. 3DES 场景确认 key 材料：16 字节（k1=k3）或 24 字节（k1/k2/k3）；不要只信静态 `memset`/`memcpy` 长度，以实际调用与试解结果验证，再用 PyCryptodome `DES3.new(key, mode, iv)` 解密。
5. 若校验函数明显不可静态分析/运行时被改写，定位 `WriteProcessMemory`/`VirtualProtect`/`mprotect` 调用，在补丁完成后下断、NOP `rdtsc` 与失败写检查，运行到返回前 dump 代码段。
6. 将各阶段结果串起来：例如 DES 输出作为下一阶段 AES 的 key，3DES 解出的后半段与 z3 解出的前半段拼接成 flag；用已知格式验证。

## PoC

单 DES（羊城杯 babyre 形态）：

```python
from Crypto.Cipher import DES
key = bytes.fromhex('AD52F24CE32C20D6')          # 断点从寄存器/栈读到，非字面字符串
ct  = bytes.fromhex('0af4eec8428a9bdba2266feeeee0d8a2')   # = byte_6040C0 的 16 字节
print(DES.new(key, DES.MODE_ECB).decrypt(ct))   # 前 8 字节 th1s1sth，后 8 字节乱码
print(DES.new(key, DES.MODE_CBC, key).decrypt(ct))   # 前 8 字节乱码，后 8 字节 3n1c3k3y
# 原文以 key 作 IV 试解，实际以程序 IV 参数为准；取 ECB 前 8 字节 + CBC 后 8 字节拼出 th1s1sth3n1c3k3y
```

3DES（强网杯 just re 形态，24 字节三密钥）：

```python
from Crypto.Cipher import DES3
key = b'AFSAFCEDYCXCXACNDFKDCQXC'   # 24 字节 DES-EDE3；原文工具用完整字符串，实测可解
ct  = bytes.fromhex('507CA9E68709CEFA20D50DCF90BB976C9090F6B07BA6A4E8')
pt  = DES3.new(key, DES3.MODE_ECB).decrypt(ct)
print(pt)   # b'0dcc509a6f75849b' + 8 字节 PKCS#7 填充(0x08)
# 用前 16 字节 AFSAFCEDYCXCXACN 按双密钥解出的是乱码，不能当 k1||k2
```

SMC 绕过（just re）：

```text
1) main 的 if (sub_401610(&input) && sub_4018A0(&input)) 处断点，输入占位长度
2) 进入 sub_401610 循环，NOP 掉 __rdtsc 与超时写 0 的检查
3) 运行到 WriteProcessMemory 之后、sub_4018A0 调用之前
4) 在 sub_4018A0 的 retn 处 F4，OD  dump 被补丁的 96 字节代码
```

## 变体与关联

- **通用加密识别**：算法常量/S 盒/轮数识别的总览见 [[code-analysis-reverse-crypto-encoding-identification-decrypt]]；本卡补充 DES/3DES 的 OpenSSL API、key 派生/长度与 ECB/CBC 试解细节。
- **SMC 与反调试**：两层 SMC + 改 eax 绕反调试 + NOP 花指令见 [[ctf-reverse-double-layer-smc-antidebug-junk-tea-key-xor-caesar]]；RWX 页自解密代码块见 [[ctf-reverse-elf-rwx-selfdecrypt-staged-transform]]；`WriteProcessMemory` 运行时补丁属于同类自修改代码手法。
- **3DES 其他案例**：[[code-analysis-reverse-obfuscation-3des-192-ecb-key-from-username-zero-padded]]（3DES-192 ECB key 由用户名零填充）、[[code-analysis-reverse-firmware-audiocodes-hardcoded-des3-password-decrypt]]（固件硬编码 3DES key）。
- **约束求解**：z3 解混淆校验方程见 [[ctf-reverse-htc-matrix-permutation-xor-conditional-breakpoint-z3]]。

## 检测与防御

- **逆向侧检测**：FindCrypt 命中 DES 表/常量、导入 `DES_*`/`DES_ede*`、出现 8 个 64 项 S 盒、PC1/PC2 移位表、连续三次 DES 调用、`__rdtsc` 与 `WriteProcessMemory` 组合，都是 DES/3DES + SMC 的强特征。
- **防护侧**：不要硬编码或可逆派生密钥；优先使用 AES-GCM 等现代 AEAD；必须兼容 DES/3DES 时使用 3DES 三密钥并限制数据量；对密钥做运行时保护与完整性校验，避免仅靠 `DES_string_to_key` 混淆。
- **研究注意**：DES/3DES 已不安全，仅用于遗留系统兼容与 CTF/逆向分析；本卡只描述识别与解密方法，不涉及攻击真实业务系统。

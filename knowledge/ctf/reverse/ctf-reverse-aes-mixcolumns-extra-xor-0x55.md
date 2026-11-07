---
id: ctf-reverse-aes-mixcolumns-extra-xor-0x55
title: 魔改 AES 逆向：差分定位 MixColumns 额外异或 0x55，改标准 AES 写注册机
type: scenario
domain: ctf
path: ctf/reverse
technique: aes-mixcolumns-extra-xor-0x55
aliases:
- CrackMe
- 魔改 AES
- MixColumns 0x55
- AES 差分调试
- 注册机
- 自定义 AES
tags:
- ctf
- reverse
- aes
- mixcolumns
- differential-debugging
- keygen
- custom-crypto
- qt
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:17:07+08:00'
  notes: 已对照原文与图03-08核对；MD5_Custom+Showmaker11、MixColumns额外异或0x55、注册机4ac06ab6f14dfc1bbfa65d00c9cd012b均一致；domain修正为ctf；PoC未复跑
---

## 一句话结论

目标用 `MD5_Custom(username)` 作 AES 密钥、`MD5_Custom(username+"Showmaker11")` 作密文，校验用户输入的 Password（32 个十六进制字符 → 16 字节）经魔改 AES 加密后是否等于该密文。AES 的 Sbox 是标准值，但 MixColumns 在标准公式结果上额外异或了 `0x55`；通过把程序内部密文/密钥同步到标准 AES 代码、逐步下断对比，哪一步开始不一致就是修改点。修改标准 AES 的 MixColumns 后即可写注册机，对任意用户名生成合法 Password。

## 原理

- **输入与流程**：用户名通过 `MD5_Custom` 得到 16 字节 Key；`username+"Showmaker11"` 再 `MD5_Custom` 得到 16 字节 Cipher；界面要求 Password 是 32 个十六进制字符（`unhex` 后 16 字节），`AES_Custom(Password, Key)` 的结果必须等于 Cipher。因此解密方向是 `Password_bytes = AES_Decrypt_Modified(Cipher, Key)`，再把 16 字节转 hex 得到 Password。
- **魔改定位**：作者先确认 Sbox 未被修改（提取的表与标准 AES 一致）；然后把程序里的 Key/Cipher 复制到标准 AES 实现，逐步（SubBytes/ShiftRows/MixColumns/AddRoundKey）对比中间状态。发现数据在 MixColumns 处开始对不上，进一步对比标准代码，看到程序多异或了 `0x55`。
- **为什么只改 MixColumns 仍可逆**：MixColumns 是线性变换，额外 XOR 常数 `0x55` 仍是可逆的（XOR 是自逆）；解密时在逆 MixColumns 后同样异或 `0x55` 即可。SubBytes/ShiftRows/AddRoundKey 未变，所以整体仍可加解密。
- **注册机**：调用程序自带的 `MD5_Custom`（libcrypto 的 `sign` 导出）得到 Key/Cipher；用修改后的标准 AES 解密（逆 MixColumns 后 XOR 0x55），得到 16 字节 Password；hex 编码提交即可。
- **为什么用差分调试**：直接读混淆/打乱的 AES 代码很难；把已知输入喂给程序，在每轮关键步骤后对比标准实现的中间值，能快速把“哪一步开始不同”缩小到一个变换，再读该处代码找具体修改。
- **原文输出**：用户名 `inkey` 对应 Password `4ac06ab6f14dfc1bbfa65d00c9cd012b`；把网页上的用户名批量跑注册机即可。

## 触发条件

- 目标使用 AES/TEA 等标准分组密码，但某轮函数/常量被修改（Sbox、MixColumns、轮密钥、字节序等）。
- 程序保留可调用的标准密码库（如 libcrypto 的 MD5/AES）或可提取 Sbox/密钥/密文；有调试能力。
- 输入/输出格式明确（Password 为 hex、AES-128、16 字节块），可验证解密结果。
- 修改点是可逆的（XOR 常数、线性变换、Sbox 置换等）；若是单向/丢失信息的修改，需爆破或逆向更多。
- 有标准实现可做对照（OpenSSL/自写 AES），能把程序中间状态与标准状态逐轮比较。

## 利用步骤

1. 字符串/交叉引用定位核心校验函数；确认 `Password` 的正则与 `unhex` 后长度 16。
2. 确认 `MD5_Custom(username)` 作 Key、`MD5_Custom(username+"Showmaker11")` 作 Cipher，`AES_Custom(Password, Key) == Cipher`。
3. 提取程序 AES 的 Sbox，与标准 AES Sbox 对比；若一致，继续对比轮函数。
4. 用已知 Key/Cipher 在标准 AES 实现中加密/解密，在 SubBytes/ShiftRows/MixColumns/AddRoundKey 后下断，记录程序与标准实现的中间状态；找到第一处不一致。
5. 读该处反汇编/伪代码，确认修改（原文 MixColumns 结果额外 `^ 0x55`）。
6. 修改标准 AES 的对应步骤（加密/解密方向都要改），用程序输出验证：对同一输入，修改后的实现结果应等于程序结果。
7. 写注册机：对任意 username 计算 Key/Cipher，解密得到 Password 字节，hex 输出提交。

## PoC

```cpp
#include <iostream>
#include <windows.h>
#include <string>
#include "AES.h"

std::string GetPassword(std::string UserName) {
    auto hLibCrypto = LoadLibraryA("libcrypto_.dll");
    DWORD* (*MD5_)(const char*, int, uint8_t*, int) =
        (DWORD*(*)(const char*, int, uint8_t*, int))GetProcAddress(hLibCrypto, "sign");
    uint8_t Key[16]{}, Cipher[16]{};
    MD5_(UserName.c_str(), UserName.length(), Key, 16);
    auto Str1 = UserName + "Showmaker11";
    MD5_(Str1.c_str(), Str1.length(), Cipher, 16);

    uint8_t Password_bytes[16]{};
    // 魔改点：invMixColumns 结果再异或 0x55
    aesDecrypt(Key, 16, Cipher, Password_bytes, 16);

    std::string Password;
    for (int i = 0; i < 16; i++) {
        char buf[10]{};
        sprintf_s(buf, "%02x", Password_bytes[i]);
        Password += buf;
    }
    return Password;
}

int main() {
    std::cout << GetPassword("inkey") << std::endl; // 4ac06ab6f14dfc1bbfa65d00c9cd012b
}
```

原文的 `AES.h` 是作者修改过的标准 AES 实现（MixColumns/invMixColumns 额外 XOR 0x55）；本卡未复跑。

## 变体与关联

- **修改点变体**：Sbox 替换、ShiftRows 偏移、轮密钥顺序、AddRoundKey 字节序、轮数；定位方法相同（差分对比）。
- **无标准库可调用**：若 MD5/AES 是自实现，需要先还原其接口/参数顺序，再用动态调试验证；原文的 MD5 直接用 libcrypto 的 `sign` 导出，省去逆向。
- **加密方向 vs 解密方向**：注册机通常需要解密；若程序只做加密校验，也可用“加密方向”的逆函数；注意 MixColumns 的 XOR 0x55 在逆变换中位置可能不同，需按程序代码确认。
- **关联**：`[[ctf-reverse-aes256-custom-rcon-key-schedule-decrypt]]`（自定义轮密钥）、`[[ctf-reverse-custom-aes-sbox-shiftrows-c2-traffic-decrypt]]`（自定义 Sbox/ShiftRows）、`[[ctf-reverse-aes128-aux-table-roundkey-recovery]]`（辅助表/轮密钥恢复）。
- **边界**：若修改不可逆（如丢弃字节、单向哈希），不能直接写注册机；若程序有反调试/完整性校验，需先绕过。

## 检测与防御

- **对逆向方**：优先提取 Sbox/常量表并对比标准实现；用差分调试定位第一处不一致；修改标准实现后用程序输出做正反向验证；注意大小端与 Qt/Windows 字符串编码。
- **对防守方（软件保护）**：不要用“改一个常数”的自定义密码当作保护，标准算法+正确密钥管理更安全；若必须自定义，增加完整性校验/反调试，并确保修改可逆性不影响安全目标；不要把密钥/密文硬编码在可提取位置。
- **检测**：二进制中出现 AES Sbox/轮常量、MixColumns 系数与额外 XOR 常量；动态调试时对加密函数下断，观察输入/输出与标准实现的差异。

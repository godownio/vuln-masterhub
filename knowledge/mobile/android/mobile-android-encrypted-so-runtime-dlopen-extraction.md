---
id: mobile-android-encrypted-so-runtime-dlopen-extraction
title: Android 加密 so 运行时解密/dlopen：从 /data/data 提取解密后的 .so 逆向 TEA 校验
type: scenario
domain: mobile
path: mobile/android
technique: android-encrypted-so-runtime-dlopen-extraction
aliases:
- VCTF ez_app
- qwqer1
- p0l1st
- validator_decrypted
- initNative
- dlopen dlsym
- 动态加载 so
tags:
- android
- native
- so
- dlopen
- jni
- unpacking
- tea
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V121
  verified_at: '2026-11-06T04:20:59+08:00'
  notes: 已对照原文及15张图核对：checkFlag 包装、initNative→sub_18BC、AAssetManager_open(qwqer1)、密钥 p0l1st、sub_14DC 解密与 PKCS#7 去填充、fopen/chmod(0x1ED)/dlopen/dlsym/off_40A8/byte_40B0、/data/data 提取 validator_decrypted_4621.so、TEA 32 轮密钥与密文、vctf flag 均与原文/截图一致；已把“12 个 32 位块”修正为“12 个 32 位字（6 个 TEA 块）”；CTF 应用无版本标记，affected_versions 已清空；PoC 未本机执行
---

## 一句话结论

APK 的 `checkFlag` 只是 JNI 包装层，真正逻辑在 `initNative` 里：它从 `assets/qwqer1` 读取加密 so，用密钥 `p0l1st` 做魔改 AES 解密，写到 `/data/data/<pkg>/validator_decrypted_*.so`，`chmod` 后 `dlopen`/`dlsym` 找到 `checkFlag` 函数指针；与其硬逆解密算法，不如 patch 掉 unlink/签名校验后运行 App，让它自己解密，再从 `/data/data` 把明文 so 拉出来分析 TEA 校验。

## 原理

- **JNI 加载链**：`System.loadLibrary` → `dlopen` → `JNI_OnLoad`（若存在）→ 静态绑定（`Java_<pkg>_<Class>_<method>`）或动态注册（`RegisterNatives` + `JNINativeMethod` 数组：方法名、签名、函数指针）。
- **本题结构**：Java `MainActivity.checkFlag` 声明为 native；so 里的 `Java_com_qwq_myapplication_MainActivity_checkFlag` 只是 `if (byte_40B0 != 1 || off_40A8 == 0) return 0; else return off_40A8();` 的包装。
- **initNative**：`onCreate` 中先调用 `initNative()`；它通过 JNI 拿 `AssetManager`，`AAssetManager_open("qwqer1")`，读取加密 so 到内存；`sub_14DC` 用密钥 `p0l1st` 做魔改 AES 解密（带 PKCS#7 去填充）；`fopen(...,"wb")` 写到临时文件，`chmod(0x1ED)`，`dlopen`，`dlsym("Java_com_qwq_myapplication_MainActivity_checkFlag")`，把函数指针存到 `off_40A8`，置 `byte_40B0=1`。
- **为什么直接提取**：魔改 AES 逆起来费时；App 自己会解密并落盘，运行时提取明文 so 更省事。so 里还有 `unlink`/反调试，patch 掉即可；APK 有签名校验，需要重签名/模拟器自动签名后再安装。
- **提取路径**：运行 App 后，解密 so 落在 `/data/data/com.qwq.myapplication/validator_decrypted_4621.so`；`su` 下 `cp` 到 `/sdcard/`，`adb pull` 到主机。
- **TEA 校验**：提取的 so 里 `checkFlag` 把输入与十六进制密文 `c2f6...e9ae` 比较；TEA 32 轮、密钥 `{0xA56BABCD,0x1F1234F1,0x12345678,0xFEDCBA98}`；解密 12 个 32 位字（6 个 TEA 块）得到 `vctf{5e7db573-a852-4ab8-84a1-6c64a2603157}`。

## 触发条件

- APK 使用“加密 so + 运行时解密 + dlopen”保护，Java 层只做桥接。
- 能在模拟器/已 root 设备上安装并运行 App；能访问 `/data/data/<pkg>/`。
- 能 patch so 的反调试/`unlink`，并绕过或重签名 APK 的签名校验。
- 提取的 so 中校验逻辑可静态分析（TEA/AES/RC4 等）。

## 利用步骤

1. jadx 看 Java 层：找 `native checkFlag`、`initNative` 调用顺序、`System.loadLibrary`。
2. IDA 看 so：找 `JNI_OnLoad`/`RegisterNatives`，定位 `initNative` → `sub_18BC`；记录 asset 名（`qwqer1`）、密钥（`p0l1st`）、解密函数、临时文件名、`dlopen`/`dlsym` 目标。
3. patch so 里的 `unlink`/反调试；patch 或绕过 APK 签名校验（重签名、模拟器“一键随机签名 APK”、或改校验分支）。
4. 安装并运行 App，触发 `initNative`；用 `su` 进入 `/data/data/<pkg>/`，找到 `validator_decrypted_*.so`。
5. `cp` 到 `/sdcard/`，`adb pull` 到主机；用 `file`/IDA 确认是 ARM64 so。
6. 分析提取 so 的 `checkFlag`：找密文、密钥、轮数/算法；写解密脚本（本题 TEA 32 轮）得到 flag。
7. 若不想 patch，可用 Frida Hook `dlopen`/`dlsym` 或 `sub_18BC` 直接 dump 解密后的 so。

## PoC

```bash
# 运行 App 后，从应用私有目录提取解密 so
adb shell su -c "ls /data/data/com.qwq.myapplication/"
adb shell su -c "cp /data/data/com.qwq.myapplication/validator_decrypted_4621.so /sdcard/"
adb pull /sdcard/validator_decrypted_4621.so
```

TEA 解密（提取 so 中的密文/密钥）：

```c
#include <stdint.h>
#include <string.h>
#include <stdio.h>

void tea_decrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720; // delta * 32
    const uint32_t delta = 0x9e3779b9;
    for (int i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    v[0] = v0; v[1] = v1;
}

int main(void) {
    uint32_t key[4] = {0xa56babcd, 0x1f1234f1, 0x12345678, 0xfedcba98};
    uint32_t blocks[] = {
        0xc2f6aade, 0x913f38fa, 0x407aceea, 0x7679a9db,
        0x017ea632, 0x769a2c53, 0x0f9917cb, 0xf2388a8d,
        0xc89f8017, 0x4a0d9618, 0x20ebf4b2, 0x0328e9ae
    };
    for (int i = 0; i < 6; i++) tea_decrypt(&blocks[i * 2], key);
    printf("%s\n", (char *)blocks);  // vctf{5e7db573-a852-4ab8-84a1-6c64a2603157}
    return 0;
}
```

## 变体与关联

- **提取变体**：从 `/data/data` 落盘文件提取；Frida Hook `dlopen`/`dlsym`/`android_dlopen_ext` dump 内存；Hook 解密函数返回明文；从 `/proc/<pid>/maps` + `memfd` 提取。
- **保护变体**：魔改 AES/RC4/XXTEA、分段解密、so 头抹除、反调试/`unlink`、签名校验、完整性校验。
- **JNI 变体**：静态绑定 `Java_*` vs `RegisterNatives` 动态注册；`JNI_OnLoad` 里做初始化解密。
- **关联卡片**：[[mobile-android-packer-apkid-frida-dexdump-jadx]]（脱壳/内存 dump）、[[ctf-reverse-android-arm64-jni-unicorn-offline-oracle]]（JNI 仿真）、[[mobile-android-apk-signature-sha1-xor-key-decrypt]]（签名校验）、[[ctf-reverse-apk-jni-username-xtea-hex-sse-compare]]（JNI+XTEA）。
- **边界**：若 so 只在内存解密且不落盘、或解密后有完整性校验/反 dump，需要 Frida/内存取证；签名校验未绕过时 App 可能直接退出。

## 检测与防御

- **防御**：加密 so + 运行时解密、完整性/签名校验、反调试/反 dump、内存加密；但客户端保护最终可被动态提取。
- **检测信号**：assets 中有非标准加密文件；`dlopen` 从应用私有目录加载 so；`/data/data/<pkg>/` 出现 `*_decrypted_*.so`；`dlsym` 查找 `Java_*` 符号。
- **测试建议**：先 patch 反调试/签名校验，再运行提取；提取后优先静态分析算法，不要硬逆解密器。

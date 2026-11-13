---
id: code-analysis-reverse-firmware-imgdecrypt-aes-key-rsa-qemu-recover
title: 加密固件密钥获取：逆向固件内 imgdecrypt 的 AES 常量，或用 qemu-mipsel chroot 直接执行取 key
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: firmware-imgdecrypt-aes-key-recover-qemu
tags:
- firmware
- reverse
- ghidra
- qemu
- mips
- mipsel
- aes-cbc
- key-recovery
- iot
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V646
  verified_at: '2026-11-13T03:55:58+08:00'
  notes: 已对照原文与36张图（源图缺03.png，img/img_small 各36张全部读取，大图降最长边1200，无失败）：图04/05 decrypt_firmare 反编译与原文一致（读 /etc_ro/public.pem、调用 FUN_00402554(&local_18) 后打印 key）；图07/08/12 证实 FUN_0040108c 内 AES_set_decrypt_key(param_3,0x80) + AES_cbc_encrypt；图14/16 .rodata 常量与卡内一致：key@0x402e68=358790034519f8c8235db6492839a73f、IV@0x402e58=98c9d8f0133d0695e2a709c8b69682d4、blob@0x402e78=c8d32f409cacb347c8d26fdcb9090b3c；图17/19 openssl/CyberChef 解出 c05fbf1936c99429ce2a0781f08d6ad8；图20-23 qemu-user-static、readelf（MIPS R3000 little endian）、qemu-mipsel-static chroot 直接输出 key:C05FBF1936C99429CE2A0781F08D6AD8，两路线结果互证。dedup：与 AES-ECB 密钥派生、尾部 0x80 单字节异或、AudioCodes 3DES、NOE-FWP KDF、DIR-816/schroot qemu 仿真卡均 related 但触发与用途不同（本卡用 qemu 只为跑解密器取 key），非同链；dup-scan 无涉及 pair。原文未标注受影响版本。未验证点：未复跑；原文未给出 RSA 公钥的具体用途，卡内已按'签名/封装校验'表述并弱化。未 commit/index/embed。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-imgdecrypt-aes-key-rsa-qemu-recover/
draft: false
kb_aliases:
- imgdecrypt 取固件密钥
- 固件解密程序逆向
- qemu-mipsel-static chroot 固件
- Ghidra 提取 AES key/IV
- public.pem 固件解密
- 固件 key 恢复
---

# 一句话结论

加密固件升级包的解密密钥通常由设备端自带的解密程序（如 `bin/imgdecrypt`）在运行时使用；从未加密的过渡版本固件中拿到该 ELF 后，既可用 Ghidra 逆向其 AES-128-CBC 常量并解密被封装 key，也可用 `qemu-mipsel-static` + `chroot` 在本地模拟执行该程序，让它直接打印出固件 key。

# 原理

- **解密程序必然随固件分发**：设备要能在升级时解密新固件，解密逻辑和密钥材料必须存在于设备端。厂商常把解密工具（`imgdecrypt`）放进未加密的过渡版本固件；拿到该版本即可获得解密器，而不用先攻破设备。
- **imgdecrypt 的逻辑**：Ghidra 反编译 `decrypt_firmare` 可见：读取 `/etc_ro/public.pem`（RSA 公钥），随后调用 `FUN_00402554(&local_18)`。该函数进入 `FUN_0040108c`，内部为 `AES_set_decrypt_key(key, 0x80, &ctx)` + `AES_cbc_encrypt(...)`，即 **AES-128-CBC 解密**；参数来自二进制 `.rodata`：
  - 0x402e68 起的 16 字节为 AES key（`35 87 90 03 45 19 f8 c8 23 5d b6 49 28 39 a7 3f`）；
  - 0x402e58 起的 16 字节为 IV（`98 c9 d8 f0 13 3d 06 95 e2 a7 09 c8 b6 96 82 d4`）；
  - 0x402e78 起的 16 字节为被加密的 key blob（`c8 d3 2f 40 9c ac b3 47 c8 d2 6f dc b9 09 0b 3c`）。
  用它俩对 blob 做一次 AES-128-CBC 解密，得到 16 字节固件 key（`c0 5f bf 19 36 c9 94 29 ce 2a 07 81 f0 8d 6a d8`），程序随后以 hex 打印并用于解密固件文件。RSA 公钥在本例中更多承担签名/封装校验角色，实际取 key 依赖的是这组 AES 常量。
- **模拟执行等价**：imgdecrypt 是 MIPS32 小端 ELF（`readelf -h` 显示 MIPS R3000, little endian）。把 `qemu-mipsel-static` 复制到解包后的固件根目录，`chroot . ./qemu-mipsel-static ./bin/imgdecrypt <encrypted_fw>` 即可在 x86 主机上运行该 MIPS 程序，它按同样逻辑打印 `key:...`，无需理解汇编。
- **为什么两条路都可行**：静态路线依赖常量在 `.rodata` 中可见（Ghidra 的 Copy Special 可导出 Byte String）；动态路线只依赖程序能运行，绕过反编译/混淆。两者结果一致（`C05FBF1936C99429CE2A0781F08D6AD8`），可互相验证。

# 触发条件

- 拿到目标设备的加密固件，以及同一产品线的未加密/过渡版本固件（其中含解密程序或库）。
- 解密程序为 MIPS/ARM 等可被 qemu-user 支持的架构；或能在 Ghidra/IDA 中静态分析。
- 攻击机安装 `qemu-user-static`（或对应 `qemu-<arch>-static`）、binwalk、Ghidra/IDA、openssl。

# 利用步骤

1. 用 `binwalk -Me <unencrypted_fw>` 解包过渡版本固件，得到类 Unix 根文件系统。
2. 定位解密器：`find ./ -name '*decrypt*'`，本例得到 `./bin/imgdecrypt`；同时可看到 `./etc_ro/public.pem`。
3. 判断架构：`readelf -h ./bin/imgdecrypt` 得到 MIPS32 小端、入口点、段表；`file`/`binwalk` 也可辅助。
4. 路线 A（静态）：Ghidra 打开 imgdecrypt → 定位 `decrypt_firmare` → 进入 `FUN_00402554`/`FUN_0040108c` 确认 `AES_set_decrypt_key`+`AES_cbc_encrypt` → 在 `.rodata` 选中 key/IV/blob 三处 16 字节，右键 Copy Special → Byte String (No Spaces)/Python Byte String 导出。
5. 用 openssl 解密被封装 key：
   ```bash
   printf "\xc8\xd3\x2f\x40\x9c\xac\xb3\x47\xc8\xd2\x6f\xdc\xb9\x09\x0b\x3c" | \
     openssl aes-128-cbc -d -nopad -K 358790034519f8c8235db6492839a73f \
     -iv 98c9d8f0133d0695e2a709c8b69682d4 -in - | hd
   # 输出 c0 5f bf 19 36 c9 94 29 ce 2a 07 81 f0 8d 6a d8
   ```
6. 路线 B（动态）：把 qemu 复制进固件根目录并 chroot 执行：
   ```bash
   cp /usr/bin/qemu-mipsel-static .
   sudo chroot . ./qemu-mipsel-static ./bin/imgdecrypt FW110B02_FW_Encrypt.bin
   # key:C05FBF1936C99429CE2A0781F08D6AD8
   ```
7. 用得到的 key 与固件头中的 IV 解密固件（见 SHRS 容器卡），或直接把 key 交给后续 binwalk 解密流程。

# PoC

```bash
# 1) 从未加密固件中取解密器
binwalk -Me FW104B02_Middle_FW_Unencrypt.bin
find ./ -name '*decrypt*'          # ./bin/imgdecrypt
readelf -h ./bin/imgdecrypt        # MIPS R3000, little endian

# 2A) 静态：Ghidra 读 .rodata 常量
#     AES key: 358790034519f8c8235db6492839a73f
#     IV     : 98c9d8f0133d0695e2a709c8b69682d4
#     blob   : c8d32f409cacb347c8d26fdcb9090b3c
printf "\xc8\xd3\x2f\x40\x9c\xac\xb3\x47\xc8\xd2\x6f\xdc\xb9\x09\x0b\x3c" | \
  openssl aes-128-cbc -d -nopad -K 358790034519f8c8235db6492839a73f \
  -iv 98c9d8f0133d0695e2a709c8b69682d4 -in - | xxd

# 2B) 动态：qemu-mipsel 模拟执行
cp /usr/bin/qemu-mipsel-static .
sudo chroot . ./qemu-mipsel-static ./bin/imgdecrypt FW110B02_FW_Encrypt.bin
# key:C05FBF1936C99429CE2A0781F08D6AD8
```

# 变体与关联

- 架构变体：MIPS 大端用 `qemu-mips-static`，ARM 用 `qemu-arm-static`，AArch64 用 `qemu-aarch64-static`；非静态版需 `-L` 指定库路径。
- 静态路线变体：IDA + 常量交叉引用、`strings`/`binwalk` 找 AES S-box 与 key 常量、用 `angr`/`unicorn` 只模拟解密函数；若 key 由 KDF 派生，参考 [[code-analysis-reverse-firmware-custom-package-aes-kdf-field-recovery]]。
- 动态路线变体：`schroot`/容器内 chroot、`LD_PRELOAD` 伪造 NVRAM/配置文件、gdb-multiarch 附加；运行失败时补 pid/设备节点或 patch 检查。
- 拿到 key 后接 [[code-analysis-reverse-firmware-shrs-container-aes-cbc-sha512-repack]] 解析加密容器；其他固件解密形态见 [[code-analysis-reverse-firmware-aes-ecb-key-xor-header-decrypt]]（AES-ECB + xor 派生）与 [[code-analysis-reverse-firmware-draytek-vigor3910-fip-chacha20-lz4-cpio]]（ChaCha20 容器）。

# 检测与防御

- 检测：固件升级包中出现高熵段、`SHRS` 等自定义 magic；设备端存在 `imgdecrypt`/`public.pem` 等解密材料；发布包中残留调试/解密工具。
- 防御：不要把解密程序与密钥材料放进可分发的未加密固件；使用每设备唯一密钥/安全启动与签名验证；把解密逻辑放进 TEE/安全芯片；对固件做完整性签名并在升级时校验；移除调试符号与明文常量（虽不能根本阻止逆向，但提高成本）。

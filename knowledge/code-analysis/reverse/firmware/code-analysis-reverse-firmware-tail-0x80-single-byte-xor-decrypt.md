---
id: code-analysis-reverse-firmware-tail-0x80-single-byte-xor-decrypt
title: 加密固件尾部成片 0x80 反推单字节 XOR 密钥（0x7F）：解出后 binwalk 可正常解包，并定位刷机程序 rg-upgrade-crypto 验证
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: firmware-tail-0x80-single-byte-xor-key-inference
aliases:
- 固件单字节异或解密
- 尾部 0x80 猜 XOR key
- 锐捷固件解密
- rg-upgrade-crypto
- 加密固件解包
tags:
- reverse
- firmware
- xor
- decryption
- binwalk
- router
- ruijie
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:56:02+08:00'
  notes: 已对照原文核对：尾部成片 0x80 反推 0xFF 填充被 0x7F 异或（或 0x00 填充被 0x80 异或）→ 整文件单字节异或后 binwalk 可解包、再从 OpenWrt mtd 刷固件路径上定位 rg-upgrade-crypto 验证算法，以及正文给的 jiemi() 逐字节异或脚本，均与正文一致；卡内对「填充随机化/AES/多字节循环密钥则失效」的边界与原文表述相符；本次核对未读取图片，尾部 hexdump 实测与 binwalk 解包回显（img/02-03）未核实；未下载固件、未执行脚本。
---

## 一句话结论

厂商加密固件里通常仍保留原始镜像的结构性填充（文件末尾常是成片的 `0xFF` 或 `0x00`），加密后这些填充变成成片的同一字节；看到尾部大段 `0x80` 就可以反推「填充 `0xFF` ^ key = `0x80`」⇒ key=`0x7F`（若推断填充为 `0x00` 则 key 直接是 `0x80`），用单字节异或整文件即可让 `binwalk`/`file` 重新识别并解出文件系统；再用「解密在刷机之前完成」这一约束去固件里搜 `mtd` 写 flash 的调用，就能定位到真正的解密程序（本例 `/usr/sbin/rg-upgrade-crypto`）并对齐出准确算法。

## 原理

- **结构性填充是已知明文**：固件镜像按块对齐（常见 64KB/128KB 或 flash 擦除块），最后一块未被数据占满的部分会被填 `0xFF`（NOR/NAND 擦除态）或 `0x00`。这部分内容在加密前后长度与位置都固定，是破解单字节/重复密钥异或的「已知明文」。
- **单字节异或的不动点特征**：`0xFF ^ 0x7F = 0x80`，一整段 `0xFF` 全变成 `0x80`，于是在 hexdump 里表现为「尾部成片同值字节」。反过来看到成片 `0x80` 基本可以断定是 `0xFF` 填充被 `0x7F` 异或，或 `0x00` 填充被 `0x80` 异或——两种假设分别试，能 `binwalk` 出结果的那个就是对的。
- **为什么能解包**：文件系统（squashfs）与内核的 magic 都在文件头部，头部的结构性字节（magic、长度字段、压缩方法）同样是已知明文，异或后整体恢复即可让 `binwalk -Me` 正常识别并递归提取。
- **为什么还要找刷机程序**：单字节异或是「猜出来的」，真实算法可能是多字节/循环密钥+头部特判；固件更新一定发生在写 flash 之前，所以从 OpenWrt 的 `mtd write` 调用点向上交叉引用，就能找到厂商自带的解密二进制（本例 `rg-upgrade-crypto`），逆向它可确认是否整文件单字节异或、是否有长度/尾部特判，避免「能解包但数据错位」。
- **边界**：若填充不是单一字节（随机 padding）、或加密是 AES/多字节循环密钥，尾部同值特征不成立，本方法失效，必须从刷机程序或 bootloader 侧逆向。

## 触发条件

- 已从厂商官网/OTA 拿到加密固件，`binwalk`/`file` 无法识别，或能识别但提取出的内容明显是乱码。
- 固件长度是常见块大小的整数倍，尾部存在成片同值字节（`hexdump -C` 尾部可见）。
- 手上有可对照的「正常固件」或同一型号的解密后版本，用于验证解码结果（可选）。
- 能拿到固件内文件系统（哪怕只是部分解出），以便搜索 `mtd`/`flash` 写入逻辑定位解密程序。

## 利用步骤

1. `hexdump -C firmware.bin | tail` 看尾部：出现成片 `80 80 80 ...` 即怀疑 `0xFF` 填充被 `0x7F` 异或。
2. 写脚本对整文件异或 `0x7F`，输出 `firmware.dec`；再用 `binwalk firmware.dec` 看是否识别出 squashfs/内核。若失败，改试 `0x80`（假设填充为 `0x00`）或 `0xFF`（未加密的对称猜测）。
3. `binwalk -Me firmware.dec` 解包，确认 `squashfs-root` 下有 `etc/init.d/`、`usr/lib/lua/` 等合理目录 → 解密正确。
4. 在解出的 rootfs 里搜刷机逻辑：`grep -r "mtd" etc/ usr/ | grep -i write`，找到调用解密程序的位置；本例定位到 `/usr/sbin/rg-upgrade-crypto`。
5. 用 IDA/Ghidra 逆向该二进制，确认算法（是否整文件单字节异或、是否有尾部/头部特判、密钥是否硬编码），必要时修正脚本。
6. 用官方 pairing 验证：解出的固件能被 `binwalk` 完整递归提取、`unsquashfs -l` 列表正常、关键二进制可被 `file` 识别为 MIPS ELF，即视为解密成功。

## PoC

```python
# 尾部同值字节反推密钥 → 整文件单字节异或
import sys

def xor_file(src, dst, key):
    with open(src, 'rb') as fi, open(dst, 'wb') as fo:
        while True:
            chunk = fi.read(0x10000)
            if not chunk:
                break
            fo.write(bytes(b ^ key for b in chunk))
    print(f"{src} -> {dst} (key=0x{key:02x})")

if __name__ == '__main__':
    xor_file(sys.argv[1], sys.argv[2], 0x7F)   # 尾部 0x80 的推断结果
```

```bash
# 验证链路
hexdump -C vendor_fw.bin | tail -n 5      # 看到成片 80
python3 xor_fw.py vendor_fw.bin fw.dec
file fw.dec
binwalk fw.dec | head
binwalk -Me fw.dec --run-as=root
ls squashfs-root/etc/init.d | head        # 目录结构合理 => 解密正确
```

```text
判定：解密后 binwalk 能列出 squashfs 条目、squashfs-root 出现 etc/bin/usr/lib 等标准目录，即成功；
      若仍乱码，改用 0x80/0xFF 假设或转去逆向刷机程序。
```

## 变体与关联

- **填充为 `0x00` 的固件**：尾部成片 `0x80` 也可能对应 `0x00 ^ 0x80`，此时 key 是 `0x80`；两个假设各跑一次 `binwalk` 最快判定。
- **多字节循环密钥**：尾部同值只说明最后一个密钥字节；若头部解不出 magic，说明是循环密钥，需要结合文件头已知明文（magic、版本字段）做多字节求解。
- **更复杂方案**：AES/XOR+压缩的固化封装需要用刷机程序或 bootloader 的验签/解密路径逆向；同类思路见其他固件解密卡（包尾派生 key、AES-ECB 头部解密、ChaCha20/LZ4 自定义封装）。
- **定位解密程序的通用技巧**：固件解密必在写 flash 前发生 → 搜 `mtd`/`flash_erase`/`ubiupdatevol` 的调用者；也可搜 `crypto`/`decrypt`/`upgrade` 命名的二进制与 init 脚本。

## 检测与防御

- 厂商侧：不要把结构性填充原样交给弱异或加密（等价于给已知明文），至少用带认证的加密（AES-GCM）并把镜像头作为 AAD；解密密钥不要硬编码在可从固件读出的二进制里。
- 测试侧：验证「固件被完整加密」时应检查尾部填充是否也随机化，否则攻击者可直接反推密钥。
- 研究流程：先看尾部同值字节 → 做单字节试验 → 用 `binwalk` 结果验证 → 再用刷机程序确认算法，避免把「部分正确」误当成成功。

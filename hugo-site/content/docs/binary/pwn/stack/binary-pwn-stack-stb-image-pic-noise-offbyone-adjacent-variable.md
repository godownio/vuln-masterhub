---
id: binary-pwn-stack-stb-image-pic-noise-offbyone-adjacent-variable
title: stb_image PIC 噪声数组越界写相邻栈变量：构造 PIC 像素把 privilege 改成 0x1337
type: scenario
domain: binary
path: binary/pwn/stack
technique: stb-image-pic-noise-offbyone-adjacent-variable
tags:
- pwn
- stack
- stb-image
- pic
- off-by-one
- adjacent-variable
- image-parser
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:12+08:00'
  notes: 已对照原文与 img/01 核对 PIC 头 5380F634/PICT、channel header 00 08 00 F0、噪声模式、width=0x55、循环 i<=10 覆盖 privilege_value 与 0x1337 解锁菜单；原稿 rand 命中概率 1/64 已修正为约 1/2（0x37 仅需 rand()&0x3F 第3位为0）。未验证点：未本机复跑 exp；修改版 stb_image 非上游默认接口。
url: /docs/binary/pwn/stack/binary-pwn-stack-stb-image-pic-noise-offbyone-adjacent-variable/
draft: false
kb_aliases:
- stbi__pic_load 越界写
- image_noises[10] 溢出
- PIC 图片解析栈溢出
- privilege 0x1337
- 图片解析器相邻变量覆盖
---

## 一句话结论

在题目修改版的 stb_image 中，`stbi__pic_load` 用 `for (i = 0; i <= 10; ++i) image_modifications_ptr[i] = image_noises[i];` 把 11 个 double 写进调用方只有 10 个 double 的 `modification_parameters_1`，第 11 个 double 正好落在相邻的 `privilege_value` int 上；构造 PIC 图片让 `image_noises[10]` 的第二字节为 0x13，再配合 `rand() & 0x3f` 的低字节概率得到 0x37，就能把权限值改成 `0x1337`，使 `privilege = (*ptr != 4919)` 变为 0，解锁后续堆菜单。

## 原理

- **栈布局**：`main` 中 `__int64 modification_parameters_1[10]` 位于 `rbp-0xA0`，`int privilege_value` 位于 `rbp-0x50`。10 个 double 恰好占 0x50 字节，所以 `modification_parameters_1[10]` 的起始地址就是 `privilege_value` 的地址，二者相邻。
- **越界写**：`stbi__pic_load` 在解析完 PIC 数据后执行 `for (i = 0; i <= 10; ++i) *(double *)&image_modifications_ptr[i] = image_noises[i];`。循环条件 `<= 10` 比数组长度多一次，第 11 个 double（8 字节）覆盖 `privilege_value` 及其后的 4 字节填充；`privilege_value` 的低 4 字节由该 double 的前 4 字节决定。
- **如何控制 image_noises[10]**：PIC 的 channel header 类型为 0 时，解析器按 width 次读取 4 字节像素，计算 `mod_result = (cur_first_byte - prev_first_byte) % 11`；若为负取反，用该值作为 `image_noises` 的下标，并在原值上累加 `(byte1 ^ byte2) * 1e-16`。输入首字节交替 10 和 0（差值 10 与 -10），即可稳定命中下标 10；中间两字节用 0xf0 与 0x0f（异或 0xff）让每次累加最大。
- **凑出 0x1337**：`image_noises[10]` 的 double 表示中第二字节需要是 0x13，才能让 `privilege_value` 的高字节为 0x13。每次只加 255e-16，需要靠 width 控制累加次数；原文实测 width=0x55 时命中。随后程序执行 `*ptr |= 7`、`*ptr &= 0x1FFF`，再用 `rand() & 0x3F` 填低 6 位；在噪声已把高字节凑成 0x13 的前提下，最终低字节要成为 0x37（55），只需 `rand() & 0x3F` 的第 3 位（0x08）为 0，命中概率约 1/2，所以 exploit 也需要多跑几次直到 `yo face = 4919`。
- **为什么必须走 PIC**：`stbi__load_main` 会依次测试 PNG/BMP/GIF/PSD/PIC/JPEG/PNM/HDR/TGA；只有 PIC 路径的 `stbi__pic_load` 带有这个多写一个元素的循环，并且能把解析出的噪声数组传回调用方。
- 根因是“解析器对调用方提供的定长数组多做一次写入”，而调用方把安全状态（privilege）放在该数组之后的栈槽；这类相邻变量覆盖不需要覆盖返回地址，就能改变程序控制流。

## 触发条件

- 目标使用带 `modification_parameters`/`image_noises` 参数的修改版 stb_image，且 `stbi__pic_load` 的循环条件为 `i <= 10`（或等价的多写一次）。
- 调用方在 `main` 栈上把该数组紧挨着安全判断变量/函数指针等敏感槽位。
- 输入先经过图像格式测试，必须能走到 PIC 分支：开头 4 字节 `53 80 F6 34`，偏移 0x58 处 `PICT`。
- width/height 不超过 4096，且 width 足够大以累加出目标字节（原文 0x55）。
- 没有栈保护提前终止（本例是写相邻局部变量，不触碰 canary）。

## 利用步骤

1. 逆向 `main` 与 `stbi__pic_load`，确认 `modification_parameters_1[10]` 与 `privilege_value` 的栈偏移，以及 `for (i = 0; i <= 10; ++i)` 的多写一次。
2. 构造 PIC 文件头：偏移 0 放 `53 80 F6 34`，偏移 0x58 放 `PICT`。
3. 偏移 0x5C 放 width（大端 0x0055），0x5E 放 height（大端 0x0001）。
4. 偏移 0x68 放 channel header：`00 08 00 F0`（type=0、header[0]=8、header[1]=0、header[2]=0xF0）。
5. 偏移 0x6C 起重复 8 字节模式 `0A F0 0F 04 00 F0 0F 04`，填满 0x40 组（多出的数据解析器会忽略）。
6. 发送文件大小与内容，读取 `yo face = %d`；若不是 4919，重试（`rand()` 低字节随机）。
7. 得到 4919 后，`privilege` 为 0，菜单的 alloc/delete/show 解锁，进入后续堆利用。

## PoC

```python
from pwn import *

def pack_data():
    return bytes([10, 0xf0, 0x0f, 4]) + bytes([0, 0xf0, 0x0f, 4])

data = flat({
    0x00: bytes([0x53, 0x80, 0xF6, 0x34]),      # PIC magic
    0x58: b"PICT",                               # pic_test 的第二个魔数
    0x5c: bytes([0x00, 0x55]),                   # width  = 0x55 (BE)
    0x5e: bytes([0x00, 0x01]),                   # height = 0x01 (BE)
    0x68: bytes([0x00, 0x08, 0x00, 0xF0]),       # type=0, header[0]=8, header[2]=0xF0
    0x6c: pack_data() * 0x40,                    # 交替噪声，命中 image_noises[10]
}, filler=b"\x00")

io.sendlineafter(b"Enter image size in bytes: ", str(len(data)).encode())
io.sendline(data)
# 反复重连，直到输出: yo face = 4919
```

说明：原文用 `p16(0x5500)`/`p16(0x100)` 以小端打包得到 `00 55`/`00 01`，解析器按大端读取得到 width=0x55、height=1；上面的 `bytes([...])` 直接写出实际字节，避免混淆。PoC 未在本机复跑。

## 变体与关联

- 变体：如果第 11 个 double 落在别的敏感变量上（角色、长度、函数指针），可把 `image_noises[10]` 的字节改成对应目标值，而不是 0x1337。
- 变体：同一模式可出现在其它图像/媒体解析器的“按通道写回调用方数组”逻辑中；审计时重点看 `<= n` 与调用方数组长度为 n 的组合。
- 关联：[[binary-pwn-heap-tcache-reverse-into-fastbin-fastbin-dup-arbitrary-alloc]]（本卡解锁的堆菜单后续利用）、[[binary-pwn-heap-glibc-exit-initial-pointer-guard-forge-system]]（最终 exit 劫持）、[[binary-pwn-stack-snprintf-return-length-read-overflow]]（另一类“长度/边界计算错误导致栈写”）。
- 边界：上游 stb_image 默认接口没有这个 noise 数组参数；循环写成 `i < 10`、调用方数组更大、或编译器把 `privilege_value` 放到别的槽位时，本手法不成立。

## 检测与防御

- 修复：循环边界改为 `i < 10`（或按数组实际长度），不要把解析器内部噪声数组写回调用方定长数组；若必须写回，使用长度参数并校验。
- 加固：开启 `-fstack-protector-strong`、`-D_FORTIFY_SOURCE=2`；把安全判断变量与可写缓冲区分离，避免相邻布局；对图像解析器做模糊测试与 ASan。
- 检测：图像解析路径中出现对调用方数组的越界写、循环次数比数组长度多 1；程序安全状态变量被输入间接改变；同一输入多次运行出现概率性权限变化。
- 研究侧：保留原始固件/二进制与输入样本，记录 width、噪声模式与随机重试次数，便于复核。

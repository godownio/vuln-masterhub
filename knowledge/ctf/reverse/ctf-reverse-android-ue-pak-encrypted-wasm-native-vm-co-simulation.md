---
id: ctf-reverse-android-ue-pak-encrypted-wasm-native-vm-co-simulation
title: Android UE 游戏逆向：UE pak 内 XTEA-CBC 加密 WASM + 原生 VM/WASM 协同模拟，四轮可逆变换解 3941 次点击并派生 AES key/iv
type: scenario
domain: ctf
path: ctf/reverse
technique: android-ue-pak-encrypted-wasm-native-vm-co-simulation
aliases:
- 千千的咲
- UE IoStore pak 提取
- main.obb.png
- p.bin XTEA-CBC
- p.wasm
- libUnreal.so 反调试
- 原生 VM + WASM 协同
- 四轮可逆变换
- 改写 AES 缺 Rcon
tags:
- ctf
- reverse
- android
- unreal-engine
- pak
- wasm
- xtea
- cbc
- native-vm
- frida
- wasmtime
- anti-debug
- aes
- kdf
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:55:56+08:00'
  notes: 已对照原文核对；main.obb.png→UE pak、XTEA-CBC key qianqiandexiao99、WASM 桥、493 块/3941 点击、KDF 与改写 AES 一致；PoC 未复跑
---

## 一句话结论

Android UE 游戏把真正的校验逻辑拆成三层：`main.obb.png`（实为 ZIP）里的 UE IoStore/pak 中藏着 XTEA-CBC 加密的 `p.bin`，解密得到 `p.wasm`；WASM 通过 `e.q(sel,arg)` 导入把点击转发给 `libUnreal.so` 里的原生 VM，原生 VM 再用 493 块块表 + 四轮可逆变换处理 3941 次点击。要拿到 key/iv，必须让原生 VM 与真 WASM 一起“边跑边解”：先用探针算出块头密钥 `V`，逐块反解出点击序列，再真跑序列让 engine 哈希链定型，最后由 `SHA256(0x02‖S‖u64(3941)‖c)` 派生 AES key/iv 解密 48 字节密文。

## 原理

- **容器与资源提取**：APK 里 `lib/x86_64/libUnreal.so`（100MB）与 `lib/arm64-v8a/libUnreal.so`（96MB）包含全部游戏逻辑；`assets/main.obb.png` 改后缀为 ZIP 后是 UE 的 `pak/ucas/utoc`，用 CUE4Parse 或自写 TOC 解析 + ooz Kraken 解压可列出 1934 个文件，关键是 `CTFGame/Content/Data/p.bin`；贴图/背景里没有 flag（16 块 256×256 拼起来是正常立绘，无文字、无 LSB）。
- **p.bin 解密**：头部 `magic 8F 21 D6 B4`、`u32 明文长度 0x57E=1406`、8 字节 CBC IV、密文。算法是 XTEA 解密 + CBC 链接：key=`qianqiandexiao99`（16 字节）、`delta=0x9E3779B9`、32 轮、初始 `sum=delta<<5`，每块解密后与前一块密文异或，末尾 PKCS#7 去填充，得到 1406 字节的 `p.wasm`。
- **WASM 与原生 VM 的桥**：`p.wasm` 导出 `b()`（初始化并让原生 VM `q(4988,0)`）、`a(i)`（一次点击，返回整体是否完成）、`c(i)`（取第 i 个结果字节）；导入 `e.q(sel,arg)->i32` 直接落到原生分发器 `0x481C236`。`a(i)` 依次调用 `q(9325,i)`、`q(18367,h1)`、`q(22720,h2)`、`q(27089,h3)`，其中 h1/h2/h3 由 WASM 内 6 个 32 位状态字（初值为 π 常量）经 mix 计算，状态在每次点击后更新。
- **原生 VM 状态**：`read(i)=vm[i*8+8]^vm[i*8+0xC]`（写入带链式混淆，但 read 恒等于写入值）；重要字段包括 f08 当前块号（初始 `0x1BC=444`，不是 0）、f09 点击计数（到 `0xF65=3941` 完成）、f0A 块内步号、f0B/f0C 滚动状态、f0D..f12 块头解码结果、f13..f16 本次 nonce、f17 点击格号、f18 状态机状态、f00..f07 最近 8 次点击的滚动哈希。
- **每次点击的哈希链**：`nonce_k = SHA256(0x03 ‖ engine[32] ‖ u64(k))[0:16]`；`engine = SHA256(0x01 ‖ engine[32] ‖ u64(k) ‖ cell)`，counter++；f13..f16=nonce，f17=cell，f18=1。关键点：nonce 在更新 engine 之前算，**与本次点哪一格无关**，所以可以用“随便点一格”的探针拿 nonce，而不污染真正的点击序列。
- **块表与块头解密**：493 块 × 21 dword（5 个头字段 + 8 对指令字段）。进入块时用 `V = vm_fn_0x481B2EE(vm)` 解头：`f051(X,i)=mix(X ^ ((i+1)*0x9E3779B9) ^ 0xA511E9B3)`，`header[i] = table[block*21+i] ^ f051(V,i)`。`V` 依赖 f08/f09/环缓冲/f0B/f0C/f13..f16/f19/f1a/f1c，其中 f19/f1a 是 WASM 算出的摘要，所以纯静态读表不够。
- **四轮可逆变换**：`T(x,a,b,c)` 对 `i=0..3` 做 `t=mix(a^c^(0x9E3779B9*i)); x=rol((x^t)+rol(b,3+5i)+c,5+6i); x=(x*(mix(b+i)|1)) & 0xFFFFFFFF`。乘数 `mix(b+i)|1` 恒为奇数，模 2³² 必有逆元，因此四轮都能倒着走：`x=(y*inv(mix(b+i)|1))`、`ror`、减去常量、再异或 `t`。`a=header[1]`、`b=header[2]`、`c=V`，`header[0]` 是目标值；第一块 444 实测 `V=0x6FEF75EB`、`header=A0D88FB7 9C1AB9CA D2AB1B9D 00000011 0000009F`，`Tinv` 得 `x=0xDB5A14A5`，低→高拆半字节为 `5,A,4,1,A,5,B,D`，即前 8 下点击 5,10,4,1,10,5,11,13。
- **必须边跑边解**：块号不是顺序的，每块 8 步结束时 `f08=(f11 或 f12)%501`，是数据驱动的链表；块头密钥 `V` 又依赖本次点击产生的 f19/f1a/f1c。因此做法是 frida 在游戏进程里 `Memory.alloc` 一个全新 VM/engine，wasmtime 加载 `p.wasm`，`e.q` 桥接原生：每块先用“随便点一格”的探针拿 nonce、算 h1/h2、写回 f19/f1a、读 V，然后 restore 快照，再用 V 解块、反解出 8 个格号，最后真跑这 8 下（同时调 WASM `a(c)`）。
- **终局 KDF 与改写 AES**：完成态取 `c(0..31)` 与 engine 32 字节终态 `S`：`digest = SHA256(0x02 ‖ S ‖ u64(3941) ‖ c[32])`，`key=digest[0:16]`、`iv=digest[16:32]`；解密 `0x869020` 的 48 字节密文得到 34 字节明文，再做 FNV-1a-64 校验（期望 `0xD59091F3EE56F409`）。二进制里虽有标准 S-box/逆 S-box，但没有 Rcon 表，密钥扩展是改写过的，直接用标准 `AES-128-CBC` 解不对，必须调用/重放原生 `0x4819EC0`（内部 `0x48198A5` 密钥扩展 → `0x48199E9` 解密 → `0x4819EC0` FNV 校验）。

## 触发条件

- 目标是 Android UE 游戏/应用，资源包为 pak/IoStore，游戏逻辑在 `libUnreal.so` 等原生库中。
- 资源里存在加密的 WASM/字节码（本例题 `p.bin`），且 WASM 通过导入函数把关键操作转给原生 VM。
- 原生库有字符串混淆/反调试，但可 patch 或绕过；能在模拟器/真机上运行游戏并 attach frida。
- 最终密钥由点击序列/哈希链决定，且末尾有可验证的校验（本题是 FNV-1a-64）。

## 利用步骤

1. 解包 APK，提取 `libUnreal.so`；把 `main.obb.png` 当作 ZIP 解压，用 CUE4Parse 解析 UE pak/IoStore，找到 `CTFGame/Content/Data/p.bin`。
2. 识别 `p.bin` 头部（magic、明文长度、CBC IV），用 XTEA-CBC（key `qianqiandexiao99`）解出 `p.wasm`，`wasm2wat` 反汇编。
3. 分析 `libUnreal.so`：字符串 XOR 0xA7 解密类名/函数名；定位反调试 `0x481A30D`（读 `/proc/self/maps` 找 frida-agent/gadget、查 `TracerPid`）与看门狗；把文件偏移 `0x481630D` 的首 3 字节改为 `31 C0 C3`（`xor eax,eax; ret`）。
4. 在 MuMu/真机上启动游戏，frida-server attach；在游戏进程里分配新 VM/engine，用 wasmtime 加载 `p.wasm`，把 `e.q` 桥接到原生分发器。
5. 按“探针 → 解块 → 真跑”的循环处理 493 块：每块先 submit 0 拿 nonce、算 h1/h2、写 f19/f1a、读 V、restore；用 V 解 5 个 header、`Tinv` 解出 8 个格号；再真跑这 8 下并同步调 WASM `a(c)`，直到 f09=3941、f18=0。
6. 完成态取 `S` 与 `c(0..31)`，算 `digest=SHA256(0x02‖S‖u64(3941)‖c)`，取 key/iv；用原生 `0x4819EC0` 解密 `0x869020` 的 48 字节密文并做 FNV 校验，得到 flag。

## PoC

“探针 → 解块 → 真跑”的核心循环（按原文 frida/wasmtime 脚本重写，未在本库复跑）：

```python
seq = []
while len(seq) < 3941:
    blk = rd(8) & 0xFFFFFFFF
    n   = min(8, 3941 - len(seq))

    # 探针：只为拿 V（nonce 与格子无关，随便点）
    snap = E.snap()
    E.submit(0)
    r2 = E.q(0x246D, 0) & 0xFFFFFFFF
    h1, h2 = h1h2(wasm_mem[1040:1064], r2)
    E.wr(0x19, h1); E.wr(0x1A, h2)
    V = E.v() & 0xFFFFFFFF
    E.restore(snap)

    # 解块
    hdr = [(TBL[blk][i] ^ f051(V, i)) & 0xFFFFFFFF for i in range(5)]
    x   = Tinv(hdr[0], hdr[1], hdr[2], V)
    cells = [(x >> (4*k)) & 0xF for k in range(n)]

    # 真跑这 8 下
    for c in cells:
        E.submit(c)
        wasm_a(c)
    seq += cells
```

原文实测 3941 次点击后得到 `flag{WuTher1ng_Waves_ch1Sak1_6666}`；关键校验 `FNV1a64(plain[:34]) == 0xD59091F3EE56F409`。

## 变体与关联

- **资源格式变体**：UE pak/IoStore、Unity AssetBundle、自定义加密归档；先识别 magic 与压缩算法（ooz/Kraken），再解密内层字节码。
- **WASM 变体**：WASM 可直接包含逻辑，也可只做桥接；注意导入函数的 selector 分发、线性内存布局与状态字初值。
- **VM 变体**：块表 + 数据驱动链表、每块密钥依赖运行时状态、四轮可逆变换；纯静态求逆不够时，用“探针+快照+restore”。
- **密码变体**：XTEA-CBC、改写 AES（缺 Rcon）、SHA256 KDF；不要默认标准库实现与题目一致，优先调用原生例程。
- **关联卡片**：[[ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx]]（纯原生 VM 的 ISA 抠取与逐轮求逆）、[[ctf-reverse-apk-knapsack-chacha20-vault]]（APK 加密归档 + KDF + ChaCha20）。

## 检测与防御

- **对逆向方**：先做资源/容器识别，再处理反调试；对“密钥依赖运行时状态”的 VM，必须真跑或高保真模拟，不要只静态读表；标准密码库解不开时，检查常量表（如 Rcon）是否被改写。
- **对保护方**：把关键逻辑拆到 WASM/原生 VM 只能提高分析成本；反调试应覆盖 frida、TracerPid、maps 与时间差；KDF 应绑定不可预测的运行时状态。
- **对题目设计方**：贴图/背景不要暗示 flag 藏法；`--bof` 类干扰项应与主逻辑隔离；最终校验应能区分“自洽但错误”的序列（本题 FNV 起到了这个作用）。

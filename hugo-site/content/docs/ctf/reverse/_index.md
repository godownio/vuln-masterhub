---
title: CTF Reverse
weight: 1
---

# CTF Reverse

## 这层是什么

Reverse 题型技巧。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [1264 个 Java class 各自解密小段字节：批量反编译拼接 PNG](ctf-reverse-batch-java-class-constants-decrypt-image/) | verified | high | 2026-11-06 |
| [20 轮自定义 Feistel 逆推：key 指针按 4 字节取模 12 循环取 dword，正向两分支交换、逆向只需把 prev/next 角色对调](ctf-reverse-custom-feistel-20round-dword-key-rotation-inverse/) | verified | high | 2026-11-08 |
| [2x3 六比特块转可打印字符：图像编码器逆推](ctf-reverse-six-bit-block-printable-image-encoder/) | verified | medium | 2026-11-06 |
| [4 位半字节进位链加密逆向：低 4 位传给下一字符高 4 位，解必须按正序一边解 LCG 密钥一边推进](ctf-reverse-nibble-carry-chain-lcg-xor-inverse/) | verified | high | 2026-11-08 |
| [5×26 位图目标表逐位置反解：130 项 bitmask 相等校验直接还原 5 行输入](ctf-reverse-bitmask-target-table-position-recovery/) | verified | high | 2026-11-06 |
| [6502 超长可逆指令流：模式匹配高层操作后反向执行恢复输入](ctf-reverse-6502-reversible-op-stream-inversion/) | verified | high | 2026-11-06 |
| [ADFGVX 6×6 坐标点击矩阵 + 行列和/MD5 约束爆破还原点击路径](ctf-reverse-adfgvx-click-matrix-md5-constraint-brute-force/) | verified | high | 2026-11-06 |
| [AES-128 辅助表泄露 RK9/RK10：逐字节枚举恢复轮密钥并反推主密钥](ctf-reverse-aes128-aux-table-roundkey-recovery/) | verified | high | 2026-11-06 |
| [AES-256-CBC 密钥扩展 Rcon 魔改：自定义轮常量表重建轮密钥并解密](ctf-reverse-aes256-custom-rcon-key-schedule-decrypt/) | verified | high | 2026-11-06 |
| [AES-CBC 轮密钥逐块交换魔改：按 j%11 交换第 0 轮与第 n 轮后解密](ctf-reverse-aes-cbc-roundkey-swap-per-block/) | verified | high | 2026-11-06 |
| [Android APK 三段校验链：手势 SHA-256 爆破 + JNI 可逆字节变换 + SQLite IV 的 AES-CBC 解密](ctf-reverse-android-pattern-sha256-jni-arx-aes-cbc-chain/) | verified | high | 2026-11-06 |
| [Android JNI 登录校验逆向：用户名派生 XTEA key + hex 编码 + SSE 常量比较（getFlag 直读捷径）](ctf-reverse-apk-jni-username-xtea-hex-sse-compare/) | verified | high | 2026-11-06 |
| [Android native RC4 密文比对绕过：Frida hook 比对函数取 correctCiphertext，已知明文构造恢复 RC4 密钥流](ctf-reverse-android-frida-keystream-recovery-bypass-rc4-compare/) | verified | high | 2026-11-08 |
| [Android so 层 RC4 解出 XTEA key/iv 后按魔改 XTEA-CBC 轮逆推解密](ctf-reverse-android-so-rc4-derived-xtea-cbc-decrypt/) | verified | high | 2026-11-08 |
| [Android UE 游戏逆向：UE pak 内 XTEA-CBC 加密 WASM + 原生 VM/WASM 协同模拟，四轮可逆变换解 3941 次点击并派生 AES key/iv](ctf-reverse-android-ue-pak-encrypted-wasm-native-vm-co-simulation/) | verified | high | 2026-11-06 |
| [Android 内嵌 CPython 的加密 sitecustomize.py：从 .so 静态提取 AES-ECB 脚本并还原运算符重载 RC4 校验](ctf-reverse-android-embedded-python-sitecustomize-aes-rc4/) | verified | high | 2026-11-06 |
| [Android 多组件分段校验题：ContentProvider/广播/Deep Link 三通道取片段 + 自定义 Base64 + native 链式收口](ctf-reverse-android-multicomponent-fragment-chain-native-verify/) | verified | high | 2026-11-06 |
| [APK native NEON 校验逆向：vqtbl1q_s8 查表重排 + veorq_s8 异或 + 3 字节分组 ROR 与换表 Base64](ctf-reverse-apk-native-neon-vqtbl-shuffle-xor-ror-custom-base64/) | verified | high | 2026-11-07 |
| [APK native 三段校验逆解：TEA 16 轮 + GF(2^8) 矩阵求逆 + LCG 异或流](ctf-reverse-apk-native-tea-gf256-matrix-lcg/) | verified | high | 2026-11-06 |
| [APK native 自定义 RC4：S 盒初始化为 [1..255,0] + 6 字节 key，解出凭证后再反向 RLE 还原 flag](ctf-reverse-apk-native-custom-rc4-sbox-rle-credential/) | verified | high | 2026-11-07 |
| [APK 加密归档逆向：64 维低密度背包 LLL 还原选择向量，派生 ChaCha20 密钥解密 RBV2 归档](ctf-reverse-apk-knapsack-chacha20-vault/) | verified | high | 2026-11-05 |
| [APK 原生 ChaCha20 校验：识别 expand 常量与 counter=1 后异或还原 flag](ctf-reverse-apk-chacha20-counter-one-native/) | verified | high | 2026-11-06 |
| [APK 原生校验黑盒反推：Hook Java eq 与 native strcmp，用 XOR 线性关系消去 keystream](ctf-reverse-android-native-luajit-xor-keystream-cancel/) | verified | high | 2026-11-07 |
| [APK 多源参数派生 RC6 密钥：DEX 音律序列 + ELF 常量 + assets DB CRC 流](ctf-reverse-apk-rc6-base58-dex-db-derive/) | verified | high | 2026-11-06 |
| [APK 环境状态绑定校验：dex/签名哈希 + 资源 ID + 自定义 chunk 折叠为 VM keystream](ctf-reverse-android-apk-environment-state-derived-keystream/) | verified | medium | 2026-11-06 |
| [APK 签名 SHA1 作异或密钥：还原被 UI 隐藏的 flag](ctf-reverse-apk-signature-sha1-xor-key-hidden-flag/) | verified | high | 2026-11-06 |
| [ArkTS ABC 三步串联加密逆向：KSA 下标互换 + 加法替代异或的 RC4、单字节 RSA 与换表 Base64](ctf-reverse-arkts-abc-modified-rc4-addition-rsa-custom-base64/) | verified | medium | 2026-11-08 |
| [ArkTS ABC 双段 flag 逆向：长度偏移+索引递减变换与 Base64 反转，绕过百万次点击门控](ctf-reverse-arkts-abc-two-part-flag-string-transform/) | verified | medium | 2026-11-08 |
| [Autothink 组态工程逻辑逆向：FBD 迷宫位图还原与上升沿计数篡改](ctf-reverse-autothink-plc-project-maze-counter-tamper/) | verified | high | 2026-11-06 |
| [Base64 换表 + 索引魔改还原：先映射回标准表再按 key 逆运算](ctf-reverse-base64-table-index-mutation/) | verified | high | 2026-11-06 |
| [Brotli 内嵌前端 + RC4 + XTEA + XOR 掩码多层解密](ctf-reverse-brotli-embedded-js-rc4-xtea-xor/) | verified | high | 2026-11-07 |
| [Bukkit 插件用成就依赖链编码 flag 半字节：jadx 逆向与路径还原](ctf-reverse-bukkit-advancement-chain-nibble-encoding/) | verified | high | 2026-11-06 |
| [C#/.NET CTF 逆向：dnSpy 反编译、de4dot 去混淆与逐字节算术校验逆推](ctf-reverse-dotnet-dnspy-de4dot-arithmetic-inverse/) | verified | high | 2026-11-06 |
| [C++ 向量构造字节码的自定义 VM 逆向：4 条指令解释器与常量表异或](ctf-reverse-cpp-vector-bytecode-vm-constant-xor/) | verified | high | 2026-11-06 |
| [C++ 虚表构造函数混淆：魔改 TEA 生成状态掩码再异或还原输入](ctf-reverse-cpp-vtable-modified-tea-mask-xor/) | verified | high | 2026-11-06 |
| [Crackme 注册机：固定种子 srand 派生可预测 AES 密钥 + 对密文的校验和用填充字段暴破满足](ctf-reverse-crackme-fixed-srand-aes-key-checksum-padding-keygen/) | verified | high | 2026-11-08 |
| [CRC32 校验表缺失项恢复：reverse 求 4 字节原像 + 未知位置排列爆破，恢复 AES key](ctf-reverse-crc32-table-missing-entry-reverse-permutation/) | verified | high | 2026-11-09 |
| [CTF 勒索软件逆向：XOR 字符串 + CRC32 种子 + MT19937 流 XOR 解密](ctf-reverse-ransomware-xor-crc32-mt19937-keystream/) | verified | high | 2026-11-06 |
| [CTF 迷宫逆向：10×10 硬编码地图 WASD 移动校验，BFS 求最短路径后 MD5 得 flag](ctf-reverse-fixed-grid-wasd-maze-bfs-path-md5/) | verified | high | 2026-11-07 |
| [ctypes 加载原 PE 调用内部函数：GenKey/B90/D30 复用，Python 只逆 E70/B10](ctf-reverse-ctypes-load-pe-call-internal-functions/) | verified | high | 2026-11-06 |
| [Cython pyd 校验器盲测：替换模块函数返回值包装成「比较即打印」的 Symbol 对象，从 __eq__ 日志读出每段期望值，再枚举被掩码吃掉的高位补出 8 位 hex 输入](ctf-reverse-pyd-symbol-eq-oracle-masked-permutation-enumeration/) | verified | medium | 2026-11-08 |
| [DES-ECB 纯干扰：比较对象是 PKCS#7 填充后的明文 hex，不是密文](ctf-reverse-des-red-herring-pkcs7-padded-plaintext/) | verified | high | 2026-11-06 |
| [DOCM 宏用 certutil -decode 释放 PE：olevba 提取宏 + 位移 6/异或 7 校验逆运算](ctf-reverse-docm-vba-certutil-decode-shift-xor-check/) | verified | high | 2026-11-08 |
| [Electron asar + Rust WASM 许可证校验：32 位滚动哈希碰撞 + Z3 联立解锁输出约束](ctf-reverse-electron-asar-wasm-license-hash-collision-z3/) | verified | medium | 2026-11-06 |
| [ELF REL 可重定位目标文件差分重定位建模：未定义符号作输入位点还原仿射校验](ctf-reverse-elf-rel-differential-relocation-affine-model/) | verified | high | 2026-11-06 |
| [ELF 三层可逆校验逆解：256 字节 S-box + 前缀异或链 + 8 位重排](ctf-reverse-elf-sbox-rolling-xor-bit-permutation-inverse/) | verified | high | 2026-11-06 |
| [ELF 三阶段加密逆向：位交换/加减/XOR + .data 代码块复制到 RWX 页自解密](ctf-reverse-elf-rwx-selfdecrypt-staged-transform/) | verified | high | 2026-11-06 |
| [ESP32-S3 RF 发射固件逆向：JPEG COM 取频道/ID，Xtensa 还原 16 字节触发帧与校验](ctf-reverse-esp32-rf-trigger-frame-reconstruction/) | verified | high | 2026-11-06 |
| [exit(code) 返回下标当 oracle：把比较失败改成 exit(i)，用子进程返回码逐字节爆破 flag](ctf-reverse-exit-code-index-oracle-byte-brute/) | verified | high | 2026-11-08 |
| [FJM 高地址 RV32 状态机：逆向输入格式与 16-bit 状态约束恢复 flag body](ctf-reverse-fjm-rv32-state-machine/) | verified | high | 2026-11-06 |
| [FNV-1a 假 flag + 29 字节自定义逐字节变换逆解](ctf-reverse-fnv1a-decoy-29byte-transform-inverse/) | verified | high | 2026-11-06 |
| [FNV-1a 取模跳表分发 + 131 进制哈希反解：剔除假 flag 分支](ctf-reverse-fnv1a-jumptable-base131-hash/) | verified | high | 2026-11-06 |
| [GBA ROM 用 DMA 寄存器当布尔门：unary 按键编码 + 电路反解](ctf-reverse-gba-dma-boolean-circuit-unary-input/) | verified | high | 2026-11-06 |
| [gdb Python 黑盒逐字节明文爆破：断点监控加密输出，与已知密文逐字节比对还原 flag](ctf-reverse-gdb-blackbox-bytewise-plaintext-brute/) | verified | high | 2026-11-07 |
| [GFCTF 2021 wordy：jmp-db 花指令 EB FF C0 BF ?? 00 00 00 E8 批量 NOP 后重建 main 并自动提取 putchar 字符](ctf-reverse-gfctf2021-wordy-jmp-db-patch-putchar-extract/) | verified | high | 2026-11-09 |
| [GIF 像素打包为十进制大整数流：逆向还原图像与二维码](ctf-reverse-gif-pixel-shift-packing-integer-stream/) | verified | medium | 2026-11-06 |
| [Go CTF pic.exe：5 字符 RC4 密钥 + PNG 文件头已知明文爆破](ctf-reverse-go-pic-rc4-short-key-png-header-bruteforce/) | verified | medium | 2026-11-06 |
| [Go 程序 paper.bin 多层逆向：XOR/ROL 解包 + RC4-like 控制块 + 改造 XXTEA 参数派生](ctf-reverse-go-paper-bin-rc4-custom-xxtea-multilayer/) | verified | high | 2026-11-06 |
| [Go 魔改 SM4：FK 异或固定 MASK + 种子派生 16 字节 key 解密 .data 密文](ctf-reverse-go-modified-sm4-fk-mask-key-derivation/) | verified | high | 2026-11-06 |
| [Godot 4 单文件导出逆向：EXE 尾部 GDPC 内嵌 PCK + 40 字节头 AES-256-CFB 资源解密](ctf-reverse-godot4-embedded-pck-encrypted-resource-aes-cfb/) | verified | high | 2026-11-06 |
| [Godot GDExtension 伪 DLL 逆向：RC4 解密 + 12 字节热补丁跳转自解密 shellcode + 魔改 Base64/LCG 求逆](ctf-reverse-godot4-gdextension-rc4-hotpatch-shellcode/) | verified | high | 2026-11-06 |
| [Godot 游戏逆向：pck/gdc 解包反编译、12 位十进制编码还原与补丁重打包](ctf-reverse-godot-pck-gdc-decompile-patch-repack/) | verified | high | 2026-11-06 |
| [GPT-2 logits 序列反推输入：逐 token MSE 匹配与 loss 断崖剪枝](ctf-reverse-gpt2-logits-inversion-mse-token-recovery/) | verified | high | 2026-11-06 |
| [HarmonyOS 手势锁逆向：N-API verifyPattern 校验 + XXTEA 解 9 元组恢复解锁顺序](ctf-reverse-harmonyos-pattern-lock-napi-xxtea-recover/) | verified | medium | 2026-11-08 |
| [int3 调度基本块的控制流混淆：父进程 ptrace 转储结构体并重建 CFG](ctf-reverse-int3-basic-block-cfg-recovery/) | verified | high | 2026-11-07 |
| [Intel AMX 矩阵乘法实现的状态机逆向：64 符号转移 + 行和约束 BFS](ctf-reverse-intel-amx-matrix-state-bfs/) | verified | medium | 2026-11-06 |
| [iOS ARM64 Mach-O 游戏逆向：Unicorn 装载 + 用直接 actor handler 替换 Mach IPC，复现 RC4 解密](ctf-reverse-ios-macho-unicorn-mach-ipc-rc4/) | verified | high | 2026-11-06 |
| [iOS ARM64 无调试环境逆 Crypto 题：用 Unicorn 模拟 init 段机器码，从内存里直接取魔改 Base64 表与 RC4 解密结果](ctf-reverse-ios-arm64-unicorn-init-string-base64-table-rc4-decrypt/) | verified | high | 2026-11-09 |
| [iOS Mach-O Swift 九宫格手势逆向：路径数字串加权编码与 target_all 反查](ctf-reverse-ios-swift-nine-grid-path-weight-encoding/) | verified | high | 2026-11-06 |
| [Java String.hashCode 8 位数字授权码爆破：按 h*31+c 逐位枚举匹配 32 位目标](ctf-reverse-java-string-hash-8digit-bruteforce/) | verified | high | 2026-11-06 |
| [keygenme 序列号校验逆向：128 hex→16 DWORD、16 个固定密钥、XOR 链式(extra=前一密文块)解密、CRC32 校验与注册机编写（movzx/movsx 差异）](ctf-reverse-keygenme4-xor-chain-crc32-keygen/) | verified | medium | 2026-11-07 |
| [KeygenMe 魔改 XTEA 自耦合校验 trick：KEY[0] 既是密钥又是密文（sign 加密结果须等于 KEY[0]），固定其余密钥字 + 多线程按线程号切高位暴力 KEY[0]](ctf-reverse-keygenme-xtea-self-referential-key-bruteforce/) | verified | high | 2026-11-08 |
| [LinuxChal 多层逆向：花指令修复 + XOR 0x27 内嵌 ELF + 魔改 RC4 数组 + z3 解 NAND 电路](ctf-reverse-linux-junk-xor-embedded-elf-nand-circuit-z3/) | verified | high | 2026-11-06 |
| [Love2D 游戏 lovely-injector 注入逆向：改 dump_all 标志导出 LuaJIT 字节码并反编译](ctf-reverse-love2d-lovely-injector-luajit-dump-decompile/) | verified | high | 2026-11-07 |
| [Lua 5.3 字节码逆向：循环异或解密 + unluac + RC4/XOR 逆推](ctf-reverse-lua53-bytecode-xor-rc4/) | verified | high | 2026-11-06 |
| [memcmp 长度写错只比 2 个 int：菜单状态机逆向 + reward 变换还原 flag](ctf-reverse-memcmp-length-bug-state-machine-reward/) | verified | high | 2026-11-06 |
| [MIPS CTF 逆向 ereere：字符串定位换表 Base64 与标准 RC4，按加密顺序逆解出 flag](ctf-reverse-mips-rc4-custom-base64-ereere/) | verified | high | 2026-11-08 |
| [MMX/SIMD 字节级块加密逆运算：XOR→奇偶交换→循环左移→逐字节加 key](ctf-reverse-mmx-simd-block-xor-swap-rot-add/) | verified | high | 2026-11-07 |
| [M·CORE 固件逆向：先 RC4（key=testkey）再对结果做「从后往前累加异或」，倒序一次即可还原 flag](ctf-reverse-mcore-rc4-then-reverse-cumulative-xor/) | verified | medium | 2026-11-08 |
| [NCTF 2022 cccha：三类花指令（call $+5 改返回地址、jmp db、抵消式）patch 后识别 ChaCha20 恢复密钥流](ctf-reverse-nctf2022-cccha-flower-patch-chacha20/) | verified | high | 2026-11-09 |
| [NRO 顶点缓冲重绘：按 6 float/顶点 + 三角形光栅化还原白字 flag](ctf-reverse-nro-vertex-buffer-rasterization-text/) | verified | high | 2026-11-06 |
| [obfusheader.h 花指令混淆动调：内存断点定位 memcmp，转储 rand 值与密文逆半字节交换/取反/16 位 XOR](ctf-reverse-obfusheader-dynamic-memcmp-rand-xor-nibble-swap/) | verified | high | 2026-11-07 |
| [ONNX ViT 后门逆向：图差分定位 flag 常量 + 逐层逆 Transformer 重建触发图](ctf-reverse-onnx-vit-backdoor-flag-constant-inversion/) | verified | high | 2026-11-07 |
| [ONNX 模型 DCT 频域触发器逆向：构造频点命中触发图像](ctf-reverse-onnx-dct-frequency-trigger/) | verified | high | 2026-11-06 |
| [PE 隐藏初始化改写 .data 中的 AES 密钥：静态/运行时内存差分恢复 XOR 补丁并解密](ctf-reverse-pe-runtime-data-patch-aes-key-diff/) | verified | high | 2026-11-06 |
| [PELoader 内存 dump 脱壳 + 自定义 64 位 ARX 轮函数逆序还原 16 字节口令](ctf-reverse-peloader-dump-custom-arx-round-inverse/) | verified | high | 2026-11-07 |
| [PNG 蓝通道 LSB 提取自定义 S-box：复现 AES-256 变体解密 flag](ctf-reverse-png-lsb-custom-sbox-aes256-decrypt/) | verified | high | 2026-11-06 |
| [PyInstaller + pyarmor 1shot 还原源码：逆自定义 XTEA 与 Carlotta 变换解密](ctf-reverse-pyarmor-pyinstaller-custom-xtea-carlotta/) | verified | high | 2026-11-07 |
| [PyInstaller 提取 marshal code object 后逆 XXTEA/btea 分组加密](ctf-reverse-pyinstaller-marshal-btea-xxtea-decrypt/) | verified | high | 2026-11-06 |
| [Python 3.13 自定义 VM 逆向：隐藏容器解密 + 逐字节分支 oracle 求解](ctf-reverse-python-vm-hidden-container-branch-oracle/) | verified | high | 2026-11-06 |
| [Python 逆向：monkey-patch str.__eq__ 记录 flag 校验的比较对](ctf-reverse-python-str-eq-monkey-patch-comparison-log/) | verified | high | 2026-11-06 |
| [RC4 变种 S[i]=~i + (P⊕X)+A：用全 0/全 255 加密 oracle 反推 keystream 解密 PNG](ctf-reverse-rc4-inverted-sbox-add-xor-oracle-keystream/) | verified | high | 2026-11-06 |
| [Rust ELF 后门魔改 AES-128-CBC：自定义 S-box 与 ShiftRows，逆向外带流量解密 flag](ctf-reverse-custom-aes-sbox-shiftrows-c2-traffic-decrypt/) | verified | high | 2026-11-06 |
| [SHA256 三字节滑动窗口 + 二叉搜索树乱序密文的逆向：3 字符爆破与 2 字节重叠链还原 flag](ctf-reverse-sha256-sliding-window-bst-bruteforce/) | verified | medium | 2026-11-07 |
| [SMC 自解密 + 魔改 XXTEA：mix 改成同一变量双移位项，运行时 Attach 取真代码后逆轮](ctf-reverse-smc-runtime-attach-xxtea-same-var-double-shift-mix/) | verified | medium | 2026-11-08 |
| [so .rodata 内嵌加密 dex 分段广播拼装：dump 后 jadx 提取隐藏校验逻辑](ctf-reverse-android-native-embedded-encrypted-dex-segment-dump/) | verified | high | 2026-11-08 |
| [SPARC 大端 ROM 逆向与 ChaCha8 魔改验证：fake_flag XOR 密文再 XOR keystream](ctf-reverse-sparc-rom-chacha8-fakeflag-xor/) | verified | high | 2026-11-06 |
| [SQLCipher 加密库密钥恢复：应用内多层编码藏 key 后 PRAGMA 解密导出](ctf-reverse-android-sqlcipher-key-recovery-export/) | verified | high | 2026-11-08 |
| [Swift String 迭代引发的 UTF-8 重编码混淆：c2/c3 前缀还原后逆向多层加密链](ctf-reverse-ios-swift-utf8-reencode-obfuscation-chain/) | verified | high | 2026-11-08 |
| [Switch NRO 尾部追加 JPEG：按 SOI/EOI 边界 carve 提取隐藏图片](ctf-reverse-nro-appended-jpeg-carving/) | verified | high | 2026-11-06 |
| [Telink TC32 固件逆向：CRC-CCITT 约束恢复 AES key + 解密数据区还原双 QR](ctf-reverse-telink-tc32-crc-aes-qr/) | verified | high | 2026-11-06 |
| [time(0) 时间种子 + 双轮 65537 次洗牌与自定义 mix：按样本 mtime 窗口爆破 seed 并逆变换](ctf-reverse-time-seed-shuffle-mix-bruteforce-mtime/) | verified | high | 2026-11-06 |
| [Tracr 编译 Transformer 逆向：pickle/zstd stub 反序列化 + NumPy 前向 + residual_labels](ctf-reverse-tracr-transformer-residual-labels/) | verified | high | 2026-11-06 |
| [Twofish 逆向：Q-box/MDS 查表识别、dump 表与逆向 16 轮 Feistel](ctf-reverse-twofish-table-dump-decrypt/) | verified | high | 2026-11-06 |
| [Unicorn 用户态仿真 Android ARM64 JNI .so：伪造 JNIEnv/Java String 与导入桩，构建离线加解密 oracle](ctf-reverse-android-arm64-jni-unicorn-offline-oracle/) | verified | high | 2026-11-06 |
| [UPX 脱壳 + PE .data 参数提取 + LCG 可打印字符环移逆推（OR 分支只解快分支）](ctf-reverse-upx-pe-data-lcg-printable-shift-or-branch/) | verified | high | 2026-11-06 |
| [UPX 自定义 VM 逆向：PE 段表 VA 映射补零 + 不可达解密路径的 rol/xor/ror 求逆](ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse/) | verified | high | 2026-11-06 |
| [UPX 自解压 ELF 内存 dump + VM 逐字符可逆变换反推（滚动 hash 与 pair check 复核）](ctf-reverse-upx-vm-rolling-hash-per-char-inversion/) | verified | high | 2026-11-06 |
| [VM 加密器逆向：core dump 恢复运行时上下文 + 两阶段 VM 变换逆序求逆](ctf-reverse-vm-encryptor-core-context-two-stage-inverse/) | verified | high | 2026-11-06 |
| [VM 单字节校验的插桩侧信道爆破：Frida hook opcode 分发计数 / Pintools 指令计数，逐位选执行路径最长的字符](ctf-reverse-vm-instrumentation-instruction-count-bruteforce/) | verified | high | 2026-11-06 |
| [VM 解释器中的 TEA 识别与解密：从 opcode 分发器还原 sum/delta 轮函数，按魔改 delta 与 36 轮反推 flag](ctf-reverse-vm-tea-interpreter-recovery/) | verified | high | 2026-11-06 |
| [VM 题 opcode 编码还原：首字节低 2 位选操作数解析格式（1 字节/2 字符/字符+qword/3 字节大端拼装）、高 6 位选 handler](ctf-reverse-vm-opcode-low2-format-high6-dispatch/) | verified | high | 2026-11-08 |
| [WASM 前端登录时间戳签名：覆盖 Date.now 在给定时间窗内爆破 MD5 前缀](ctf-reverse-wasm-login-date-now-timestamp-bruteforce/) | verified | high | 2026-11-06 |
| [WASM 前端登录校验逆向：FNV-1a 用户名 + 8 轮 Feistel 逆解密码 + xorshift64* 密钥流解密](ctf-reverse-wasm-login-fnv1a-feistel-xorshift-keystream/) | verified | high | 2026-11-06 |
| [xorshift Fisher-Yates 逆置换 + 38 字节自定义变换逆解](ctf-reverse-xorshift-fisher-yates-inverse-permutation-38byte-transform/) | verified | high | 2026-11-06 |
| [XXTEA 魔改 delta 0x87654321 + 异或循环移位派生密钥：按自定义 mix 与 42 轮逆推](ctf-reverse-xxtea-custom-delta-derived-key/) | verified | high | 2026-11-07 |
| [Z3 BitVec 建模复杂 flag 校验：字节变换 + SWAR popcount + SplitMix64 哈希约束求解](ctf-reverse-z3-bitvec-popcount-splitmix64/) | verified | high | 2026-11-07 |
| [Z3 求解逆向题约束方程组：按变量表取值，注意移位与逻辑或](ctf-reverse-z3-constraint-equation-solve/) | verified | high | 2026-11-06 |
| [三关串联校验逆向：魔方公式密钥 + FNV1a32、五元线性方程组与 seed 派生动态迷宫](ctf-reverse-multi-stage-cube-fnv1a-linear-system-dynamic-maze/) | verified | medium | 2026-11-06 |
| [不逆算法，直接 GUI 自动化通关：pyautogui 点击+输入 + pywinauto UIA 读弹窗文本，用「已访问集合」剪枝跑 BFS](ctf-reverse-ui-automation-pyautogui-pywinauto-game-solve/) | verified | medium | 2026-11-08 |
| [两层 SMC 手剥流程：动调改 eax 绕反调试、NOP 掉花指令 jmp、取 sum 后按魔改 TEA（key 先 XOR 0x52）解出前半段，后半段再补 Caesar 逆移](ctf-reverse-double-layer-smc-antidebug-junk-tea-key-xor-caesar/) | verified | medium | 2026-11-09 |
| [主函数为空、逻辑藏在 atexit/全局析构：按注册逆序还原 rot13 + DCT 校验管线并反变换](ctf-reverse-atexit-reverse-order-dct-coefficients-rot13/) | verified | medium | 2026-11-08 |
| [二次多项式索引交换图像加密逆向：RGB 通道逐轮还原 + 轮数爆破](ctf-reverse-quadratic-swap-image-encryption-rounds/) | verified | high | 2026-11-06 |
| [仓颉(Cangjie)二进制逆向：StringBuilder::append 切片定位 7 段可逆字符变换，二叉树 DFS 打印顺序错位后重排还原](ctf-reverse-cangjie-segment-transform-btree-print-order/) | verified | medium | 2026-11-08 |
| [像素低 4 位方向编码的 10x10 迷宫逆向：XOR 0x7f 解密 + BFS 求路径](ctf-reverse-pixel-low-nibble-direction-maze-bfs/) | verified | high | 2026-11-06 |
| [列换位（columnar）密钥派生与双阶段输入校验逆向：HDB3 统计的全零绕过](ctf-reverse-columnar-transposition-two-stage-check/) | verified | medium | 2026-11-06 |
| [加密 SQLite 资源库逆向：点击序列→TEA/CRC32 tag→CRC32 流解密→seed 驱动改版 RC6](ctf-reverse-tag-crc32-encrypted-sqlite-seed-rc6/) | verified | medium | 2026-11-06 |
| [可打印 ASCII 链式 Caesar + 异或隐藏置换表的 16 轮矩阵变换逆向](ctf-reverse-printable-ascii-caesar-hidden-permutation-table/) | verified | low | 2026-11-06 |
| [可预测分数派生 AES key/IV：从高分值解密硬编码密文](ctf-reverse-predictable-score-derived-aes-key-iv/) | verified | high | 2026-11-06 |
| [右移一位约束 + MD5 校验：笛卡尔积爆破恢复 flag](ctf-reverse-right-shift-constraint-md5-bruteforce/) | verified | high | 2026-11-06 |
| [多 witness 残缺约束 + Base32 字符集枚举：32^5 空间恢复 5 个未知字符](ctf-reverse-multi-witness-partial-constraint-base32-enumeration/) | verified | medium | 2026-11-06 |
| [多层字节变换逆向：S 盒→ROR2→mod257 逆元→半字节线性映射→ROL3/XOR→按下标 ROL 的逆序还原](ctf-reverse-bytewise-multilayer-sbox-rot-nibble-mod257-inverse/) | verified | medium | 2026-11-07 |
| [多阶段 PE + 自定义 VM 魔改 SM4 逆向](ctf-reverse-multistage-pe-vm-modified-sm4/) | verified | high | 2026-11-06 |
| [字节对加法+ROL8+缓冲区轮转的五轮可逆变换逆向：解析求逆与诱饵串识别](ctf-reverse-byte-pair-add-rol8-buffer-rotate-inverse/) | verified | high | 2026-11-06 |
| [字节数组逆变换：每字节减 10 再异或 100 还原 flag](ctf-reverse-byte-subtract-xor-100/) | verified | high | 2026-11-08 |
| [微信小程序 VIN 校验变种 RC4 逆向：反向 KSA + 位置异或解密](ctf-reverse-miniprogram-variant-rc4-reverse-ksa/) | verified | high | 2026-11-06 |
| [微信小程序 wxapkg 未加密直接读取：ROR 位数取密钥和 + 循环异或校验的逆推](ctf-reverse-miniprogram-wxapkg-ror-xor-hardcoded-array/) | verified | high | 2026-11-07 |
| [微信小程序包内嵌 WASM 段提取：按 00 61 73 6D 魔数 dump，IDA 9 解析后 XOR 0x99 解出 flag](ctf-reverse-wechat-miniprogram-embedded-wasm-extract-xor/) | verified | medium | 2026-11-07 |
| [恶意样本 killswitch 域名解密：复现 7*n+66 密钥生成循环 + Base64 + 循环 XOR](ctf-reverse-xor-keygen-base64-killswitch-decrypt/) | verified | high | 2026-11-07 |
| [投毒 bash 后门 DSMV 协议逆向：自定义帧 + VM 字节码 + RSA 块变换还原外带](ctf-reverse-trojan-bash-dsmv-vm-rsa-exfil/) | verified | high | 2026-11-06 |
| [按调用点反堆栈取异或键，用 IDC PatchByte 批量还原被 XOR 加密的代码段](ctf-reverse-idc-patch-xor-encrypted-code-segment/) | verified | medium | 2026-11-08 |
| [损坏驱动 PE 修复与两轮链式异或逆向：每 4 字节 XOR 0x44 + z3 多解约束](ctf-reverse-pe-driver-4byte-xor-repair-chained-xor-z3/) | verified | high | 2026-11-06 |
| [换表 Base64 + 轮密钥 XOR 两层编码逆向：先 translate 解码，再按 key[i%5] 异或还原（勿额外加索引）](ctf-reverse-base64-custom-table-then-repeating-xor/) | verified | high | 2026-11-06 |
| [改版 UPX 壳 + 加法收尾 RC4：修补 magic 后同构解密](ctf-reverse-upx-magic-rc4-addition-decrypt/) | verified | high | 2026-11-06 |
| [文件驱动地图 VM 逆向：状态机复刻 + A* 搜索生成通关行动文件](ctf-reverse-zhie-map-vm-search/) | verified | high | 2026-11-06 |
| [木马标准 SM4 密钥逆向：握手 4 字节种子经 glibc srand/rand 生成 128 位密钥](ctf-reverse-sm4-srand-seed-key-schedule/) | verified | medium | 2026-11-06 |
| [标准 SM4 逆向识别：FK/CK/Sbox 常量定位与小端字序解密](ctf-reverse-sm4-constant-recognition-little-endian-decrypt/) | verified | high | 2026-11-05 |
| [校验状态与明文字节耦合导致不可逆：正向逐位爆破 + 双字结对缩小候选 + 语义猜解收尾](ctf-reverse-state-chained-plaintext-forward-brute-multi-solution/) | verified | medium | 2026-11-09 |
| [校验逻辑藏在内嵌 PE 的可执行文件里：把 flag 当「贪吃蛇通关走位」解——按分数曲线反推投食时机，用命名管道协议重建对局求解](ctf-reverse-embedded-game-validator-pipe-snake-path-solve/) | verified | low | 2026-11-08 |
| [混淆校验函数逐轮字节枚举：复刻状态机匹配目标字节表](ctf-reverse-obfuscated-state-machine-per-round-byte-enumeration/) | verified | high | 2026-11-06 |
| [白盒 AES 运行时表重建与按列 MITM 逆向：Polaris 混淆外壳下的 10 轮查表](ctf-reverse-whitebox-aes-runtime-table-reconstruction-mitm/) | verified | high | 2026-11-06 |
| [程序把 argv 里的 flag 前缀逐字符加密后按 hex 打印：每位密文互相独立，直接对每一位枚举可打印字符、比对目标 hex 对即可还原 flag](ctf-reverse-per-char-hex-ciphertext-argv-prefix-brute/) | verified | medium | 2026-11-08 |
| [素数约束时间 + 三素数 RSA 变体：用目标自带 GMP 枚举时间并解密两段密文](ctf-reverse-prime-constrained-time-three-prime-rsa/) | verified | high | 2026-11-06 |
| [自修改 VM 字节码解密 + PATCH/DATAXOR + Z3 符号执行恢复 16 字节输入](ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution/) | verified | high | 2026-11-06 |
| [自定义 Python VM 字节码逆向：反汇编器与多轮变换逆推](ctf-reverse-custom-python-vm-bytecode-disassembler/) | verified | high | 2026-11-06 |
| [自定义 S 盒流密码逆向：魔改 KSA 条件索引 + ROR3 密钥流 + 前后异或链解密](ctf-reverse-custom-sbox-stream-cipher-ror-keystream/) | verified | high | 2026-11-07 |
| [自定义 SM4 变体逆向：24 轮 + 自定义 S-box/FK/CK 的 native .so 解密](ctf-reverse-custom-sm4-24round-native-so-decrypt/) | verified | high | 2026-11-06 |
| [自定义 VM 字节码逆向：VM 上下文/ISA 恢复 + rol24 XOR 混淆 Base64 求逆](ctf-reverse-custom-vm-isa-rol24-xor-base64-inverse/) | verified | high | 2026-11-06 |
| [自定义 VM 校验器逆向：掩码 opcode + 可逆指令反向执行恢复 witness](ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery/) | verified | high | 2026-11-06 |
| [自定义 VM 还原 + TEA-like 30 轮加密：按 4 字节块暴力枚举可见字符解 flag](ctf-reverse-custom-vm-tea-like-30round-block-bruteforce/) | verified | high | 2026-11-06 |
| [自定义 VMC2 寄存器虚拟机逆向：从 handler 抠精确 ISA + 逐轮可逆 ARX 求逆（字节内存/8 位 rotate/STAGE S-box/非零初值）](ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx/) | verified | high | 2026-11-06 |
| [自定义栈式 VM 字节码逆向：跳转表还原 15 条指令，逐字符约束反解 flag](ctf-reverse-custom-stack-vm-bytecode-constraint-recovery/) | verified | high | 2026-11-06 |
| [输入前两字节作 LFSR 初值的密钥流异或：反馈位移位 + ROL + 位交换逐字节还原](ctf-reverse-lfsr-derived-keystream-bit-swap-xor/) | verified | high | 2026-11-08 |
| [输出回显当进度条：程序打印的递增字符/星号数量即前缀匹配长度，逐字节枚举还原 flag（含 VM 双字节变体）](ctf-reverse-output-prefix-oracle-byte-brute/) | verified | high | 2026-11-08 |
| [逆向嵌入 shellcode 生成 AES-256 密钥：从 .rodata 机器码提取 32 字节 key 并用 AES-CBC 解密](ctf-reverse-embedded-shellcode-builds-aes256-key-cbc-decrypt/) | verified | high | 2026-11-07 |
| [逆向自实现的类 RC4 分组加密：定位 20 轮异或+字节置换的轮函数，从 .rodata 取密钥常量后写逆运算程序直接还原明文](ctf-reverse-custom-block-cipher-round-inverse-key-constant/) | verified | high | 2026-11-08 |
| [逐字符加盐 MD5 爆破：识别 decoy 路径并按位置枚举字符](ctf-reverse-per-char-salted-md5-bruteforce-decoy-path/) | verified | high | 2026-11-06 |
| [逐字节乘法+整体反转的 26 字节校验逆向：允许字符集内枚举求逆](ctf-reverse-byte-multiply-reverse-26-byte-check-inverse/) | verified | high | 2026-11-06 |
| [静态 ELF 栈上成对常量异或还原隐藏 flag](ctf-reverse-elf-stack-constants-xor-hidden-flag/) | verified | high | 2026-11-06 |
| [静态取初始密文 + Base58 解码 + 单字节 XOR 爆破还原 flag](ctf-reverse-base58-xor-key-bruteforce/) | verified | high | 2026-11-07 |
| [魔改 AES 逆向：差分定位 MixColumns 额外异或 0x55，改标准 AES 写注册机](ctf-reverse-aes-mixcolumns-extra-xor-0x55/) | verified | high | 2026-11-07 |
| [魔改 Base64 只打乱组内字符位置（每组第 2/3 位对调）：与标准编码比对找出换位规律后换回再解码](ctf-reverse-base64-group-char-swap-position-permutation/) | verified | medium | 2026-11-09 |
| [魔改 RC4 识别与解密：轮数/S 盒初始化改动需逐处同步](ctf-reverse-modified-rc4-rounds-sbox/) | verified | high | 2026-11-06 |
| [魔改 RC4 逆运算：20 字节密钥表重复 256、PRGA 后先减 0x71 再异或 keystream](ctf-reverse-modified-rc4-keytable-subtract-xor/) | verified | high | 2026-11-07 |
| [魔改 RC5 识别与解密：自定义 P32/Q32 轮常量 + 12 轮 + 半块交换逆推](ctf-reverse-modified-rc5-custom-p32-q32/) | verified | high | 2026-11-07 |
| [魔改 SHA-512 常量 + PBKDF2 + 非标准 RC4 KSA：VMP 脱壳后解密 flag.enc](ctf-reverse-modified-sha512-pbkdf2-nonstandard-rc4-decrypt/) | verified | high | 2026-11-06 |
| [魔改 SM4 逆向：轮函数额外异或 TEA delta + 双层 Base64 还原 rawfile 加密图片](ctf-reverse-sm4-round-extra-xor-tea-delta-rawfile-image/) | verified | medium | 2026-11-08 |
| [魔改 TEA 逆向：delta 取 GetTickCount 但环境固定为 0x68547369，按 48 轮逆推解密](ctf-reverse-tea-delta-gettickcount-fixed-value/) | verified | high | 2026-11-07 |
| [魔改 TEA 逆向：自定义 delta 0x897354D2 + 密钥 [2,0,2,2] 的 32 轮小端解密](ctf-reverse-modified-tea-custom-delta-little-endian-decrypt/) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。

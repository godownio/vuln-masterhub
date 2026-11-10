# 固件逆向

## 这层是什么

固件提取、文件系统、启动链、模拟/仿真与漏洞分析（含 IoT 固件）。

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
| [8051 + EEPROM 固件逆向：逐指令模拟还原 AUTH/MAC 状态机，暴力 nonce 后解密 EEPROM 记录](code-analysis-reverse-firmware-8051-eeprom-protocol-mac.md) | verified | high | 2026-11-05 |
| [ARM32 固件双环境仿真：qemu-arm-static chroot 跑 boa httpd（补 boa.conf/hosts 修 gethostbyname）+ qemu-system-arm versatile 桥接网络](code-analysis-reverse-firmware-arm32-qemu-user-and-system-dual-env-boa-hosts.md) | verified | high | 2026-11-08 |
| [ARM32 路由器固件 qemu-user chroot 模拟：patch 网络等待死循环 + br0 绑定 httpd](code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0.md) | verified | high | 2026-11-07 |
| [D-Link DIR-816 goahead 固件仿真：binwalk 解包 + qemu-mipsel chroot，补 pid 文件与 libnvram/patch 启动 Web](code-analysis-reverse-firmware-dlink-dir816-goahead-qemu-mipsel-emulation.md) | verified | high | 2026-11-08 |
| [DrayTek Vigor3910 固件解密：THUNDER 分段定位 FIP、bl33 ChaCha20 与 LZ4/cpio 解包](code-analysis-reverse-firmware-draytek-vigor3910-fip-chacha20-lz4-cpio.md) | verified | high | 2026-11-07 |
| [FortiGate 固件提取、patch init 绕过校验并借 diagnose smartctl 挂 shell](fortigate-firmware-patch-smartctl-shell.md) | draft | high | 2026-11-08 |
| [Ivanti coreboot.img initrd 解密：内核 populate_rootfs 内 XOR 派生 AES key + 扇区号 IV 的链式分组解密](code-analysis-reverse-firmware-ivanti-coreboot-initrd-xor-key-sector-iv-decrypt.md) | verified | high | 2026-11-07 |
| [jhttpd CGI 路由表提取：IDAPython 按 0x14 步长遍历 httpd_cgi_all_fun，解析路径字符串与 handler 函数建立路由映射](code-analysis-reverse-firmware-jhttpd-cgi-table-idapython-dump.md) | verified | high | 2026-11-08 |
| [MIPS 路由器固件系统级仿真：QEMU malta + binwalk rootfs + 桥接网络 + httpd](code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd.md) | verified | high | 2026-11-06 |
| [OpenSSL 加密 IoT 固件的提取与字典爆破：binwalk 定位 offset/salt，openssl enc -d -aes-256-cbc -pbkdf2 逐字典试解，成功后再 binwalk 提取](code-analysis-reverse-firmware-openssl-salted-extract-dictionary-bruteforce.md) | verified | high | 2026-11-09 |
| [OpenWrt 固件取证：binwalk 拆 SquashFS + JFFS2 overlay/sysupgrade.tgz 恢复 /etc 配置](code-analysis-reverse-firmware-openwrt-squashfs-jffs2-overlay.md) | verified | high | 2026-11-07 |
| [QEMU user-mode MIPS 固件仿真：LD_PRELOAD 伪造 apmib 依赖 + gdb 远程调试](code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb.md) | verified | high | 2026-11-06 |
| [STM32 HAL 固件函数识别：RCC 系统时钟计算与 GPIO BSRR digitalWrite](code-analysis-reverse-firmware-stm32-hal-function-identification.md) | verified | high | 2026-11-06 |
| [Synology TC500 .sa.bin 固件解包与 QEMU user-mode 仿真：construct 头解析 + UBI/SquashFS 提取 + webd 运行](code-analysis-reverse-firmware-synology-sa-bin-construct-ubi-qemu-user.md) | verified | high | 2026-11-07 |
| [VMware 挂起内存 vmem 等长字符串补丁：替换控制台脚本路径获取加密设备 Shell](code-analysis-reverse-firmware-vmem-patch-console-script-shell.md) | verified | high | 2026-11-06 |
| [VxWorks 初始化结构恢复基址：_sysInit 初始栈指针与 usrInit BSS 清零](code-analysis-reverse-firmware-vxworks-base-sp-bss.md) | verified | high | 2026-11-06 |
| [VxWorks 固件加载基址恢复：switch 跳转表绝对地址减文件偏移](code-analysis-reverse-firmware-vxworks-base-jump-table.md) | verified | high | 2026-11-06 |
| [VxWorks 符号表/字符串表恢复加载基址：符号名地址减字符串偏移 + IDA 脚本恢复函数名](code-analysis-reverse-firmware-vxworks-symbol-table-base.md) | verified | high | 2026-11-06 |
| [ZKTeco 固件更新包静态还原：DataX 十六进制转字节 + zkfp_ExtractPackage 以包尾/包长派生 XOR 密钥解密](code-analysis-reverse-firmware-zkteco-updatepackage-xor-keysize-decrypt.md) | verified | medium | 2026-11-08 |
| [利用嵌入式设备内置 node 执行 js 下载 busybox 赋权并恢复反弹 shell](embedded-nodejs-busybox-shell-recovery.md) | draft | high | 2026-11-08 |
| [剥离符号 U-Boot 固件逆向：同版本源码编译 + BinDiff 恢复 main_loop 符号，逆 XOR 0x72 与自定义 Base58 表](code-analysis-reverse-firmware-uboot-bindiff-symbol-custom-base58.md) | verified | high | 2026-11-07 |
| [加密固件尾部成片 0x80 反推单字节 XOR 密钥（0x7F）：解出后 binwalk 可正常解包，并定位刷机程序 rg-upgrade-crypto 验证](code-analysis-reverse-firmware-tail-0x80-single-byte-xor-decrypt.md) | verified | medium | 2026-11-09 |
| [华为魔改 SquashFS 固件解包与 MIPS 服务仿真](code-analysis-reverse-firmware-huawei-squashfs-mips-emulation.md) | verified | high | 2026-11-04 |
| [固件仿真挖掘硬编码 telnet 后门：WayOS mqtt_ai 的 mqtt_ai_sw_telnet_login 与 /etc_ro/rcS 自启](code-analysis-reverse-firmware-wayos-mqtt-ai-hardcoded-telnet-backdoor.md) | verified | medium | 2026-11-08 |
| [固件升级包 AES-128-ECB 解密：16 字节 passwd 与 4 字节 xor_key 派生密钥](code-analysis-reverse-firmware-aes-ecb-key-xor-header-decrypt.md) | verified | high | 2026-11-06 |
| [固件里定位后门程序并取硬编码 C2：文件系统提取 → 关键字扫 backdoor/password → UPX 脱壳 → 追 connect 参数](code-analysis-reverse-firmware-backdoor-binary-upx-c2-extraction.md) | verified | medium | 2026-11-08 |
| [小米 AX9000（AArch64）UBI 固件解包、Lua 反编译与 QEMU 系统级仿真](code-analysis-reverse-firmware-xiaomi-ax9000-ubi-aarch64-qemu-emulation.md) | verified | high | 2026-11-06 |
| [自定义固件包 NOE-FWP 逆向：updater KDF 解 AES-256-CBC 载荷，恢复 Feistel/Digest/校验和三处被抹字段](code-analysis-reverse-firmware-custom-package-aes-kdf-field-recovery.md) | verified | high | 2026-11-05 |
| [锐捷 EW 固件 QEMU mipsel 系统级仿真跑起 unifyframe-sgi：bind proc/dev + chroot 启 ubusd/lighttpd，再 gdbserver --attach 远程跟 Lua→libuflua→ufm_popen 链路](code-analysis-reverse-firmware-ruijie-ew-ex-qemu-mipsel-gdbserver-attach.md) | verified | medium | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。

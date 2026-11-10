---
id: code-analysis-reverse-firmware-backdoor-binary-upx-c2-extraction
title: 固件里定位后门程序并取硬编码 C2：文件系统提取 → 关键字扫 backdoor/password → UPX 脱壳 → 追 connect 参数
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: firmware-backdoor-binary-upx-hardcoded-c2-extraction
tags:
- reverse
- firmware
- iot
- backdoor
- upx
- hardcoded-credential
- c2
- ida
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:25:31+08:00'
  notes: 已对照原文核对；本次核对未读取图片；多层提取文件系统、按 backdoor/password 关键字扫字符串、UPX 壳检测与脱壳、追 connect 参数取硬编码 C2 与端口，均与原文流程一致；未验证点：C2 域名与端口（echo.byethost51.com:36667）及 PowerPC 大端段/IDC 恢复脚本、ftpuser 与 icspwd 等具体结论均在未读取的截图中，卡内仅保留了方法链
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-backdoor-binary-upx-c2-extraction/
draft: false
kb_aliases:
- 固件后门程序分析
- 找后门使用的远程服务器和端口
- 固件文件系统 grep backdoor
- UPX 脱壳后门
- 硬编码 C2 提取
- 工控固件逆向
---

## 一句话结论

拿到固件后先"多级提取"出文件系统，再用 `backdoor`/`password`/`passwd` 这类语义关键字在整个根文件系统里 grep 出可疑可执行文件；若该文件是 UPX 压缩壳，先脱壳再反汇编，然后用"字符串里出现的主机名/端口"回溯到调用 `connect()` 的函数，即可确定后门硬编码的 C2 地址与端口（本例 `echo.byethost51.com:36667`）。

## 原理

- **固件是层层封装的容器**：一个 `.bin` 往往先是厂商头 + 压缩/加密段，可能套 squashfs/jffs2/ubi/cpio 中的一种或多种，`binwalk -e` 一次解不出文件系统是常态（本例第一次只解出一个 217 字节的分区/镜像片段）。必须先确认每段的类型与架构，再按段单独解，才能拿到 `/bin`、`/etc`、`/tmp` 等目录。
- **后门不会藏得很深，但会藏得很"像正常程序"**：工控/IoT 固件里投的后门通常是一个静态编译的小程序，放在 `/tmp`、`/usr/sbin`、`/etc/init.d` 之类会被启动脚本带起的位置。用 `find . | xargs grep -ri backdoor` 或 `grep -ri password` 扫的是**字符串常量**，因为这类程序一定会引用自己的名字、配置文件名或口令字面量，字符串扫描比逐个反汇编快几个数量级。
- **UPX 壳会让静态分析"看起来没有函数"**：UPX 压缩后的入口是解压 stub，IDA 打开后只有一小段 stub 和一段高熵数据，`strings` 也读不到明文。判壳特征很直接：文件头 section 名为 `UPX0`/`UPX1`、`upx -l` 能列出、`binwalk`/`strings` 里出现 `UPX!`；`upx -d` 脱壳后 section 与导入表恢复，IDA 才能正常识别函数与字符串。
- **硬编码 C2 一定出现在"构造 sockaddr 的地方附近"**：程序要么用字符串常量拼出域名后 `gethostbyname`，要么把 IP 直接写成 4 字节常量。无论哪种，域名/端口的字符串常量都会在 `.rodata` 里、被某个函数以 `lea`/`mov` 取地址后传给 `connect()`/`sendto()`；从字符串交叉引用（XREF）往回追一两跳就能定位到那处调用，从而同时读出"目标地址 + 端口"。
- **端口常量常以网络字节序立即数出现**：`36667` 在代码里是 `0x8F3B`，网络字节序写作 `htons(36667)`，反汇编里常表现为 `mov ..., 0x3B8F` 或先 `movzx` 再 `rol`。看到"和字符串里的域名在同一个函数里被使用、且紧邻 `connect`/`socket` 调用"的立即数，就是端口。

## 触发条件

- 手上有完整固件镜像（或厂商升级包），且能解出根文件系统（binwalk/unsquashfs/ubi_reader/jefferson 等至少一条路可走）。
- 固件中确实存在可疑后门/调试程序（比赛题会给提示；真实设备可从启动脚本、`/etc/rc.d`、`crontab`、开放端口反推）。
- 目标程序未加加密壳（UPX 这类压缩壳可脱；VMProtect/Themida 级别的需要动态脱壳）。
- 需要静态提取，无法在设备上跑（或不敢跑）。

## 利用步骤

1. `binwalk firmware.bin` 看分段；对每段分别用 `binwalk -e`、`unsquashfs`、`jefferson`、`ubi_reader`、`dd` 手动切；反复提取直到出现 `bin/ sbin/ etc/ lib/` 这类目录结构。
2. `find . | xargs grep -ri -e backdoor -e password -e passwd -e telnetd` 扫字符串，按命中文件名与所在目录筛出可疑二进制（`/tmp/xxx`、`/usr/sbin/xxx`）。
3. `file` + `binwalk`/`readelf` 确认架构与是否加壳；命中 `UPX!` 或 `upx -l` 可列出时，`upx -d <bin> -o unpacked` 脱壳。
4. IDA/Ghidra 载入脱壳后的文件；先看 `strings` 窗口里的域名、URL、`/dev/tcp`、`nc`、`sh -c` 等特征，双击字符串看 XREF。
5. 从字符串的 XREF 追到使用它的函数，确认该函数里同时存在 `socket`/`connect`/`gethostbyname`（或 `sendto`），读出目标主机与端口立即数。
6. 对另一个候选程序（同名不同实现）重复步骤 4–5，排除"提示用的假地址"，确认真正被启动脚本调用的那个。
7. 记录 C2 地址/端口、启动方式（`/etc/init.d` 脚本、`rcS`、crontab）与持久化路径，作为 IOC。

## PoC

无漏洞 PoC；给出可复用的提取与定位命令序列（纯静态分析，不运行样本）：

```bash
# 1) 逐层提取
binwalk -e firmware.bin
binwalk -e --run-as=root _firmware.bin.extracted/*.bin
unsquashfs -d rootfs _firmware.bin.extracted/*.squashfs

# 2) 语义关键字扫后门/口令
find rootfs | xargs grep -ril -e backdoor -e password -e passwd 2>/dev/null

# 3) 判壳与脱壳
file rootfs/tmp/<suspect>
strings -a rootfs/tmp/<suspect> | grep -i upx
upx -d rootfs/tmp/<suspect> -o unpacked

# 4) 脱壳后取字符串线索
strings -a unpacked | grep -Ei 'https?://|[a-z0-9.-]+\.(com|net|org|cn)|/dev/tcp|nc |sh -c'
```

后续在 IDA 中对上述字符串按 `X`（交叉引用）跳到引用函数，读 `connect` 前的 `sockaddr_in` 初始化即可。

## 变体与关联

- 若程序被 UPX 改过（magic/section 名被改），用 `code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation` 的思路模拟 stub 还原；纯手工可断在 `popad` + `jmp OEP`。
- 若固件里没有明文关键字，改用启动脚本反推：从 `/etc/init.d/rcS`、`/etc/inittab`、crontab 里找被调起的非标准二进制。
- 硬编码凭据（`ftpuser`、`password`、`icspwd` 之类）的定位手法与此相同：`grep -ri` → 字符串 XREF → 比较/校验函数。
- 关联：[[iot-wayos-mqtt-ai-hardcoded-telnet-backdoor]]（真实设备里后门账号 + telnetd 拉起）、[[code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla]]（手工脱 UPX 的通用流程）、[[code-analysis-reverse-firmware-vxworks-symbol-table-base]]（固件符号恢复，补齐"无符号"时的函数级定位）。

## 检测与防御

- 厂商侧：发布固件前剥离符号、检查是否被植入额外二进制；对 `/tmp`、`/var` 等可写目录做只读挂载或完整性监控。
- 设备侧检测：启动脚本中出现指向外部域名/端口的 `nc`、`telnet`、`sh -c`；固件中出现 `UPX!` 且未被列入白名单的二进制；对外连接与固件内字符串常量匹配。
- 分析侧：把"提取—关键字扫—判壳—XREF 追 C2"固化成流水线，批量跑一批固件时按命中文件名与 C2 域名聚类，可快速发现同一厂商同源后门。

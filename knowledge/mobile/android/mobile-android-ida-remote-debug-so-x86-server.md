---
id: mobile-android-ida-remote-debug-so-x86-server
title: IDA 远程调试 Android .so：android_x86_server + adb forward + JEB 启动调试 + attach 进程
type: scenario
domain: mobile
path: mobile/android
technique: ida-remote-debug-android-so-adb-forward
aliases:
- IDA 调试 Android so
- android_x86_server
- IDA Android 远程调试
- adb forward 23946
- JEB 启动调试
- am start -D
- Android native 动态调试
tags:
- android
- ida
- jeb
- native
- so
- remote-debug
- adb
- reverse
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V305
  verified_at: '2026-11-08T12:08:39+08:00'
  notes: 已对照原文核对：img/09 adb devices emulator-5554；img/10 getprop 为 x86；img/11 dbgsrv 四个 server；img/12 push android_x86_server 到 /data/local/tmp；img/13 chmod 777+运行，Listening on 0.0.0.0:23946；img/14 adb forward tcp:23946 tcp:23946；img/15 manifest android:debuggable=true 与包名；img/16 am start -D；img/17 Waiting For Debugger；img/18 JEB 附加调试选择 com.example.ndktest2；img/19 app 正常运行；img/20 JEB 导出 so；img/21-24 IDA 下断点/Process options(Hostname 127.0.0.1,Port 23946)/Attach；img/25 选进程 2621；img/26 同名模块不同路径点 Same；img/27-31 命中 test 断点、F8 后在栈上读到 YouaretheB3ST。步骤与原文一致。dedup 与 tools-ida-remote-linux-elf-debug-server 为 related（cos 0.8865，Linux ELF vs Android），与 fork 子进程 patch 卡为 related（cos 0.9078，不同场景），非重复；dup-scan 无本篇 pair。路径 mobile/android 合法。教程无产品版本，affected_versions 为空。未验证点：未复现模拟器/IDA 调试。无 sources/source_url。
---

## 一句话结论

在 Windows 上用 IDA 调试 Android 模拟器里的 `.so`，需要把 IDA `dbgsrv` 目录下与模拟器架构匹配的 `android_x86_server` push 到 `/data/local/tmp` 并运行（监听 23946），用 `adb forward tcp:23946 tcp:23946` 把端口映射到本机；再以 `android:debuggable="true"` 的 APK 通过 `adb shell am start -D -n <包名>/.MainActivity` 以等待调试状态启动，JEB 附加后让程序运行，IDA 用 `Remote Linux debugger` + `Attach to process` 选中目标进程，即可在 `.so` 的函数上下断点、单步并读取内存中的明文（原文据此从 `test` 函数栈上取出 `YouaretheB3ST`）。

## 原理

- **调试架构**：Android 上的 `android_x86_server`（IDA 自带调试代理）通过 ptrace 控制目标进程，与桌面 IDA 通过 TCP 23946 通信；桌面 IDA 负责界面、反汇编和断点管理。
- **架构与版本匹配**：`dbgsrv` 下有 `android_server`（ARM 32）、`android_server64`（ARM64）、`android_x64_server`、`android_x86_server`。先用 `adb shell getprop ro.product.cpu.abi` 看模拟器架构（原文 x86），再选对应 server；老 APK 可能需要 Android 5 及以下模拟器，否则 native 库不兼容会崩溃。
- **端口转发**：server 默认监听 `0.0.0.0:23946`，但模拟器在 NAT 后；`adb forward tcp:23946 tcp:23946` 把宿主 23946 转发到模拟器 23946，IDA 连接 `127.0.0.1:23946` 即可。
- **让 App 等待调试器**：APK 的 `AndroidManifest.xml` 必须 `android:debuggable="true"`（JEB 可查看）；`adb shell am start -D -n <包名>/.MainActivity` 以 `-D`（debug）方式启动，App 会停在 “Waiting For Debugger” 等待 JDWP 调试器附加。JEB 的 debugger 附加并 resume 后，App 正常运行但进程仍可被 native 调试器 attach。
- **主机名与模块匹配**：IDA Remote Linux debugger 的 Process options 中 Hostname 填 `127.0.0.1`、Port 23946（因为是 adb forward，不是模拟器 IP）；Attach 时选择 `com.example.ndktest2` 进程。IDA 会提示“found two modules with same base name but different paths”（本地导出的 so 与设备上 `/data/app/.../lib/x86/libnative-lib.so`），点 `Same` 让它按同名模块处理；可能出现入口断点，再点一次运行即可。
- **断点与取数**：在 `test` 函数（真实加密函数，见关联卡）下断点，模拟器输入任意内容点击登录，IDA 命中后 F8 单步到 `NewStringUTF` 前，双击栈上字符串指针查看数据，即可读到明文 flag/密钥。

## 触发条件

- 有可用的 Android 模拟器/真机（架构与 `dbgsrv` server 匹配；老 APK 需 Android 5 或更低版本）。
- APK 可安装且 `android:debuggable="true"`，能通过 `am start -D` 进入等待调试状态；设备已 root 或可执行 pushed server（模拟器通常可）。
- 桌面有 IDA（含 `dbgsrv`）与 JEB/jadx，adb 可用。
- 目标 `.so` 未加壳或已脱壳，能在 IDA 中正常反汇编。

## 利用步骤

1. 启动模拟器并安装 APK；`adb devices` 确认设备。
2. `adb shell` → `getprop ro.product.cpu.abi` 查看架构（如 x86）→ 退出。
3. 从 IDA 安装目录 `dbgsrv/` 选择匹配的 `android_x86_server`，`adb push <server> /data/local/tmp/`。
4. `adb shell` → `cd /data/local/tmp` → `chmod 777 android_x86_server` → `./android_x86_server`，看到 `Listening on 0.0.0.0:23946`。
5. 另开终端执行 `adb forward tcp:23946 tcp:23946`。
6. JEB 打开 APK，确认 manifest `android:debuggable="true"`，记录包名与 Activity；`adb shell am start -D -n <包名>/.MainActivity`，模拟器出现 Waiting For Debugger。
7. JEB 的 debugger 附加该进程并运行，App 进入正常界面。
8. 从 JEB 导出目标 `.so`，IDA 打开并定位真实函数下断点；`Debugger → Process options` 填 Hostname `127.0.0.1`、Port `23946`；`Debugger → Attach to process` 选择目标进程，模块路径不一致提示点 `Same`，如有入口断点再运行一次。
9. 在模拟器输入任意内容点击登录，命中断点后 F8 单步、查看栈/寄存器/内存取明文；原文最终在栈上读到 `YouaretheB3ST`。

## PoC

```bash
adb devices
adb shell getprop ro.product.cpu.abi          # x86
adb push "F:\IDA_Pro_v8.3_Portable\dbgsrv\android_x86_server" /data/local/tmp/
adb shell
cd /data/local/tmp && chmod 777 android_x86_server && ./android_x86_server
# IDA Android x86 32-bit remote debug server(ST) v8.3.28 ... Listening on 0.0.0.0:23946...

adb forward tcp:23946 tcp:23946

adb shell am start -D -n com.example.ndktest2/.MainActivity
# Waiting For Debugger
```

IDA：Debugger → Process options（Hostname `127.0.0.1`、Port `23946`）→ Attach to process → 选择 `com.example.ndktest2`。

## 变体与关联

- Linux ELF 远程调试用 `linux_server/linux_server64` + 虚拟机 IP（见 `tools-ida-remote-linux-elf-debug-server`）；本卡是 Android 模拟器 + `android_*_server` + `adb forward` 的变体。
- 只需看 Java 层返回值时，可用 objection/Frida hook 省去 IDA（见关联卡）；需要精确观察 native 寄存器/内存时仍需 IDA/gdb。
- APK 不可调试时，可重打包加 `android:debuggable="true"` 并重签名（见 `mobile-android-apk-debuggable-repack-jadx-attach`）。
- 若 so 有反调试（ptrace 检测、status 检查），需先 patch/绕过，再 attach。

## 检测与防御

- 逆向侧：确保 server 架构与设备一致、版本与 IDA 匹配；先 `adb forward` 再连接；模块路径不一致点 `Same`；老 APK 用低版本 Android。
- 防护侧（App 开发者）：release 关闭 `debuggable`、检测调试器/ptrace、so 加壳与符号剥离、关键算法放服务端。
- 检测：设备上出现 `android_x86_server`/`frida-server` 等调试代理、`adb forward 23946`、应用处于 debuggable 状态，均为逆向分析特征。

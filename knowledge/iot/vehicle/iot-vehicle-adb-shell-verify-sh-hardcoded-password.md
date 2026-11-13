---
id: iot-vehicle-adb-shell-verify-sh-hardcoded-password
title: 车机 adb shell 二次密码认证：导出 /system 下 verify_sh 逆向出硬编码口令 adb36987 绕过
type: scenario
domain: iot
path: iot/vehicle
technique: vehicle-adb-shell-verify-sh-hardcoded-password
aliases:
- adb shell 密码认证
- verify_sh 逆向
- adb36987
- 车机 adb 验证程序
- adb pull 可用 adb shell 要密码
tags:
- iot
- vehicle
- automotive
- android
- adb
- reverse
- hardcoded-password
- initial-access
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V665
  verified_at: '2026-11-13T08:18:52+08:00'
  notes: 已对照原文与全部21张截图核对：img12伪代码逐字为 v9=_strlen_chk("adb36987", 9LL); if(!strncmp((const char*)&v78.__unused[1], "adb36987", v9)){ shf_fprintf(...,"verify success!\n"); ... break; }，硬编码口令adb36987（8字符，_strlen_chk第二参9为对象大小）与卡内完全一致；blocking_read(0,...)确证从stdin读口令。原文仅引述绿盟案例并给此图，未展示完整adb pull/逆向过程，卡片以通用步骤补全并注明『不同车厂程序名与口令不同，需按实际导出逆向』，非过度断言。dedup：与iot-vehicle-adb-special-mode-password-root为related/new（工程模式口令开ADB vs adb shell二次门禁逆向口令），非同链；dup-scan无涉及本卡pair。原文未标版本。内部链接均存在。PoC未本机复跑。
---

## 一句话结论

部分车机对 adb 通道做了二次保护：`adb devices`、`adb pull` 正常，但 `adb shell` 要求先通过密码验证（由 `/system` 下 `verify_sh` 之类程序校验）。该验证程序可被 `adb pull` 导出逆向，其中口令以明文硬编码（原文案例为 `adb36987`），输入后提示 `verify success!` 即获得 shell——认证秘密完全存放在攻击者可读的分区里。

## 原理

- 车厂在标准 adbd 之上加了一层 shell 门禁：USB/网络 adb 连接与文件传输（pull/push）不受限，只有 `adb shell` 会话启动前由包装程序（原文为 `verify_sh`）从 stdin 读取口令并比对，正确才 exec 真正的 shell。
- 校验逻辑是普通字符串比较：原文伪代码反编译为 `v9 = _strlen_chk("adb36987", 9); if (!strncmp(input, "adb36987", v9)) { printf("verify success!\n"); ... }`——口令以字面量形式存在于二进制中，未做加密/白名单绑定（如按 VIN/设备唯一密钥派生）。
- 该程序位于 `/system` 分区（通常只读但全局可读），而 adb pull 不需要通过 shell 门禁，所以攻击者可以先把 `verify_sh` 拉到本地，用 IDA/Ghidra 搜索字符串或反编译拿到口令，再回到 `adb shell` 输入。
- 为什么成立：门禁把「文件传输」与「shell」分开授权，却把认证材料放在同一可读分区并明文硬编码；安全强度退化为「知道一个固定字符串」，且该字符串可从设备自身提取。

## 触发条件

- 车机 adb 可达（物理调试口或无线 adb 已开启），且 `adb pull` 对 /system 可读文件可用。
- `adb shell` 被包装程序（verify_sh 等）拦截，要求输入口令。
- 口令为硬编码字面量，未按设备唯一化/加密。

## 利用步骤

1. `adb devices` 确认设备连接；`adb shell` 验证是否提示输入密码（说明存在 shell 门禁）。
2. 定位并导出验证程序：`adb pull /system/bin/verify_sh`（原文为 system 目录下的 verify_sh；路径按目标实际文件名调整）。
3. 逆向：`strings verify_sh | grep -iE 'verify|pass'`，或 IDA/Ghidra 反编译校验函数，找到 `strncmp(input, "<口令>", len)` 的明文口令（原文为 `adb36987`）。
4. 重新 `adb shell`，输入该口令，看到 `verify success!` 后获得车机 shell。
5. 进入 shell 后按常规做信息收集（getprop、/sdcard、logcat）与提权。

## PoC

```bash
adb devices
adb shell                      # 提示口令验证
adb pull /system/bin/verify_sh # 或从 system 目录其他路径导出
strings -a verify_sh | grep -iE 'adb|verify|pass'
# 反编译校验函数可见：strncmp(input, "adb36987", 9)
adb shell
# 输入：adb36987  ->  verify success!
```

说明：口令 `adb36987` 与伪代码来自原文引用绿盟技术博客的案例截图；不同车厂/车型的程序名与口令不同，需按目标实际导出逆向。

## 变体与关联

- 变体：同类二次门禁也可能出现在 adb 之外——串口 console、telnet、工程模式入口用固定口令/硬编码校验，均可导出二进制逆向。
- 变体：若口令按设备唯一值（VIN、序列号）派生，需结合固件中的派生算法计算，不能直接复用固定口令。
- 关联：[[iot-vehicle-adb-special-mode-password-root]]（工程模式口令开启 ADB 的另一入口；本卡是其「adb shell 被密码门禁拦截」时的补充突破手法）、[[mobile-android-adbd-tcp-userdebug-root]]（adbd 网络调试面）。
- 关联方法论：[[code-analysis-reverse-firmware-wayos-mqtt-ai-hardcoded-telnet-backdoor]]（固件/二进制中硬编码口令的通用逆向思路）。

## 检测与防御

- 检测：从车机拉取/运行 verify_sh 等自定义验证程序、`strings` 检索口令；adb 会话出现先 password 后 shell 的异常交互；`adb pull /system/...` 大量导出系统文件。
- 修复：不要用硬编码固定口令做 shell 门禁；改为按设备唯一密钥（VIN/安全芯片）派生的挑战-响应认证，或直接禁用量产车的 adb shell；认证程序放不可读分区并剥离符号/字符串。
- 加固：量产固件关闭 adb 或限制为签名授权会话；对 /system 关键程序做完整性校验；监控 adb 连接与数据导出。

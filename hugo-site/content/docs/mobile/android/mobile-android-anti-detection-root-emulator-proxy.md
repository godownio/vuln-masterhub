---
id: mobile-android-anti-detection-root-emulator-proxy
title: Android APP 反检测环境：Shamiko/HideMyApplist/PlayIntegrityFork 与 iptables 透明代理绕过
type: scenario
domain: mobile
path: mobile/android
technique: android-anti-detection-environment-bypass
tags:
- android
- magisk
- shamiko
- hide-my-applist
- play-integrity
- emulator-detection
- proxy-detection
- frida
- iptables
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V64
  verified_at: '2026-11-05T12:22:56+08:00'
  notes: 已对照原文与图37-56核对：Shamiko v1.2.5 安装与排除列表（图37-41）、PlayIntegrityFork v16 与 autopif4.sh 生成 Pixel 10 Pro Fold pif.prop（图42-43）、HideMyApplist 3.6.1-462 模板/Applist Detector 全绿（图44-48）、Pixel Props 与 resetprop（图? 正文）、iptables DNAT 80/443→192.168.110.91:9999 与 UDP443 REJECT（图51）、Charles 9999/SSL *:* /外部代理 127.0.0.1:8083（图52-54）、Yakit 抓包成功（图56）。未验证点：环境为作者自建模拟器，未针对具体检测 SDK 做前后评分对比；PoC 未本机复跑；无版本/CVE。
url: /docs/mobile/android/mobile-android-anti-detection-root-emulator-proxy/
draft: false
kb_aliases:
- Android 反 Root 检测
- Shamiko 隐藏 Root
- HideMyApplist 隐藏应用列表
- PlayIntegrityFork 伪造设备完整性
- Pixel Props 模拟器伪装
- iptables 透明代理绕过
- 模拟器检测绕过
---

## 一句话结论

银行/支付类 APP 常用 Root 文件、Magisk/Frida 应用列表、模拟器设备节点、Play Integrity 与代理设置做打分式环境检测；在 Magisk 环境用 Shamiko 隐藏 su/Magisk、HideMyApplist 隐藏敏感应用、PlayIntegrityFork 伪造设备完整性、Pixel Props 伪装系统属性，并用 iptables 在出口劫持流量、阻断 QUIC，可把检测得分压到 APP 可接受范围并正常抓包。

## 原理

- Root 检测：检查 `su` 文件、Magisk 目录/包名、`ro.debuggable` 等；Shamiko 通过 Zygisk 对指定 APP 隐藏这些痕迹，Magisk 排除列表让进程不被修改。
- 应用列表检测：扫描已安装包名，发现 Magisk、Frida、Xposed 即判定环境异常；HideMyApplist 通过 Xposed/Vector 对目标 APP 隐藏黑名单应用。
- 设备完整性：银行/支付 APP 调用 Play Integrity API；PlayIntegrityFork 生成伪造的 `pif.json` 设备指纹，使 DEVICE verdict 通过。
- 模拟器检测：检查 `/dev/qemu_pipe`、`/dev/goldfish_pipe`、`/sys/qemu_trace`、`ro.hardware`/`ro.product.model` 等；Pixel Props 覆盖系统属性，Shamiko/HideMyApplist 隐藏路径，Frida Hook `File.exists` 兜底。
- 行为检测：模拟器电池、传感器、电话信息与真机不同；Frida Hook `BatteryManager`、`TelephonyManager` 返回正常值。
- 代理检测：APP 读取系统代理设置或探测代理端口；iptables 在模拟器出口直接 DNAT 80/443 到 PC 代理，APP 应用层看不到代理配置；QUIC（UDP 443）不经过 TCP 代理，需 REJECT 强制回退。

## 触发条件

- 测试设备为已 Root 的模拟器（Magisk + ZygiskNext + Vector）。
- 目标 APP 使用打分式环境检测（梆梆、同盾、数美等），未使用无法绕过的 native 反调试/RASP。
- 已安装 Shamiko、HideMyApplist、PlayIntegrityFork、Pixel Props 等模块，并能针对目标 APP 配置排除列表。
- 代理工具与模拟器网络可达，iptables 规则可写入。

## 利用步骤

1. **隐藏 Root**：Magisk 安装 Shamiko，开启后进入 Magisk 设置 → 配置排除列表，展开勾选目标 APP 的全部进程；不要勾选“遵循排除列表”（会与 ZygiskNext 冲突）。
2. **隐藏应用列表**：安装 HideMyApplist，在 Vector 中启用并勾选 System Framework；创建黑名单模板，加入 Magisk、Frida、Xposed 等应用，再对目标 APP 应用模板；用 Applist Detector 验证全部通过。
3. **伪造设备完整性**：安装 PlayIntegrityFork，重启后执行 `adb shell su -c "sh /data/adb/modules/playintegrityfix/autopif4.sh"` 生成 `pif.json`；若 Integrity 突然失败，重新执行刷新指纹。
4. **伪装系统属性**：安装对应机型的 Pixel Props 模块（Magisk 本地安装，按音量键确认），重启；必要时在 `/data/adb/post-fs-data.d/props.sh` 写 `resetprop ro.hardware qcom` 等补丁并 `chmod 755`。
5. **兜底 Hook**：用 Frida 加载 `hide_emulator.js` Hook `File.exists`，对 `qemu_pipe`/`goldfish_pipe`/`qemu_trace`/`nox`/`vbox` 等路径返回 false；加载 `fake_sensor_battery.js` 伪造电池与电话信息。
6. **透明代理**：`iptables -t nat -A OUTPUT -p tcp --dport 80/443 -j DNAT --to-destination <PC_IP>:9999` 转发到 Charles，再由 Charles 转发到 Yakit/Burp；`iptables -A OUTPUT -p udp --dport 443 -j REJECT` 阻断 QUIC。
7. 用 Applist Detector 与目标 APP 验证检测项全部通过，再开始抓包/逆向。

## PoC

```bash
# PlayIntegrityFork 生成伪造指纹
adb shell su -c "sh /data/adb/modules/playintegrityfix/autopif4.sh"

# 补充系统属性（/data/adb/post-fs-data.d/props.sh）
#!/system/bin/sh
resetprop ro.hardware qcom
resetprop ro.boot.hardware qcom
resetprop ro.hardware.chipname Tensor
# chmod 755 /data/adb/post-fs-data.d/props.sh

# iptables 透明代理（HTTP/HTTPS 转发到 Charles）
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.110.91:9999"
adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.110.91:9999"
# 阻断 QUIC，强制回退 TCP HTTPS
adb shell su -c "iptables -A OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable"
# 清理
adb shell su -c "iptables -t nat -F OUTPUT"
adb shell su -c "iptables -D OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable"
```

```javascript
// hide_emulator.js：隐藏模拟器设备节点
Java.perform(function() {
    var File = Java.use("java.io.File");
    var blacklist = ["qemu_pipe", "goldfish_pipe", "qemu_trace", "nox", "vbox", "genymotion", "andy", "bluestacks"];
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < blacklist.length; i++) {
            if (path.indexOf(blacklist[i]) !== -1) return false;
        }
        return this.exists();
    };
});
```

## 变体与关联

- **Zygisk 排除列表**：Shamiko 失效时的备选，Magisk 设置勾选“遵循排除列表”并配置目标 APP；与 ZygiskNext 可能冲突，需二选一。
- **native 检测**：检测 SDK 直接 syscall 读文件/属性时，Java 层 Hook 无效，需要 Frida native Hook 或内核层对抗。
- **服务端风险评分**：客户端检测可被绕过，但服务端仍可能基于 IP、设备指纹、行为做风控；绕过环境不等于绕过业务风控。
- **关联**：[[mobile-android-ssl-pinning-bypass-cert-frida]]（证书与抓包）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（定位检测逻辑）。

## 检测与防御

- APP 侧采用 native 层检测、Play Integrity 服务端校验、RASP 与多因子风控，不依赖单一客户端判断。
- 服务端对设备指纹、IP、行为序列做综合评分，发现模拟器/代理特征时降权或二次验证。
- 使用 mTLS、请求签名与证书 pinning，降低抓包与 Hook 的收益。
- 检测：设备存在 Shamiko/HideMyApplist/PlayIntegrityFork/Pixel Props 模块；`/data/adb/post-fs-data.d` 异常脚本；iptables OUTPUT 链被修改；Frida 端口/进程；代理 CA 安装。

---
id: mobile-android-unity-il2cpp-frida-gadget-infinite-revival
title: Unity IL2CPP 手游免死改包：Frida-Gadget 脱机注入与 RestartStage→AutoRevival 重定向
type: scenario
domain: mobile
path: mobile/android
technique: unity-il2cpp-frida-gadget-revival-hook
tags:
- android
- unity
- il2cpp
- frida
- gadget
- game-hacking
- hook
- reverse
- apk-repack
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V102
  verified_at: '2026-11-05T22:37:45+08:00'
  notes: 已对照原文与6张图核对 Il2CppDumper、Gadget 16.5.9、RVA/偏移与 x1→x99 实机结果；RVA 为样本实测值，未独立复现。
url: /docs/mobile/android/mobile-android-unity-il2cpp-frida-gadget-infinite-revival/
draft: false
kb_aliases:
- Unity IL2CPP 改包
- Frida-Gadget 脱机注入
- 无限复活
- AutoRevival
- RestartStage
- CryptInt
- Il2CppDumper
---

## 一句话结论

对 Unity IL2CPP 手游，先用 Il2CppDumper 从 `libil2cpp.so` + `global-metadata.dat` 还原符号与调用链，定位“死亡 → AutoRevival / RestartStage”分叉；当 `frida-server` attach 被反调试阻断时，把 frida-gadget 16.5.9 注入 `Application.onCreate` 并以 `script` 模式脱机自启动，Hook `RestartStage → AutoRevival`、跳过 `DeadFlash` 闪屏、把 `CryptInt` 复活次数字段锁到 99 并 Hook `Set/Get` 防扣减，即可实现碰撞点续跑与无限复活。

## 原理

- **Unity IL2CPP 结构**：C# 代码经 IL2CPP 转为 C++ 并编译进 `libil2cpp.so`，类型/方法元数据在 `global-metadata.dat`；Il2CppDumper 解析两者后输出 `dump.cs`（伪 C# 逻辑）、`script.json`（Frida 用 Address 表）与 `il2cpp.h`（字段偏移），RVA 均在 `libil2cpp.so` 基址之上。
- **死亡/复活调用链**：示例 `TimeEventCreator.Dead/DeadFlash` → `GameSystem.PlayerDeadFlash()/OnPlayerDeadFlash()`（死亡闪屏）→ `GameSystem.PlayerDead()/OnPlayerDead()`（分叉点）→ `AutoRevival()`（碰撞点原地续跑）或 `PanelContinue.*`（金币/广告续命）或 `RestartStage()`（整关重来）。`GameProperty.m_death_pos_backup` 保存死亡位置，说明游戏本身具备“在碰撞点恢复”的数据基础。
- **改包目标**：把 `RestartStage` 重定向为 `AutoRevival`，阻断整关清零；对 `DeadFlash`、`OnPlayerDeadFlash`、`PlayerDeadFlash` 三处 `replace` 为空实现，去掉死亡闪屏；对 `m_revival_chance`（偏移 `0x34`）、`m_ability_equip_revival`（`0x38`）、`m_revival_item_count`（`0x1C`）三个 `CryptInt` 字段调用 `Set(99)`，并 Hook `CryptInt.Set/Get` 防止逻辑层把次数扣回 0。
- **为什么用 Gadget 而不是 attach**：示例样本在 native 层含 `frida`/`ptrace` 特征，`frida-server` attach 报 `ProcessNotRespondingError`；frida-gadget 在进程启动早期由 `System.loadLibrary("frida-gadget")` 加载，可赶在反调试逻辑生效前挂上 Hook。
- **脱机 script 模式**：`listen` 模式必须保持 PC 连接；改为 `script` 模式后，Gadget 在应用启动时自动加载 `/data/data/<pkg>/files/il2cpp_auto_hook.js`，`on_load: resume` 表示加载后不阻塞启动，`on_change: reload` 便于替换脚本调试，从而做到“装改包 APK 就能玩”。
- **CryptInt 加密整型**：复活次数不是普通 `int`，不能直接搜内存改写；必须先定位字段偏移，再通过 `CryptInt.Set(int)` 写入，并 Hook `Get/Set` 防止扣减。
- **为什么要多点触发**：实机死亡可能不走 `OnPlayerDead`，而走 `DeadFlash` 链；只在单点补次数会出现“Hook 挂上了但次数仍减少”的半生效状态。v3 在 `DeadFlash`、`PlayerDead`、1.5s 定时器、`Revival` 链都调用 `refillAllRevival`，并对已跟踪指针的 `Set/Get` 做白名单与 RVA 兜底。

## 触发条件

- 目标为授权测试的 Unity IL2CPP Android 游戏/应用，含 `lib/<abi>/libil2cpp.so` 与 `assets/.../global-metadata.dat`，外层无高强度商业壳（apktool 可解包）。
- ABI 与 frida-gadget 匹配（示例仅 `armeabi-v7a`，使用 gadget 16.5.9 arm32；17.x 在示例机型加载即崩溃）。
- 能重打包并重签 APK（debug.keystore），设备允许安装未知来源/卸载原包。
- 样本有反 Frida/反调试，但可在 `Application.onCreate` 早期加载 gadget 并用 `strstr`/`strcmp` 绕过。
- 逻辑在客户端本地判定（若关键判定在服务端，改包只能改变表现，不能获得真实收益）。
- 仅用于自有/授权环境，不用于线上游戏作弊或侵犯他人产品。

## 利用步骤

1. **环境摸底**：adb 连接设备、枚举包名；用 apktool/jadx 检查加固与架构，确认 `libil2cpp.so`、`global-metadata.dat`、ABI 与是否 Unity IL2CPP。
2. **静态导出**：提取 `libil2cpp.so` 与 metadata，运行 Il2CppDumper 生成 `dump.cs`、`script.json`、`il2cpp.h`；在 `dump.cs` 搜索 `Revival`、`Dead`、`Restart`、`Flash` 等关键词。
3. **还原调用链**：结合 `GameSystem`、`PanelGamePlay`、`TimeEventCreator` 等类名，画出“碰撞 → 死亡事件 → 闪屏 → PlayerDead → AutoRevival/RestartStage”的路径，记录关键方法 RVA（版本相关）。
4. **实机收窄**：用 Frida trace 或日志观察实际死亡路径（“闪一下原地继续”对应 `AutoRevival`，不是 `RestartStage`），避免 Hook 错分支。
5. **Gadget 重打包**：apktool 解包；把 frida-gadget 16.5.9 对应 ABI 的 `.so` 放入 `lib/`；修改渠道 `Application.onCreate()` 为 `System.loadLibrary("frida-gadget")`，并把 `assets/il2cpp_auto_hook.js` 复制到私有目录；写入单行 JSON 配置（`type: script`、脚本路径、`on_load: resume`、`on_change: reload`，必须 LF 换行）；apktool build + jarsigner 重签。
6. **首次联调**：先用 `listen` 模式 + PC 连接验证脚本能挂上、Hook 生效；确认后再切 `script` 模式脱机自启动。
7. **Hook 脚本**：实现 anti-frida bypass（`strstr`/`strcmp`）、`RestartStage → AutoRevival` 重定向、三处闪屏空实现、三个 `CryptInt` 字段 `Set(99)`、`CryptInt.Set/Get` 防扣减；用 `__android_log_write` 打 `FRIDA_HOOK` 标签日志。
8. **验收**：logcat 看到 `[refill] n=3`、UI 生命值 x99、撞障碍后原地续跑且不闪屏；确认服务端未同步/未封禁（授权环境）。

## PoC

Gadget 配置（单行 JSON，LF）：

```json
{"interaction":{"type":"script","path":"/data/data/com.example.runner.game/files/il2cpp_auto_hook.js","on_load":"resume","on_change":"reload"}}
```

Hook 脚本骨架（RVA 为示例样本实测值，随版本变化）：

```javascript
const base = Module.findBaseAddress("libil2cpp.so");
const RVA = {
  RestartStage: 0xFA5DC,
  AutoRevival:  0xF776C,
  DeadFlash:    0xC72B0,
  CryptIntSet:  0x73EB10,
  CryptIntGet:  0x73EB2C,
};

// 示例：RestartStage 重定向为 AutoRevival（伪代码，需按真实签名适配）
const restart = base.add(RVA.RestartStage);
const autoRevival = base.add(RVA.AutoRevival);
Interceptor.replace(restart, new NativeCallback(function () {
  return new NativeFunction(autoRevival, 'void', [])();
}, 'void', []));

// 示例：闪屏空实现
Interceptor.replace(base.add(RVA.DeadFlash), new NativeCallback(function () {}, 'void', []));

// 示例：CryptInt 防扣减（参数名不要用 ptr，避免遮蔽 Frida 全局 ptr()）
function hookCrypt() {
  Interceptor.attach(base.add(RVA.CryptIntSet), {
    onEnter(args) { this.ci = args[0]; this.v = args[1].toInt32(); },
    onLeave(retval) { if (this.v < 99) { /* 调 Set(ci, 99) */ } }
  });
}
```

重打包关键命令（示意）：

```bash
apktool d -f sample.apk -o decompiled
# 放入 libfrida-gadget.so、修改 Application.onCreate smali、写入 config 与 assets 脚本
apktool b decompiled -o repacked.apk
jarsigner -keystore debug.keystore -storepass android repacked.apk androiddebugkey
adb uninstall com.example.runner.game
adb install -r repacked.apk
adb logcat -s FRIDA_HOOK:*
```

## 变体与关联

- **注入方式变体**：frida-server attach、gadget 重打包、Xposed/LSPosed、离线 patch `libil2cpp.so`（无 Frida 依赖但版本升级维护成本高）。
- **逻辑变体**：无敌/秒杀/金币/道具数量；把死亡分支改成续跑只是其中一种；任何客户端判定的数值都可按同样“定位字段 → CryptInt.Set → Hook 防扣减”处理。
- **架构变体**：armeabi-v7a 与 arm64-v8a 的 gadget/so/偏移都不同；IL2CPP vs Mono（Mono 可直接用 dnSpy 改 DLL）。
- **反调试变体**：`strstr`/`strcmp` 绕过、patch 反调试函数、延迟加载 gadget、隐藏 gadget 名称/端口。
- **关联卡片**：[[mobile-android-packer-apkid-frida-dexdump-jadx]]（加固 APK 查壳与脱壳）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（Frida 通用 Hook）、[[code-analysis-reverse-anti-debug-silverfox-installer-vm-detection]]（反调试/反虚拟机思路）。
- **边界**：RVA 随游戏版本变化；强壳/反篡改/服务端校验会使改包无效或封号；frida-gadget 版本与机型/ABI 不匹配会崩溃；仅限授权测试。

## 检测与防御

- **客户端检测**：校验 APK 签名/完整性、检测 `libfrida-gadget.so` 与 gadget 配置、扫描 `frida`/`gadget` 字符串与端口、检测 `ptrace`/调试状态、校验 `global-metadata.dat` 与 `libil2cpp.so` 哈希。
- **运行时检测**：检测 `Interceptor.replace` 造成的函数头变化、`CryptInt` 读写异常、生命值/复活次数突变、logcat 中的自定义 Hook 标签；服务端做行为一致性校验。
- **防御设计**：关键逻辑服务端权威判定；IL2CPP metadata 加密/混淆、so 加壳/反调试、反篡改与完整性校验；对改包客户端拒绝服务而不是只做本地表现。
- **合规**：只在自有/授权应用上做逆向与改包；不针对线上游戏作弊、不绕过付费/广告；发现漏洞按厂商渠道披露。

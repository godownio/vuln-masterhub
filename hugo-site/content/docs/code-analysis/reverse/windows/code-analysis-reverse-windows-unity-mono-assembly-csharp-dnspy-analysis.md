---
id: code-analysis-reverse-windows-unity-mono-assembly-csharp-dnspy-analysis
title: Unity Mono 游戏静态逆向：Managed/Assembly-CSharp.dll 识别与 dnSpy 关键逻辑定位
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: unity-mono-assembly-csharp-dnspy-analysis
tags:
- reverse
- unity
- mono
- dnspy
- csharp
- dotnet
- game
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:02:52+08:00'
  notes: 已对照 content.md 与 15 张图核对：Mono 的 Data/Managed/Assembly-CSharp.dll 识别、dnSpy 定位关键方法、BJD 的 SHA1 1001 + MD5 大写前 20、SCTF 的 Encoding.Unicode key/iv + Base64 + DES、FlareOn5 的 GetKey 种子/32 字节异或均一致。本机用原文密文与 key 验证 DES 解密得到 UTF-16LE 'He_P1ay_Basketball_Very_We11!Hahahahaha!'，与卡片 PoC 的 utf-16le 解码一致；未运行游戏/其余 PoC。frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-unity-mono-assembly-csharp-dnspy-analysis/
draft: false
kb_aliases:
- Unity Mono 逆向
- Assembly-CSharp.dll
- dnSpy 分析 Unity
- MonoBehaviour 逆向
- Mono vs IL2CPP
---

## 一句话结论

拿到 Unity 游戏先看 `Data/Managed/Assembly-CSharp.dll` 是否存在：存在就是 Mono 打包，用 dnSpy 直接反编译该 DLL，搜索 `flag`/`password`/`check` 等关键词并重点看继承 `MonoBehaviour` 的 `Start`/`Update`/`OnClick` 方法，通常就能明文看到校验、加密和拿 flag 的逻辑；`GameAssembly.dll` + `Data/il2cpp_data` 则是 IL2CPP，另走 native 逆向。

## 原理

- Unity 的 Mono 后端把 C# 脚本编译成 IL，打包进 `Data/Managed/Assembly-CSharp.dll`（第三方插件在 `Assembly-CSharp-firstpass.dll`，其余是 Unity/.NET 库）。IL 是保留完整元数据的中间语言，dnSpy 可以直接反编译出接近源码的 C#，类名/方法名/字符串常量都在。
- IL2CPP 后端则把 IL 转成 C++ 再编译为机器码，核心逻辑在 `GameAssembly.dll` 与 `Data/il2cpp_data`，没有 `Assembly-CSharp.dll`；静态分析难度高得多，需要 IL2CPP dump/符号恢复。
- Unity 脚本组件继承 `MonoBehaviour`，生命周期方法有固定调用时机：`Start` 启动一次、`Update` 每帧、`OnClick` 按钮点击。游戏的关键校验通常挂在按钮回调或碰撞/点击回调上。
- 常用 API 是定位线索：`PlayerPrefs`（本地存档/分数）、`SceneManager`（场景切换）、`Input`（输入）、`Debug.Log`（调试输出）、`System.Security.Cryptography`（MD5/DES/AES）、`Random`（种子/随机数）。
- 反编译后先看字符串常量和类名：`EncryptData`、`encryptKey`、`GetKey`、`Check`、`SuccessPopup` 等命名往往直接暴露意图；`b.ToString("X2")` 表示大写十六进制，`Substring(0, 20)` 表示截断，这些细节决定最终 flag 的拼接。
- 静态分析不保证一次到位：有的题目会在 UI 上再覆盖一层点击框、或用多个 DLL/最新修改的 DLL 承载真正逻辑；需要结合文件修改时间、CE 动态分析或调试断点继续追。

## 触发条件

- 目标为 Unity 桌面游戏/CTF 题，目录中存在 `Data/Managed/Assembly-CSharp.dll`（Mono）。
- 关键校验/加密在 C# 层完成，未被 IL2CPP 转换；没有强名称/完整性校验阻止 dnSpy 打开（即使有，通常也能先静态看）。
- 允许在本地运行/调试游戏，或只需要静态提取算法。
- 分析者熟悉 C#/.NET 基础与 Unity 生命周期。

## 利用步骤

1. 查看游戏目录：有 `Data/Managed/Assembly-CSharp.dll` 判为 Mono；有 `GameAssembly.dll` + `Data/il2cpp_data` 判为 IL2CPP，改用 IL2CPP 工具链。
2. 用 dnSpy 打开 `Assembly-CSharp.dll`（以及 `Assembly-CSharp-firstpass.dll`），在左侧程序集树查看命名空间/类；先按修改时间排序，较新的 DLL 可能是后加的逻辑。
3. 全局搜索关键词：`flag`、`password`、`check`、`encrypt`、`decrypt`、`key`、`Success`、`Fail`；也可搜索字符串常量（dnSpy 的 Search -> String）。
4. 重点看 `MonoBehaviour` 子类的 `Start`/`Update`/`OnClick`，以及名字可疑的类（`TestClick`、`ButtonSpawnFruit`、`MainForm`、`SuccessPopup`）。
5. 还原算法：把 C# 的编码/哈希/加密调用逐行翻译成 Python；注意 `Encoding.Unicode` 是 UTF-16LE、`Encoding.UTF8` 是 UTF-8、`ToString("X2")` 是大写十六进制、`Substring` 可能截断。
6. 若静态解密结果输入后仍不对，检查是否有第二层点击框/覆盖 UI、多个 DLL 的调用顺序、或运行时才生成的 key；转 CE Mono 动态分析（见关联卡）。
7. 对 C# WinForms 题（如扫雷），从 `Program.Main` → `MainForm` 构造函数 → 事件回调逐层跟，找到胜利条件与 `GetKey` 等生成 flag 的函数。

## PoC

```python
# 例 1：C# Md5(str) 返回大写 hex 并只取前 20 字符
import hashlib
s = '1001'
h = hashlib.md5(s.encode()).hexdigest().upper()[:20]
print(h)   # B8C37E33DEFDE51CF91E
# 原文最终 flag：BJDCTF{B8C37E33DEFDE51CF91E}
```

```python
# 例 2：C# Encoding.Unicode.GetBytes("1234") 作为 DES key/iv
import base64
from Crypto.Cipher import DES

enc = base64.b64decode(
    "1Tsy0ZGotyMinSpxqYzVBWnfMdUcqCMLu0MA+22Jnp+MNwLHvYuFToxRQr0c+ONZc6Q7L0EAmzbycqobZHh4H23U4WDTNmmXwusW4E+SZjygsntGkO2sGA=="
)
key = iv = "1234".encode("utf-16le")   # 31 00 32 00 33 00 34 00
pt = DES.new(key, DES.MODE_CBC, iv).decrypt(enc)
print(pt.decode("utf-16le"))
# He_P1ay_Basketball_Very_We11!Hahahahaha!
```

```text
例 3：C# WinForms 扫雷
Program.Main -> new MainForm() -> AllocateMemory(MineField) -> SquareRevealedCallback
胜利条件 TotalUnrevealedEmptySquares == 0 时调用 GetKey(RevealedCells)
GetKey：前 3 个已揭示格子排序后拼 seed -> Random(seed).NextBytes(32 字节) -> 与固定 32 字节数组异或 -> ASCII
```

## 变体与关联

- 变体：IL2CPP 打包没有 `Assembly-CSharp.dll`，需要 `Il2CppDumper`/`il2cpp-frida` 等恢复类型与函数；参考 [[mobile-android-unity-il2cpp-frida-gadget-infinite-revival]]。
- 变体：字符串被加密/混淆时，先找解密函数并动态调用；`de4dot` 可去常见混淆，但强混淆/自定义加密仍需手工。
- 变体：有反调试/完整性校验时，先定位检测函数并 patch/NOP，或用 CE/dnSpy 调试绕过。
- 关联卡片：[[code-analysis-reverse-windows-unity-mono-dnspy-il-patch-bypass]]（dnSpy 改 IL 绕过校验）、[[code-analysis-reverse-windows-unity-mono-cheat-engine-dissect]]（CE Mono 动态分析）、[[code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida]]（native 层运行时解密）。
- 边界：dnSpy 只能处理 .NET/Mono 程序集；IL2CPP、加壳、强名称签名校验或 native 保护需要不同工具链。

## 检测与防御

- 检测（防守/游戏保护）：检测调试器/CE/dnSpy 进程、检查程序集完整性/哈希、对关键方法做控制流混淆与字符串加密；重要校验放到服务端。
- 加固：使用 IL2CPP 替代 Mono；对 DLL 做签名/加密/完整性校验；关键 flag/奖励由服务端下发，客户端只做展示。
- 分析安全：游戏样本视为不可信数据，在隔离虚拟机运行；dnSpy 编辑/保存前备份原文件，避免破坏。

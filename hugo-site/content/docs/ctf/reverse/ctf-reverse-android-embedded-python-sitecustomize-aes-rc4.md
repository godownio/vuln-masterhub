---
id: ctf-reverse-android-embedded-python-sitecustomize-aes-rc4
title: Android 内嵌 CPython 的加密 sitecustomize.py：从 .so 静态提取 AES-ECB 脚本并还原运算符重载 RC4 校验
type: scenario
domain: ctf
path: ctf/reverse
technique: android-embedded-python-sitecustomize-operator-dsl
tags:
- ctf
- reverse
- android
- python
- sitecustomize
- aes
- rc4
- operator-overloading
- native-so
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T11:58:49+08:00'
  notes: V178 指出的密文长度/.data 前缀问题已修正并重新 verify
url: /docs/ctf/reverse/ctf-reverse-android-embedded-python-sitecustomize-aes-rc4/
draft: false
kb_aliases:
- MaybeAndroid
- VipDecryptor
- sitecustomize.py 劫持
- 内嵌 CPython APK
- 运算符重载混淆校验
---

## 一句话结论

APK 把完整 CPython 运行时打包进 assets，真正的校验脚本被 AES 加密后藏在 native 库的 `.data` 里，由 JNI 解出并写入 `site-packages/sitecustomize.py`；该脚本在解释器启动时自动执行，并用 `builtins.open` 替换加运算符重载把 RC4 校验伪装成 emoji 表达式。静态提取 `.data` 密文、解密脚本、再按运算符语义还原始 RC4 参数即可得到 flag，不需要激活 VIP，也不需要运行 APK。

## 原理

- **为什么 `sitecustomize.py` 合适**：CPython 启动时 `site` 模块会自动尝试 `import sitecustomize`；只要把文件放进 `site-packages`，它就会早于业务代码执行。这是官方支持的启动钩子，因此常被保护代码/恶意代码用来隐藏逻辑，不需要改动入口 Activity。
- **内嵌解释器链路**：APK 的 `assets/python/lib/python3.14/site-packages` 下有 `flag_check.py` 等脚本；Java 层把 assets 解压到应用私有目录，设置 `TMPDIR`/`PYTHONUNBUFFERED`，再通过 `System.loadLibrary("pythonrunner")` 调 native 的 `runPython(home, args)` 启动解释器。
- **脚本从 native 库交付**：`VipDecryptor` 的 JNI 函数调用 `sub_F80`（AES 实现），密钥是字符串 `sitecustomize.py`，密文位于 `.data` 起始处，长度为 `0x680`；解密结果被 `malloc(0x6A0)` 接收并返回给 Java，Java 在执行前将其写入 `filesDir/python/lib/python3.14/site-packages/sitecustomize.py`。也就是说静态文件里同时放着密文与密钥，AES-ECB 可离线解开。
- **运算符重载把算法藏进表达式**：脚本把 `builtins.open` 换成 `oprate` 对象。
  - `open("😇","r")` 对特殊文件名直接返回而不真正打开文件；
  - `a ^ "😋"` 返回计数器 `CustomSum`，`b << "😢"` 使计数加一，`b == "😃"` 返回当前计数；
  - `a ^ "🫨"` 返回 `list(range(256))`，作为 RC4 的初始 S 盒；
  - `a ^ "😁"` 返回 `Keyget`，每次 `<< "😢"` 按序给出 RC4 key 的一个字节；
  - `a ^ "😤"` 返回 `GetEnc`，每次 `<< "😢"` 按序给出密文字节与 `0x55` 异或后的值。
- **真实校验**：`flag_check.py` 先利用 `CustomSum` 得到输入长度 32，再用上述对象完成标准 RC4 KSA/PRGA，逐字节比较。表面上看是中文/emoji 表达式，实际数据流完全等价于 `RC4(key, ciphertext XOR 0x55)`；从脚本常量中取出 key 与密文即可直接解密。
- **为什么可直接静态解**：没有依赖 Android 运行时状态、设备指纹或服务端下发；AES key 与密文同段存放，RC4 key 与密文又硬编码在脚本中，两段加密都只是防止直接阅读，不构成密钥保密。

## 触发条件

- APK 的 `assets` 内带完整或裁剪的 Python 运行时（存在 `python/lib/pythonX.Y/site-packages`）。
- native 库导出返回字节数组的 JNI 函数，或 Java 层把返回值写入 `site-packages`。
- `site-packages` 中出现 `sitecustomize.py`、`usercustomize.py`、`*.pth` 等启动期自动加载文件。
- 脚本中存在 `builtins.open`/`__builtins__` 替换、`__xor__`/`__lshift__`/`__eq__` 等大量运算符重载。

## 利用步骤

1. 解包 APK，确认 `assets/python/.../site-packages` 与加载 Python 的 native 库（如 `libpythonrunner.so`、`libvipdecryptor.so`）。
2. 在 IDA 中定位 JNI 导出函数，跟踪到 AES 调用；读取 `.data` 中的密文长度、密钥偏移与 key 字符串。
3. 用 `pyelftools` 取 `.data`，按“密文在前、key 紧随其后”的布局切分，AES-ECB 解密得到 `sitecustomize.py`。
4. 审计解密出的脚本：列出 `builtins.open` 的替代类，逐个还原 `__xor__`/`__lshift__`/`__eq__` 的返回对象与状态推进方式，把表达式翻译回普通数据流。
5. 从 `Keyget`、`GetEnc` 中提取 RC4 key、密文与 XOR 掩码，按脚本中的 KSA/PRGA 复现解密，得到 flag。
6. 若脚本读取的密文被拆分/编码，按脚本里的切片、hex、Base64 顺序还原；必要时直接在 Python 中 import 该脚本，利用其重载对象跑出明文。

## PoC

```python
from elftools.elf.elffile import ELFFile
from Crypto.Cipher import AES, ARC4

so_path = "libvipdecryptor.so"
with open(so_path, "rb") as f:
    data = ELFFile(f).get_section_by_name(".data").data()

ct_len = 0x680
ct = data[:ct_len]
key = data[ct_len:ct_len + 16]          # b"sitecustomize.py"
script = AES.new(key, AES.MODE_ECB).decrypt(ct)
open("sitecustomize.py", "wb").write(script)

# 从解密脚本中还原出的 RC4 参数
rc4_key = b"y0u_@re_vip_Us3r"
enc = bytes.fromhex("738d9ea5a7c5824836d63c872324e36936c1dd7026b2df418268066a936256a7")
pt = ARC4.new(rc4_key).decrypt(bytes(b ^ 0x55 for b in enc))
print(pt.decode())   # 5f19b83de29bd46e9e02f7f88bfb4ea2
```

VIP 激活码另有一条 AES-CBC 分支：key 为 `8888888888888888`、IV 为 `00..0f`，对 Base64 的 `VALID_CODE_ENC` 解密可得到激活码；但校验脚本本身不依赖激活状态，该分支可以跳过。

## 变体与关联

- 其他解释器启动钩子：`usercustomize.py`、`PYTHONSTARTUP`、`.pth` 文件中的 `import` 行、`sitecustomize` 的 `sitecustomize.py` 变体，均可在用户代码前执行。
- 若脚本不是加密而是 `marshal`/`.pyc`，先反编译；若是运算符重载，按对象映射表还原，不要尝试直接执行不明脚本。
- 与本库“monkey-patch `str.__eq__` 记录比较对”的卡片不同：本场景替换的是 `builtins.open` 并构造伪数据流，目的是隐藏算法本身而非记录比较结果。
- 若密文/key 不在 `.data` 而同在 `.rodata`，或做了分段异或，仍可用相同思路按引用关系定位。

## 检测与防御

- 检测 APK：`assets` 中出现完整 Python 发行版；`site-packages` 存在 `sitecustomize.py`/`usercustomize.py`；native 库对大块高熵 `.data` 做 AES；Java 层存在“解密字节数组后写入 site-packages”的调用。
- 运行时检测：监控对应用私有目录下 `sitecustomize.py` 的写入，监控 `builtins.open` 被替换，检查解释器启动参数与 `PYTHONPATH`。
- 防御：不要把密钥与密文放在同一段；对启动钩子脚本做签名校验；限制应用私有目录中可被解释器自动加载的路径。CTF 场景不需要防御，识别“内嵌解释器 + 启动钩子 + 原生层加密脚本”的组合即可。

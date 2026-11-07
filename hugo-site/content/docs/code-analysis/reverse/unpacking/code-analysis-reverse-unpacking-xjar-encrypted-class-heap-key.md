---
id: code-analysis-reverse-unpacking-xjar-encrypted-class-heap-key
title: XJar 加密 JAR 逆向：从启动器参数与 VisualVM 堆转储提取 AES key/iv 解密 class
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: xjar-encrypted-jar-heap-key-decrypt
tags:
- java
- jar
- xjar
- unpacking
- aes
- heap-dump
- visualvm
- reverse-engineering
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:11:57+08:00'
  notes: 已对照原文与32张截图核对：start-svc.exe 启动参数 AES/CBC/PKCS5Padding/128/128/ed1ee71da4a949e580c3f344aba5ab2d、XjarClassLoader 堆转储 key/iv 有符号字节数组、AES-CBC 解密脚本、Java agent dump 不全均与图文一致。未验证点：未复跑解密；密码与 key/iv 的派生关系原文未完全展开。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-xjar-encrypted-class-heap-key/
draft: false
kb_aliases:
- XJar
- XjarClassLoader
- MSRSCI.jar
- AES/CBC/PKCS5Padding
- VisualVM Heap Dump
- ClassFileTransformer dump
- 加密 JAR 脱壳
---

## 一句话结论

XJar 保护的 JAR 会把关键 class 加密，运行时由 `XjarClassLoader` 用 AES/CBC/PKCS5Padding 解密后再定义类；逆向时可从启动器（如 `start-svc.exe`）动态调试拿到启动参数（算法、key/iv 长度、密码），或从 VisualVM 的 Heap Dump 中读取 `XjarClassLoader` 的 key/iv 字段，按 AES-CBC 解密 JAR 内 `org/dromara/` 下的 class，再用 Java agent 的 `ClassFileTransformer` 辅助 dump 已加载类。

## 原理

- XJar 是 Java JAR 加密工具：构建时把指定包（如 `org/dromara/`）下的 `.class` 用 AES 加密后放回 JAR；运行时通过自定义 `XjarClassLoader` 在 `findClass`/`defineClass` 前解密，内存中再还原成正常字节码。
- 启动器通常不是直接 `java -jar`，而是用原生程序（本题 `start-svc.exe`）做完整性校验后，构造命令行把解密参数传给 Java：
  ```text
  AES/CBC/PKCS5Padding
  128
  128
  ed1ee71da4a949e580c3f344aba5ab2d
  ```
  四个参数分别对应算法、key 长度、iv 长度、密码；密码可能用于派生 key/iv，真正的 key/iv 在 `XjarClassLoader` 实例中。
- 静态反编译 JAR 时，关键 class 显示为乱码/无法反编译，是因为它们是密文；非加密类（如 `io.xjar`）仍可反编译，可从中确认 XJar 与参数格式。
- 获取 key/iv 的两种方式：
  1. **动态调试启动器**：在 `CreateProcess`/`os_exec_Command` 等构造命令行处下断点，读取四个参数；也可直接在控制台用这些参数启动 JAR。
  2. **Heap Dump**：用 VisualVM 附加运行中的 JAR，Heap Dump 后在 Objects 中搜索 `XjarClassLoader`，查看其 `key`/`iv` 字段；字段可能以有符号 byte 数组显示，需要 `b % 256` 转无符号。
- 解密：`AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)`；XJar 的 class 密文可能不是 16 字节对齐，需要补 0 到 16 的倍数；解密后按 PKCS5/7 去填充，失败时保留原始结果（可能不是标准填充）。
- 辅助手段：写 Java agent，实现 `ClassFileTransformer`，在 `transform` 中把 `classfileBuffer` 写到磁盘；但部分类由自定义 ClassLoader 加载、未经过 transformer，可能 dump 不全，所以最终仍要拿到 key/iv 自行解密。
- 根因是“客户端必须能解密并执行 class”，密钥/明文最终都在内存中；XJar 只提高静态分析成本，不能阻止动态提取。

## 触发条件

- 目标是 XJar（或类似 ClassLoader 加密）保护的 JAR，关键 class 无法正常反编译。
- 能找到启动器/启动脚本，或能附加到运行中的 Java 进程。
- 启动器没有强反调试/反附加，或 Heap Dump 可用；JAR 的加密类使用标准 AES-CBC。
- 允许动态调试/内存取证（授权分析环境）。

## 利用步骤

1. 反编译 JAR，确认哪些包/类被加密（如 `org/dromara/`），在 `io.xjar` 等未加密类中找解密参数格式。
2. 分析启动器（IDA/Ghidra）：搜索 `-jar`、`CreateProcess`、命令行拼接、完整性校验；在构造命令行处下断点，或直接运行启动器并在控制台观察参数。
3. 用拿到的算法/key 长度/iv 长度/密码启动 JAR；若密码不是直接 key，用 VisualVM 附加进程，Heap Dump → Objects → 搜索 `XjarClassLoader`，读取 `key`/`iv` 字段。
4. 把有符号 byte 转无符号（`b % 256`），按 AES-CBC 解密 JAR 中目标 class；处理非 16 对齐与填充。
5. 重新打包成普通 JAR，或用 JD-GUI/CFR/Procyon 反编译，分析远控/业务逻辑。
6. 若类仍未 dump/解密，检查是否有二次加密、类加载器嵌套或运行时字节码修改。

## PoC

```python
import zipfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

raw_key = [-126, 123, -47, -59, 15, -126, 41, -52, 46, 122, 61, 126, 41, -74, 3, -65]
raw_iv  = [54, -26, -90, 32, 90, -96, -13, 41, -102, 86, 61, 94, -24, 103, 50, 97]
key = bytes(b % 256 for b in raw_key)
iv  = bytes(b % 256 for b in raw_iv)

def decrypt_xjar(data: bytes) -> bytes:
    if len(data) % 16:
        data += b"\x00" * (16 - len(data) % 16)
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    try:
        return unpad(dec, 16)
    except ValueError:
        return dec

with zipfile.ZipFile("MSRSCI.jar") as zin, zipfile.ZipFile("decrypted.jar", "w") as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename.startswith("org/dromara/") and item.filename.endswith(".class"):
            data = decrypt_xjar(data)
        zout.writestr(item, data)
```

Java agent dump（辅助）：

```java
public static void premain(String args, Instrumentation inst) {
    inst.addTransformer((module, loader, className, redefined, domain, buffer) -> {
        if (className == null || buffer == null) return null;
        File f = new File("dump_classes/" + className + ".class");
        f.getParentFile().mkdirs();
        try (FileOutputStream out = new FileOutputStream(f)) { out.write(buffer); }
        catch (Exception ignored) {}
        return null;
    });
}
```

## 变体与关联

- **加密工具变体**：XJar、ClassFinal、ProGuard 混淆 + 自定义 ClassLoader、Spring Boot 嵌套 JAR 加密；思路都是找解密入口/key。
- **密钥获取变体**：启动参数、配置文件、环境变量、Heap Dump、调试器断点、`XjarClassLoader` 字段、密码派生（PBKDF2/SHA1）。
- **解密变体**：AES-CBC/ECB/CTR、异或流、二次加密；注意对齐、填充、IV 来源。
- **关联**：[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（打包器脱壳的同类思路）；[[code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation]]（运行时解密后 dump）；[[defense-forensics-java-rat-encrypted-config-h2-db]]（本题后续配置解密）。
- **边界**：启动器强反调试/反附加、key 由硬件/远程下发且不落内存、Heap Dump 被禁用时，需要更底层的调试/内存取证。

## 检测与防御

- **检测**：JAR 内 class 熵异常高、`XjarClassLoader`/`io.xjar` 特征、启动器构造 `java -jar` 参数、进程 Heap Dump 中出现 key/iv 数组。
- **防御**：XJar 只是提高逆向成本，不能作为安全边界；不要把密钥/授权逻辑放在客户端；对敏感逻辑使用服务端校验。
- **加固**：反调试/反附加、密钥远程下发与内存清零、类加载完整性校验；分析侧则用 Heap Dump/调试器提取。

---
id: web-java-deserialization-xmldecoder-hodoku-hsol-puzzle-rce
title: Hodoku 数独客户端 .hsol 存档导入触发 XMLDecoder 反序列化 RCE（CVE-2024-51363）：zip 内 XML 直接交给 readObject
type: scenario
domain: web
path: web/java/deserialization
technique: xmldecoder-hsol-archive-import-rce
aliases:
- CVE-2024-51363
- Hodoku 反序列化
- XMLDecoder readObject
- .hsol 文件反序列化
- loadFromFile fileType 1
- Open Puzzle File 菜单
- java.beans.XMLDecoder ProcessBuilder
tags:
- java
- deserialization
- xmldecoder
- desktop
- file-import
- rce
- cve-2024-51363
- client-side
cve:
- CVE-2024-51363
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:20:40+08:00'
  notes: 已对照原文核对 fileType==1 分支的 ZipInputStream+new XMLDecoder(zIn)+in.readObject()、initComponents->loadPuzzleMenuItemActionPerformed->loadFromFile 链、菜单项 Open Puzzle File... 与 .hsol 后缀、以及 ProcessBuilder+String[1]+void method=start 的 payload 结构；本次核对未读取图片；原文未给出受影响版本区间，未设 affected_versions；CVE-2024-51363 编号沿用通告，未额外查证
---

## 一句话结论

Hodoku（Java/Swing 数独程序）的「Open Puzzle File...」菜单在打开 `.hsol` 存档时走 `loadFromFile(path, 1)` 分支：用 `ZipInputStream` 读取压缩包第一个 entry，然后把整个流交给 `new XMLDecoder(zIn)` 并调用 `in.readObject()`。`XMLDecoder` 会把 XML 里的 `<object class="...">` 当作要实例化的类、`<void method="..."/>` 当作要调用的方法，于是构造一个 `java.lang.ProcessBuilder` 对象并调用其 `start()` 的最小 XML，压缩成 zip 后改名为 `.hsol`，诱导用户「打开题目文件」即触发任意命令执行。

## 原理

- **XMLDecoder 本身就是「可执行 XML」**：`java.beans.XMLDecoder` 为 JavaBeans 的 XML 持久化设计，解析 `<object class="X">` 会 `new X(...)`，`<void method="m">` 会在前一个对象上反射调用 `m(...)`，`<array class="..." length="n">` + `<void index="i"><string>..</string></void>` 用来填数组元素。它没有任何类型白名单，等价于把「类名 + 方法名 + 参数」交给程序执行，因此在处理不可信数据时必然导致任意对象构造与方法调用。
- **最小利用元件**：`java.lang.ProcessBuilder` 有公开构造器 `ProcessBuilder(List<String>)` 与单参便捷构造 `ProcessBuilder(String...)`，`start()` 返回 `Process`；`<array class="java.lang.String" length="1"><void index="0"><string>calc</string></void></array>` 构造一个只含命令的 `String[]`，作为构造参数传入即可让 `ProcessBuilder` 持有该命令，`<void method="start"/>` 触发执行。
- **为什么会在客户端触发**：`loadPuzzleMenuItemActionPerformed`（`initComponents` 里注册的菜单动作）→ `loadFromFile`；当 `fileType == 1` 时不走 `Options.readOptions` 的普通文本解析，而是把文件当 zip：`zIn.getNextEntry()` 取第一个条目后直接把流喂给 `XMLDecoder`，缺少「先校验条目内容/类型」的中间步骤。文件名后缀约定 `.hsol` 只是 UI 层的过滤器，不构成安全边界。
- **攻击面在「文件交换」**：数独题目的 `.hsol` 是玩家/社区之间互传的存档格式，导入第三方题包是常规操作；攻击者只需提供一个「看起来正常」的压缩包，用户在客户端里打开即中招，无需任何网络服务暴露。
- **为什么这条链是完整的**：从菜单入口到 sink 的调用链在原文中被逐层跟出（`initComponents` → `loadPuzzleMenuItemActionPerformed` → `loadFromFile` → `XMLDecoder#readObject`），PoC 由公开 payload 与压缩打包两步构成，末端是 `ProcessBuilder.start()`，危害为命令执行，不依赖后续二次条件。

## 触发条件

- 目标安装存在该漏洞的 Hodoku 版本，且使用「Open Puzzle File...」导入 `.hsol`；
- 攻击者能向受害者投递一个 zip 压缩包（把后缀改成 `.hsol`）并诱导其打开；
- 受害者的 JRE 允许 `java.lang.ProcessBuilder`（标准 JDK 均可用），且程序以普通用户权限运行；
- 无需认证、无需目标开放任何端口。

## 利用步骤

1. 定位入口：反编译/查看 `Hodoku` 主窗口 `initComponents()` 中「Open Puzzle File...」菜单项的 `ActionListener`，跟到 `loadPuzzleMenuItemActionPerformed`。
2. 跟到 `loadFromFile(String path, int fileType)`：确认 `fileType == 1` 分支用 `ZipInputStream` + `XMLDecoder(zIn)` + `in.readObject()`；`fileType` 由文件后缀决定（`.hsol` → 1）。
3. 构造 XML：一个 `java.lang.ProcessBuilder` 对象，构造参数为长度 1 的 `String` 数组（元素为要执行的命令），随后 `<void method="start"/>`。
4. 把 XML 命名成任意文件（如 `poc.xml`），用 zip 压缩，产物改名为 `poc.hsol`。
5. 在目标机器上用 Hodoku 打开该 `.hsol`（菜单 → Open Puzzle File...），`readObject` 执行 XML，`ProcessBuilder.start()` 拉起命令，得到命令执行。

## PoC

最小 XML（原文给出的完整 payload，命令位置换成待执行命令）：

```xml
<java>
    <object class="java.lang.ProcessBuilder">
        <array class="java.lang.String" length="1" >
            <void index="0">
                <string>calc</string>
            </void>
        </array>
        <void method="start"/>
    </object>
</java>
```

打包：

```bash
zip poc.zip poc.xml
mv poc.zip poc.hsol      # 后缀只影响 fileType 选择，压缩包内容不变
```

要点：`<array>` 必须作为 `ProcessBuilder` 的**构造参数**出现在 `<object>` 内部（XMLDecoder 按出现顺序把子元素当作构造实参），`<void method="start"/>` 必须写在数组之后，否则会在对象还没拿到命令时就调用方法。

## 变体与关联

- **变体（换个执行元件）**：同样的 XML 结构可把 `ProcessBuilder` 换成 `java.lang.Runtime`（`getRuntime` + `exec`）、`java.lang.System`（`setProperty`）、或写文件的 `java.io.FileOutputStream` + `write`，用于无命令执行回显时的落地验证。
- **变体（换个入口）**：任何把不可信文件/流交给 `XMLDecoder` 的导入功能都成立，例如「打开项目」「导入配置」「恢复备份」；关键特征是 `new XMLDecoder(...)` 后紧跟 `readObject()`。
- **变体（编码）**：`XMLDecoder` 也可解析 `java.beans.Statement`/`Expression` 形式的 `<object class="java.beans.Statement">`，部分过滤器只拦 `ProcessBuilder`/`Runtime` 字符串时可用 `Statement` 反射调用绕过。
- **关联**：[[web-java-deserialization-custom-readobject-runtime-exec]]（业务类 `readObject` 里直接 `Runtime.exec` 的入口型反序列化）、[[web-java-deserialization-hashmap-business-field-local-file-read]]（「数据字段直达危险 sink」的同型思路）、[[web-java-component-weaver-ecology-jdbc-socketfactory-memshell]]（XMLDecoder 作为内存马载荷的另一处用法）。

## 检测与防御

- **代码侧**：不要用 `XMLDecoder` 处理外部文件——包括「本地文件」和「用户导入的存档」。确有 XML 配置需求时改用带 schema 的 JAXB/Jackson XML 并显式绑定类，禁止 `readObject()` 直接吃不可信流。
- **产品侧**：导入功能应做格式白名单校验（例如只接受应用自身生成的、带签名/HMAC 的存档），对 zip 条目做大小/数量/路径限制，把 `.hsol` 的解析换成纯数据格式（JSON/自定义二进制），彻底移除可执行 XML 的解析路径。
- **检测点**：进程行为上，Java 客户端进程（`javaw.exe`/`java`）在打开文档后直接派生 `cmd.exe`/`powershell.exe`/`calc.exe` 等子进程是强异常；文件侧可检查 `.hsol`/`.zip` 内是否含 `<object class=`、`java.lang.ProcessBuilder`、`java.beans`、`<void method=` 等特征字符串。
- **缓解**：以低权限账户运行客户端；对用户目录下的存档导入做告警；企业环境可用 AppLocker/EDR 规则禁止办公类 Java 进程派生 shell。

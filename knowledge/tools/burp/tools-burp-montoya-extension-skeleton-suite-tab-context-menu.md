---
id: tools-burp-montoya-extension-skeleton-suite-tab-context-menu
title: Burp Montoya API 自研扩展最小骨架：BurpExtension 初始化、Suite Tab 注册与 ContextMenuItemsProvider 右键菜单
type: scenario
domain: tools
path: tools/burp
technique: montoya-extension-skeleton-suite-tab-context-menu
aliases:
- Montoya API 插件开发
- BurpExtension initialize
- Montoya 扩展骨架
- Burp 自定义 Suite Tab
- ContextMenuItemsProvider 右键菜单
- createHttpRequestEditor
- registerSuiteTab
- Montoya API 类库总览
tags:
- burp
- montoya
- burp-extension
- java
- maven
- gradle
- suite-tab
- context-menu
- http-request-editor
- tooling
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V313
  verified_at: '2026-11-08T12:47:15+08:00'
  notes: 已完整阅读 content.md 并逐张核对 9 张图：01 BurpExtender API 的 BurpExtension 接口（public、public 无参构造、initialize(MontoyaApi)、handler 在 initialize 完成后生效）；02 IDEA 新建 Gradle 项目（JDK 11）；03 build.gradle implementation net.portswigger.burp.extensions:montoya-api:2023.12.1；04 javadoc 导出按钮；05 扩展列表 MyExtension1.0；06 Output 页 this is a test/by ccc；07 右键扩展菜单 MyExtension1.0→Test；08 Burp 内 HttpMessage javadoc；09 通义灵码生成 createHttpRequestEditor/registerSuiteTab 代码。依赖坐标、入口类、Suite Tab、右键菜单 provider 代码与原文一致；原文未展示 provider 注册行，卡内已注明按 Montoya API 补为 registerContextMenuItemsProvider。Burp v2024.3.1.2 与 montoya-api 2023.12.1 属开发环境/依赖版本，非漏洞受影响版本，affected_versions 为空正确。dedup 除自身外 20 个候选均 new，与 Galaxy/Burpy/autoDecoder 等现成插件卡非同链；dup-scan 无本篇 pair。未验证点：未在本机编译加载该扩展，READ_ONLY import 原文未给。
---

## 一句话结论

从零写一个自研 Burp 扩展的最小闭环是：Java 工程引入 `net.portswigger.burp.extensions:montoya-api`，写一个 public、无参构造、实现 `BurpExtension` 的类并在 `initialize(MontoyaApi api)` 里配置名称与日志；要 UI 交互时再用 `api.userInterface().registerSuiteTab(name, JPanel)` 挂顶层 tab、用 `createHttpRequestEditor(READ_ONLY)` 嵌入 HTTP 报文编辑器、实现 `ContextMenuItemsProvider.provideMenuItems` 往右键菜单加动作，即可把测试中的重复操作固化成一个可加载的 jar 插件。

## 原理

- **加载机制**：Burp 加载扩展 jar 时会自动检测并实例化所有实现了 `burp.api.montoya.BurpExtension` 的类，并调用其 `initialize(MontoyaApi api)`。插件类必须是 `public` 且提供 public 无参构造，不需要额外的注册文件或清单，这也是入口代码能极短的原因。`initialize` 返回后，已注册的 handler 才会生效。
- **MontoyaApi 是总入口**：Burp 通过 `initialize` 把 `MontoyaApi` 传给插件，它按模块暴露 Burp 的能力，原文列出的主要模块包括：
  - `burp.api.montoya.burpsuite`：命令行参数、导出项目级/用户级配置为 JSON、编程式关闭、任务执行引擎；
  - `burp.api.montoya.collaborator`：Collaborator payload 生成与反连结果获取；
  - `burp.api.montoya.comparer`：Comparer 比较功能；
  - `burp.api.montoya.extension`：插件自身属性（如 `setName`）；
  - `burp.api.montoya.http` / `.http.handler` / `.http.message`：HTTP 请求响应访问、`HttpHandler` 注册、`HttpRequest`/`HttpResponse`/`HttpParameter`；
  - `burp.api.montoya.ui`：Suite Tab、HTTP 编辑器、主题、选择内容等 UI 能力；
  - `burp.api.montoya.logging`：扩展 Output/Error 输出。
- **叶模块结构决定了扩展能做什么**：`http.handler.HttpHandler` 让插件在请求/响应经过 Burp 时自动改写（适合自动加解密、签名、加头）；`ui` 模块让插件把自己的面板放进 Burp 主界面，从而把“复制到外部脚本处理再粘回”的流程收敛到 Burp 内部。
- **UI 组合方式**：`createHttpRequestEditor(...)` 返回一个 `HttpRequestEditor`，其 `uiComponent()` 是标准 Swing 组件，可加入任意 `JPanel`；`registerSuiteTab` 把这个 `JPanel` 注册成 Burp 顶部的独立标签页。`READ_ONLY` 选项让编辑器只展示不可改，不传参数则为可读写。
- **右键菜单**：实现 `ContextMenuItemsProvider` 的 `provideMenuItems(ContextMenuEvent event)`，返回 `List<Component>`（实际为 `JMenuItem`），Burp 会把这些项挂到右键菜单的扩展分组下。点击后的 `actionPerformed` 运行在 Swing 事件线程，修改界面组件需用 `SwingUtilities.invokeLater` 回到事件线程，避免线程问题。
- **与旧 Extender API 的关系**：Montoya 是 PortSwigger 新推的插件 API，旧 Extender API 将被逐步放弃；Montoya 的接口按模块拆分、类型更全，因此新插件应直接按 Montoya 写。

## 触发条件

- 需要在 Burp 中固化一个重复动作：如一键把当前请求/响应写入自定义面板、对选中报文做自定义解析、给右键菜单加“发送到我的工具”等。
- 本机有 JDK（原文用 JDK 11）与 Maven 或 Gradle；Burp 版本支持 Montoya API（原文用 Burp Suite Professional v2024.3.1.2，依赖 montoya-api 2023.12.1）。
- 已获得在测试机上加载自研扩展的权限；只对授权目标使用。

## 利用步骤

1. **建工程**：IDEA 新建 Java 项目（Maven 或 Gradle 均可），语言 Java。
2. **加依赖**：Maven 在 `pom.xml` 加入 `net.portswigger.burp.extensions:montoya-api:2023.12.1`；Gradle 在 `dependencies` 加 `implementation 'net.portswigger.burp.extensions:montoya-api:2023.12.1'`。依赖也可从 Burp 的扩展 API 界面导出/保存获得。
3. **写入入口类**：`public class MyExtension implements BurpExtension`，实现 `initialize(MontoyaApi api)`；在方法内保存 `api` 引用，调用 `api.extension().setName("MyExtension1.0")`，用 `api.logging().logToOutput(...)` 输出加载日志。
4. **加 Suite Tab**：new 一个 `JPanel`（如 `BorderLayout`），把 `api.userInterface().createHttpRequestEditor(READ_ONLY).uiComponent()` 放到 CENTER，再加一个 `JTextArea`+`JScrollPane` 到 NORTH 作为结果区，最后 `api.userInterface().registerSuiteTab("test", Mytab)`。
5. **加右键菜单**：实现 `ContextMenuItemsProvider`，在 `provideMenuItems` 中创建 `JMenuItem`，用 `addActionListener` 绑定动作；动作内用 `SwingUtilities.invokeLater` 更新结果区。把 provider 注册到 `UserInterface`（注册调用原文未展示，按 Montoya API 为 `api.userInterface().registerContextMenuItemsProvider(provider)`）。
6. **构建与安装**：构建 jar/工件，Burp `Extensions → Add → Java` 选择该 jar；在扩展的 Output 页看到 `this is a test`、`by ccc` 说明 `initialize` 已执行；顶部出现自定义 tab，右键菜单的“扩展”子菜单出现 `MyExtension1.0 → Test`。
7. **查 API**：需要具体类/方法时，在 Burp 的 Extender/扩展页面打开内置 API javadoc 检索，或读 `PortSwigger/burp-extensions-montoya-api` 源码与示例；不要只依赖类名列表。

## PoC

Maven 依赖：

```xml
<dependency>
    <groupId>net.portswigger.burp.extensions</groupId>
    <artifactId>montoya-api</artifactId>
    <version>2023.12.1</version>
</dependency>
```

扩展入口（按原文整理，import 由 IDE 补全）：

```java
package org.example;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class MyExtension implements BurpExtension {
    public MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        // 插件名称，显示在扩展列表中
        api.extension().setName("MyExtension1.0");

        // 加载后输出到扩展 Output 页
        Logging log = api.logging();
        log.logToOutput("this is a test");
        log.logToOutput("by ccc");
    }
}
```

Suite Tab + 内嵌请求编辑器（原文片段）：

```java
JPanel Mytab = new JPanel(new BorderLayout());
HttpRequestEditor myRequestEditor = api.userInterface().createHttpRequestEditor(READ_ONLY); // READ_ONLY 只读；不传则可读写
Mytab.add(myRequestEditor.uiComponent(), BorderLayout.CENTER);
api.userInterface().registerSuiteTab("test", Mytab);

JTextArea resultArea = new JTextArea(10, 30);
JScrollPane scrollPane = new JScrollPane(resultArea);
Mytab.add(scrollPane, BorderLayout.NORTH);
```

右键菜单（原文片段，仅 provider 实现）：

```java
public List<Component> provideMenuItems(ContextMenuEvent event) {
    List<Component> listMenuItems = new ArrayList<>();
    JMenuItem TestJmenu = new JMenuItem("Test");
    TestJmenu.addActionListener(new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            SwingUtilities.invokeLater(() -> {
                resultArea.append("baidu test\n");
                resultArea.setCaretPosition(resultArea.getDocument().getLength());
            });
        }
    });
    listMenuItems.add(TestJmenu);
    return listMenuItems;
}
```

## 变体与关联

- **HttpHandler 路线**：若目标是自动改写流量而不是手动点菜单，实现 `burp.api.montoya.http.handler.HttpHandler` 并调用 `api.http().registerHttpHandler(...)`，比 UI 路线更适合加解密/加签场景；与 [[tools-burp-galaxy-http-hook-dynamic-key-capture]] 的 Montoya 四段 hook 思路同源，但本卡是自研扩展骨架，那张卡是使用 Galaxy 插件。
- **旧 API 路线**：旧 Extender API（`IBurpExtender`、`IExtensionHelpers` 等）仍可用但已被宣布逐步放弃，新开发应选 Montoya。
- **开发辅助变体**：用 IDE/大模型（原文用通义灵码）基于 Montoya 类和 javadoc 生成样板代码，可加快 UI 部分；核心 hook 逻辑仍需自己按 Burp 生命周期验证。
- **关联卡片**：[[tools-burp-galaxy-jsrpc-auto-encrypt-decrypt-sign]]、[[tools-burp-autodecoder-flask-custom-encrypt-decrypt-script]]、[[tools-burp-burpy-pyro-python-auto-encrypt-decrypt]]（均为现成加解密插件路线，可与自研扩展对比选型）。
- **边界**：扩展运行在 Burp 进程内、拥有与 Burp 相同的权限，能读取全部流量与配置；只加载可信来源的 jar。不同 Burp 版本内置的 Montoya API 版本不同，依赖版本不匹配可能导致运行期 `NoSuchMethodError`，应以目标 Burp 自带 javadoc/API 导出为准。

## 检测与防御

- 本卡是自研测试工具的开发骨架，本身不针对特定目标，无远程攻击面；“防御”主要针对插件供应链与使用合规。
- **插件来源审计**：Burp 扩展能读取代理中的全部请求响应（含 Cookie/Token），只从官方 BApp Store 或自己构建的源码加载；第三方 jar 加载前审代码或至少核对哈希。
- **最小权限与隔离**：自研扩展只做当前项目需要的事，不额外外联；调试日志避免打印敏感头与凭据。
- **版本匹配**：升级 Burp 后重新编译扩展并对齐 montoya-api 版本，避免旧 jar 静默失效或抛异常。
- **合规**：仅在授权测试与自有环境中安装和使用；扩展产生的自动化请求需限速并控制在授权范围内。

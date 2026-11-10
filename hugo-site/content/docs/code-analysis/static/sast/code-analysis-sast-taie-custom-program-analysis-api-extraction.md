---
id: code-analysis-sast-taie-custom-program-analysis-api-extraction
title: Tai-e 自定义程序分析扩展提取 Spring Controller API：MethodAnalysis/ClassAnalysis/ProgramAnalysis + tai-e-analyses.yml 注册 + 注解路由解析
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: taie-custom-analysis-api-extraction
tags:
- code-analysis
- sast
- taie
- java
- spring-boot
- api-extraction
- annotation
- static-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V452
  verified_at: '2026-11-10T02:23:32+08:00'
  notes: 已对照原文与 26 张截图核对：三种扩展点(MethodAnalysis/ClassAnalysis/ProgramAnalysis)描述、tai-e-analyses.yml 注册(analysisClass+id)、-a/analyses 两种启用方式、TestMethod 输出方法名、ProgramAnalysis 用 World.applicationClasses+@*Mapping 注解+annotation.getElement 提取路由、extractApi 输出 /cors//ssrf//sqli 等路由、appClassPath=../../java-sec-code/target/classes、gradle fatJar 均有截图佐证；原文未声明组件受影响版本，affected_versions 置空；未被验证点：未在本机复跑 Tai-e
url: /docs/code-analysis/static/sast/code-analysis-sast-taie-custom-program-analysis-api-extraction/
draft: false
kb_aliases:
- Tai-e 二次开发
- Tai-e 自定义分析
- MethodAnalysis ProgramAnalysis
- tai-e-analyses.yml 注册分析
- Controller 路由提取
- Spring API 清单提取
---

# 一句话结论

Tai-e 允许在框架内新增自定义程序分析：继承 `MethodAnalysis`（按方法，`analyze(IR)`）、`ClassAnalysis`（按类，`analyze(JClass)`）或 `ProgramAnalysis`（全程序，`analyze()` 中可用 `World`），并在 `resources/tai-e-analyses.yml` 登记 `analysisClass` 与 `id` 后，用 `-a <id>` 或 options 的 `analyses: <id>: ;` 启用。文章用 ProgramAnalysis 遍历 `World.get().getClassHierarchy().applicationClasses()`，匹配类/方法上的 `@*Mapping` 注解并解析 `annotation.getElement("value")`，成功把 Spring Boot 应用的 Controller 路由导出为完整 API 清单（/cors、/ssrf、/sqli 等）。

# 原理

- **基于 Tai-e IR 的自定义分析**：Tai-e 前端把 Java 源码/字节码转为 Soot Jimple IR 再转 Tai-e IR，指针分析与污点分析都在 Tai-e IR 上运行。开启 `ir-dumper: ;` 后可在 `output/tir` 查看每个方法的 IR，`@RestController`、`@RequestMapping({"/sqli"})` 等注解会原样出现在 IR 中；因此只依赖 TIR 就能做注解/路由类分析，不必进入指针分析。
- **三种扩展点**：`MethodAnalysis.analyze(IR)` 对每个方法执行一次；`ClassAnalysis.analyze(JClass)` 对每个类执行一次；`ProgramAnalysis.analyze()` 对整个程序执行一次，可通过 `World.get()` 获取全局类层次、应用类集合等信息。需要汇总 class 与 method 两级路径的 API 提取适合用 ProgramAnalysis。
- **注册与启用机制**：在 `src/main/resources/tai-e-analyses.yml` 增加 `description`、`analysisClass`（实现类全名）、`id`（与类中的 `public static final String ID` 一致）；启用方式二选一：命令行 `-a <id>`，或在 options 的 `analyses:` 下写 `<id>: ;`。运行时输出 `<id> starts ...` 与耗时。
- **路由提取实现**：`World.get().getClassHierarchy().applicationClasses()` 拿到应用类；`jClass.getAnnotations()` / `jMethod.getAnnotations()` 用正则 `org.springframework.web.bind.annotation.\w+Mapping` 过滤；`annotation.getElement("value").toString()` 取出 `{"/sqli"}` 形式的路径，再 `formatMappedPath` 清理花括号等字符。类与方法是 1:N，定义 `Router(className, classPath, List<MethodRouter>)` 与 `MethodRouter(methodName, path)` 结构化输出。
- **运行与产出**：把自定义类放到 `src/main/java/pascal.taie/analysis/...`，`gradle fatJar` 构建 `tai-e-all-*.jar`，`java -cp tai-e-all.jar pascal.taie.Main --options-file=options.yml` 运行；options 中 `appClassPath` 指向被分析项目编译后的 classes，`analyses` 启用 `extractApi`。案例成功打印出全部 Controller 路由。
- **用途**：企业 API 资产梳理/攻击面测绘时接口文档常缺失，直接从字节码注解提取真实路由；也可作为污点分析的 source/入口清单输入。

# 触发条件

- 可获得 Tai-e 源码/可改造版本（案例 0.5.1-SNAPSHOT），能新增 analysis 类并构建 fatJar。
- 被分析项目为 Spring Boot/Spring MVC，Controller 使用 `@RequestMapping`/`@GetMapping` 等注解。
- 目标是 API 清单/资产梳理或为污点分析生成入口，而不是一次性的漏洞扫描。
- 能提供被分析项目的编译产物（`--app-class-path` 指向 `target/classes` 或业务 jar）。

# 利用步骤

1. 继承 `MethodAnalysis`（或 `ClassAnalysis`/`ProgramAnalysis`），声明 `public static final String ID = "extractApi"` 并实现 `analyze`。
2. 在 `src/main/resources/tai-e-analyses.yml` 注册：
   ```yaml
   - description: Extract api from controller
     analysisClass: pascal.taie.analysis.extractapi.ExtractApi
     id: extractApi
   ```
3. 在 options.yml 的 `analyses:` 下加入 `extractApi: ;`（或命令行 `-a extractApi`），并设置 `appClassPath` 指向业务 classes。
4. 用 `World.get().getClassHierarchy().applicationClasses()` 遍历类；对类与方法注解按 `org.springframework.web.bind.annotation.\w+Mapping` 过滤，取 `annotation.getElement("value")` 得到路径。
5. 组装 Router/MethodRouter（class 路径 + 每个 method 路径），打印或序列化输出。
6. `gradle fatJar` 构建后运行 `java -cp tai-e-all-0.5.1-SNAPSHOT.jar pascal.taie.Main --options-file=options.yml`，核对输出 API 清单与实际 Controller 一致。

# PoC

```java
public class TestMethod extends MethodAnalysis {
    public static final String ID = "testmethodanalysis";
    public TestMethod(AnalysisConfig config) { super(config); }
    @Override
    public Object analyze(IR ir) {
        System.out.println(ir.getMethod().getName());
        return null;
    }
}
```

```java
// ProgramAnalysis 中提取注解路由（节选）
World.get().getClassHierarchy().applicationClasses().forEach(jClass -> {
    jClass.getDeclaredMethods().forEach(jMethod -> {
        if (!jMethod.getAnnotations().stream().filter(a ->
                a.getType().matches("org.springframework.web.bind.annotation.\\w+Mapping")).toList().isEmpty()) {
            MethodRouter mr = new MethodRouter(jMethod.getName(),
                    formatMappedPath(getPathFromAnnotation(jMethod.getAnnotations())));
            methodRouters.add(mr);
        }
    });
});
```

```yaml
# options.yml 关键项
appClassPath: ../../java-sec-code/target/classes
analyses:
  extractApi: ;
```

```text
gradle fatJar
java -cp Tai-e/build/tai-e-all-0.5.1-SNAPSHOT.jar pascal.taie.Main --options-file=options.yml
# extractApi starts ...
# /sqli/jdbc/vuln
# /cors/vuln/origin
# /ssrf/urlConnection/vuln
```

# 变体与关联

- **分析类型选择**：类级注解可用 ClassAnalysis；只需方法级注解可用 MethodAnalysis；需要跨类汇总（API 清单、source 列表）用 ProgramAnalysis。
- **与 ASM 方案对比**：ASM 直接扫 `@RequestMapping` 不需要构建 Tai-e，但拿不到 Tai-e 的类层次/注解模型；本方案还可继续把提取结果作为 taint 分析的入口/source。
- **关联**：Tai-e 污点分析工程化 [[code-analysis-sast-taie-java-taint-audit-toolchain]]；Servlet 容器入口注入 [[code-analysis-sast-taie-servlet-container-entrypoint-taint]]；MyBatis sink 注入 [[code-analysis-sast-taie-mybatis-dollar-sink-inject-taintconfig]]；Tabby/Neo4j 路由-调用链方案 [[code-analysis-sast-tabby-neo4j-controller-sink-callchain]]。
- **限制**：注解 path 的多值、类级与方法级路径拼接、`@RequestMapping` 之外的 `@Path`/`web.xml` 需要分别处理；动态注册的路由（运行时 `RequestMappingHandlerMapping.registerMapping`）静态分析看不到。

# 检测与防御

- **审计方**：把提取出的 API 清单与鉴权注解/拦截器配置对照，筛出匿名可访问的敏感接口；将清单作为污点分析的 source 输入。
- **开发方**：路由与鉴权集中声明，避免依赖隐式/动态注册接口；对内部 API 做文档与资产登记。
- **误报控制**：注解提取只是清单，是否可达/是否鉴权需结合调用链与配置确认。

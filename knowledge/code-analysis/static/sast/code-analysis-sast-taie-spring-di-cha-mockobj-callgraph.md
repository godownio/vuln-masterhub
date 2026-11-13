---
id: code-analysis-sast-taie-spring-di-cha-mockobj-callgraph
title: Tai-e 指针分析补全 Spring 控制反转（CHA 启发式）：onPhaseFinish 给空指向集的 invokeinterface 接收者注入实现类 MockObj
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: taie-spring-di-cha-mockobj-callgraph
aliases:
- Tai-e 太阿 控制反转
- DependencyInjectionHandler
- 依赖注入 MockObj
- getMockObj DEPENDENCY_INJECTION
- Spring IoC 指针分析
- CHA 补全调用图
- invokeinterface 指向集为空
tags:
- java
- sast
- tai-e
- pointer-analysis
- taint-analysis
- spring
- dependency-injection
- call-graph
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V503
  verified_at: '2026-11-11T02:51:40+08:00'
  notes: 已对照原文与9/9图核对：onPhaseFinish 遍历 reachableMethods、跳过 java./sun./javax./com.sun.、invokevirtual/invokeinterface+InvokeInstanceExp、空指向集判断、接口取 getDirectImplementorsOf/类取自身+getDirectSubclassesOf、≤3 才 addPointsTo(getMockObj DEPENDENCY_INJECTION) 与图2/5/7/8一致；图2/3/4/6/9 的 TaintFlow（RestTemplate.exchange）与原文一致。未在本机编译运行 Tai-e 验证。
---

## 一句话结论

Tai-e 的指针分析默认按 `new` 语句建立堆抽象（Allocation-Site）来解析 `invokevirtual`/`invokeinterface`，但 Spring 依赖注入的对象不来自应用代码里的 `new`，接收者变量的指向集为空、调用图断链；写一个 `Plugin` 在 `onPhaseFinish`（工作队列排空、其余分析已完成）遍历可达方法的调用语句，对“`invokevirtual`/`invokeinterface` 且接收者 Var 指向集为空”的调用点，按接收者声明类型取直接实现类（接口）或自身+直接子类（类），候选数 ≤3 时用 `getMockObj("DEPENDENCY_INJECTION", 类名, 类型)` 注入指向集，即可让 `resolveCallee→dispatch` 解析到具体实现类，使污点分析能穿过 `@Resource` 注入的 `HttpService` 一路到达 `RestTemplate.exchange` 等 sink。

## 原理

- **指针分析如何解析调用**：Tai-e 先对 `New` 语句做堆抽象（`new A()` 对应 `NewObj{<New: ... new A>}`），再传播 Assign/Store/Load；处理 `invokevirtual`/`invokeinterface` 时，`CallGraphs.resolveCallee(type, callSite)` 调用类层次 `dispatch`/`lookupMethod`（先查类及其超类，再查超接口）得到具体方法。`pts`（接收者指向集）为空或没有具体对象时，解析不到 callee，调用边不存在。
- **控制反转为什么断链**：`@Configuration @Bean`、`@Service` + `@Resource/@Autowired/@Inject`、XML `<bean>` 等方式由 Spring 容器实例化对象；业务方法里只有 `service.action()` 这样的接口调用，没有 `new Impl()`。静态分析看不到容器行为，`service` 的指向集为空，`HttpService.RequestHttpBanRedirects` 这类调用不会被解析到 `HttpServiceImpl`，后续 `RestTemplate.exchange` 也不会进入污点图。
- **MockObj 注入**：`solver.getHeapModel().getMockObj(descriptor, alloc, type)` 可人为构造一个“类型为 type”的抽象对象；把它 `addPointsTo` 到接收者变量（`getCSVar(context, var)`）的指向集，等价于告诉分析器“这个变量可能指向该类型对象”。此后 `processCall` 遍历 pts 时即可解析出实现类方法。
- **CHA 候选生成**：对 `invoke.isInterface()`，候选为声明类型的 `getDirectImplementorsOf`；对虚调用（类类型），候选为自身 + `getDirectSubclassesOf`。只统计“指向集为空”的接收者，避免覆盖已有精确信息；只处理非 JDK 包（跳过 `java.`/`sun.`/`javax.`/`com.sun.`）减少噪声；候选超过 3 个时放弃，避免把过多实现类注入导致调用图爆炸和误报。
- **为什么放在 `onPhaseFinish`**：`DefaultSolver.analyze()` 在 worklist 排空后调用 `plugin.onPhaseFinish()`，此时普通指针传播已完成，接收者指向集是否为空最能反映“是否由容器注入”；在此处补点后再由框架继续传播/解析（文章在 `onPhaseFinish` 中一次性完成并设置 `isCalled` 防止重复）。
- **效果**：对 java-sec-code 的 SSRF 控制器，注入后控制台显示 `$r4 org.joychou.service.HttpService [org.joychou.impl.HttpServiceImpl]`，污点分析产出 `RestTemplateUrl → HttpServiceImpl.RequestHttp → RestTemplate.exchange` 与 `RestTemplateUrlBanRedirects → ... → exchange` 的 TaintFlow；同一机制也可让 SQL 注入等其它经接口注入的调用链进入分析。
- **局限**：CHA 是保守近似，一个接口有多个实现类时无法确定实际注入的是哪个；候选 >3 直接跳过会漏报；mock 对象不携带真实字段/构造信息；需要在编译期把插件加进 Tai-e 源码（文章将 `DependencyInjectionHandler.java` 放入 `pascal.taie.analysis.pta.plugin.taint` 并重新打包）。

## 触发条件

- 使用 Tai-e（文章基于 0.5.1-SNAPSHOT）对 Spring Boot/Spring 应用做指针分析 + 污点分析。
- 目标代码通过 `@Resource`/`@Autowired`/`@Inject` 或 XML 注入接口类型依赖，调用点接收者没有 `new` 来源。
- 能修改 Tai-e 源码/插件并重新编译，或在自定义插件机制中注册该 Plugin。
- 已在 `taint-config.yml` 配置 source/sink（如 `RestTemplate#exchange` 作为 SSRF sink）。
- 仅用于授权代码审计与安全评估。

## 利用步骤

1. 将 Tai-e 源码中的 `pascal.taie.analysis.pta.plugin.taint.DependencyInjectionHandler` 加入工程（或写成独立 Plugin 并注册）。
2. 在 `onPhaseFinish` 中遍历 `solver.getCallGraph().reachableMethods()`，跳过 JDK 包方法。
3. 对每条 `Invoke`：只保留 `isVirtual() || isInterface()` 且 `getRValue() instanceof InvokeInstanceExp` 的语句，取 `base` 变量与上下文。
4. 若该变量的 `getPointsToSet()` 非空则跳过；否则按接口/类生成候选实现类集合。
5. 候选数 ≤3 时，对每个候选 `getHeapModel().getMockObj(() -> "DEPENDENCY_INJECTION", name, type)` 并 `addPointsTo` 到该变量。
6. 重新编译 Tai-e，用 `java -cp tai-e-all.jar pascal.taie.Main --options-file=options.yml` 运行；检查输出中的 pointer/taint 结果与调用图。
7. 人工复核 TaintFlow，确认注入实现类与真实 Spring 配置一致。

## PoC

文章插件核心代码（整理）：

```java
public class DependencyInjectionHandler implements Plugin {
    private Solver solver;
    private boolean isCalled = false;

    @Override public void setSolver(Solver solver) { this.solver = solver; }

    @Override public void onPhaseFinish() {
        if (isCalled) return;
        isCalled = true;
        solver.getCallGraph().reachableMethods().forEach(csMethod -> {
            if (csMethod.getMethod().getDeclaringClass().getName()
                    .matches("^(java\\.|sun\\.|javax\\.|com\\.sun\\.).+$")) return;
            csMethod.getMethod().getIR().getStmts().forEach(stmt -> {
                if (stmt instanceof Invoke invoke &&
                        (invoke.isVirtual() || invoke.isInterface()) &&
                        invoke.getRValue() instanceof InvokeInstanceExp exp) {
                    Var var = exp.getBase();
                    Context context = csMethod.getContext();
                    if (!solver.getCSManager().getCSVar(context, var).getPointsToSet().isEmpty()) return;
                    JClass jClass = World.get().getClassHierarchy().getClass(var.getType().getName());
                    Collection<JClass> implementors = new ArrayList<>();
                    if (invoke.isInterface())
                        implementors.addAll(World.get().getClassHierarchy().getDirectImplementorsOf(jClass));
                    else {
                        implementors.add(jClass);
                        implementors.addAll(World.get().getClassHierarchy().getDirectSubclassesOf(jClass));
                    }
                    if (implementors.size() <= 3)
                        implementors.forEach(impl -> solver.addPointsTo(
                            solver.getCSManager().getCSVar(context, var),
                            solver.getHeapModel().getMockObj(() -> "DEPENDENCY_INJECTION",
                                impl.getName(), impl.getType())));
                }
            });
        });
    }
}
```

运行命令（原文）：

```bash
java -cp ~/Downloads/Tai-e/build/tai-e-all-0.5.1-SNAPSHOT.jar pascal.taie.Main --options-file=options.yml
```

说明：以上为文章代码的最小整理，未在本机编译运行；原实验对 java-sec-code 样例检出 SSRF 污点流。

## 变体与关联

- **精确变体**：不按 CHA 粗暴注入，而是解析 `@Resource/@Autowired/@Inject` 注入点与 `@Service/@Component` 实现类，在 `LoadField` 返回值上精确补点，见 [[code-analysis-sast-taie-spring-annotation-injection-loadfield-modeling]]。
- **入口注入**：Spring Controller 方法同样不在 `main` 可达图中，需要 `solver.addEntryPoint`，见 [[code-analysis-sast-taie-java-taint-audit-toolchain]] 与 [[code-analysis-sast-taie-servlet-container-entrypoint-taint]]。
- **Sink/source 配置**：MyBatis SQL sink 的建模见 [[code-analysis-sast-taie-mybatis-dollar-sink-inject-taintconfig]]、[[code-analysis-sast-taie-mybatis-abstract-mapper-sink-analysis]]、[[code-analysis-sast-taie-mybatis-field-taint-propagation]]。
- **边界**：多实现类接口、候选 >3、构造/字段依赖值、Spring 的 `@Qualifier`/profile 条件装配都会影响准确性；该法只补调用图，不模拟容器生命周期。

## 审计与防御

- **审计用法**：该插件把“容器注入导致调用图缺失”的盲区补上，适合审计大量使用接口 + `@Resource` 的 Spring 业务代码；对输出的 TaintFlow 仍需人工确认注入实现类是否与运行时配置一致。
- **误报/漏报**：CHA 注入会让一个接口的所有实现类都进入调用图，可能产生不存在的调用路径（误报）；多实现类或候选过滤会漏掉真实实现（漏报）。可结合注解/XML 配置做精确化。
- **对被测系统**：减少不必要的接口注入、用构造器注入并显式声明实现，有助于静态分析精度；敏感 sink（`RestTemplate`、JDBC、命令执行）应加统一封装与白名单，便于规则化检测。

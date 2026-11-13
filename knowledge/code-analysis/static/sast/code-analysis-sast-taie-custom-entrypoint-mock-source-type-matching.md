---
id: code-analysis-sast-taie-custom-entrypoint-mock-source-type-matching
title: Tai-e 手工入口点分析 JavaWeb 方法：mock 参数必须是形参接口的实现类、source 方法必须在具体类中声明或重写
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: taie-custom-entrypoint-mock-source-type-matching
aliases:
- Tai-e 添加入口点
- EntryPointHandler 自定义入口
- SpecifiedParamProvider mock 参数
- ServletRequestWrapper 找不到 source
- 接口参数类型匹配
tags:
- taie
- java
- sast
- taint-analysis
- pointer-analysis
- entry-point
- mock-object
- servlet
- code-audit
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V616
  verified_at: '2026-11-12T20:56:52+08:00'
  notes: 已通读原文并核对 2 张图片（均为 Tai-e Plugin 接口生命周期方法列表 setSolver/onStart/onFinish/onNewPointsToSet/onNewCallEdge/onNewMethod/onNewCSMethod/onUnresolvedCall，与卡片原理一致）。技术点核对：Tai-e 默认 main 入口/无入口指针分析直接结束、Plugin onStart 用 EntryPoint(JMethod, ParamProvider) 注册 service() 入口、DeclaredParamProvider 对接口形参造不出对象需 SpecifiedParamProvider+getMockObj、mock 类型 ServletRequestWrapper 失败而 HttpServletRequestWrapper/PageRequest 成功（实现类或实现类子类规则）、source 声明类 ServletRequest 接口无流/ServletRequestWrapper 重写有流/HttpServletRequest 与 HttpServletRequestWrapper 无流（非接口且声明或重写规则）、options.yml pta plugins 配置、25 条 TaintFlow 与 TFGDumper 输出，均与原文一致，PoC 与原文 TomcatEntry 代码结构一致。dedup 为 append_scenario、likely_duplicate 既有 verified 卡 code-analysis-sast-taie-servlet-container-entrypoint-taint；核对 worker 拆分理由成立：既有卡为 @WebServlet 扫描+doGet/doPost+Tomcat RequestFacade/ResponseFacade+ParamSourcePoint/transfer 路线，本卡为任意手工 service() 入口+mock 类型实现类规则+call 型 source 声明类规则，触发条件、PoC 与知识增量不同，属关联而非重复；dup-scan 无涉及 pair。原文未给受影响版本（仅 soot-4.4.1/Tai-e master），不设 affected_versions。未验证点：未实际运行
    Tai-e 复现。原文'模拟参数对象是接口的实现类或实现类子类'的结论仅基于 ServletRequestWrapper/HttpServletRequestWrapper/PageRequest 三例实测，卡片已按实测范围表述。
---

## 一句话结论

Tai-e 指针分析默认只从 `main` 出发，分析 JavaWeb 的非 main 方法（如 Servlet 的 `service()`）必须在 Plugin 的 `onStart()` 里用 `solver.addEntryPoint(new EntryPoint(jMethod, paramProvider))` 手工注册入口；其中接口形参只能用 `SpecifiedParamProvider` + `heapModel.getMockObj` 造出"形参接口的实现类（或实现类子类）"的 mock 对象，且 taint-config 里 `kind: call` 的 source 方法必须落在**非接口、且自己声明或重写了该方法**的类上，否则 Source nodes 为空、一条污点流都出不来。

## 原理

- **为什么必须手工加入口**：Tai-e 的 `PointerAnalysis.runAnalysis()` 创建 `DefaultSolver` 并加载内置插件组（`AnalysisTimer`、`EntryPointHandler`、`ClassInitializer`、`ThreadHandler`、`NativeModeller`、`ExceptionAnalysis`），随后 `DefaultSolver.solve()` 执行 `initialize()` + `analyze()`，从求解器登记的 EntryPoint 出发做指针分析与调用图构建。`EntryPointHandler.onStart()` 只做两件事：取 `World.get().getMainMethod()` 注册 main；若配置了 `implicit-entries` 再注册 JVM 隐式入口。JavaWeb 方法由容器运行时调用，静态代码里没有从 main 到 Servlet `service()/doGet()` 的调用边，不注册为入口这些方法根本不进入分析范围，只停留在 Soot 生成 Jimple 三地址码的阶段。
- **入口点数据结构**：`EntryPoint` 是 `record (JMethod method, ParamProvider paramProvider)`，参数对象由 ParamProvider 提供，指针分析把入口参数当作可达对象继续传播。
- **三种 ParamProvider 的边界**：`EmptyParamProvider` 用于无参方法；`DeclaredParamProvider` 按声明类型造对象，非静态方法会造 this 对象，但**参数声明类型若是抽象类/接口则造不出对象**——Servlet 的 `HttpServletRequest/HttpServletResponse` 参数正属此类，所以必须换 `SpecifiedParamProvider` 手工指定参数对象类型。
- **mock 参数类型规则**：用 `heapModel.getMockObj(Descriptor.ENTRY_DESC, "MethodParam{0}", <类型>, jMethod)` 造对象后，污点方法调用 `getParameter()` 要能解析到该对象类型上。本文实测：形参声明为 `HttpServletRequest` 时，指定 mock 类型为 `javax.servlet.ServletRequestWrapper` 失败（该类只实现 `ServletRequest` 接口，与 `HttpServletRequest` 无继承关系，`getParameter` 的调用点解析不到 source 方法）；改为 `javax.servlet.http.HttpServletRequestWrapper`（继承 ServletRequestWrapper 且实现 HttpServletRequest）或 `PageRequest`（HttpServletRequestWrapper 的子类）后即得到 25 条 TaintFlow。结论：**mock 对象类型必须是入口方法形参接口的实现类，或实现类的子类**。
- **source 方法声明类规则**：`kind: call` 的 source 按方法签名在调用图上匹配实际被调用的方法。本文实测 `getParameter(String)`：top 接口 `ServletRequest` 声明了它 → 无 source；实现类 `ServletRequestWrapper` 重写了它 → 有 source；接口 `HttpServletRequest` 未重声明 → 无 source；`HttpServletRequestWrapper` 未重写 → 无 source。结论：**source 配置的方法所在类不能是接口，且必须自己声明或重写了该方法**，污点才能挂到解析出的调用点上。
- **为什么成立**：Tai-e 的 source 匹配发生在指针分析解析出的具体被调方法上，接口声明既不承载方法体也不对应运行时接收者类型，mock 对象类型与形参接口无实现关系时指针集里也不会出现该接口的实例，两种情况都导致 source 点无法与调用点对齐。

## 触发条件

- 用 Tai-e（soot 前端 + 指针分析 + taint 插件）审计 JavaWeb/封闭 jar 系统，入口方法不是 `main`（Servlet `service()`、自定义分派方法等）；
- 入口方法形参是 `javax.servlet` 等接口类型，默认 `DeclaredParamProvider` 造不出参数对象；
- 能编写并激活自定义 Plugin（`analyses: pta: cs:ci;plugins:[自定义插件类]`），可修改 `options.yml` 的 appClassPath 与 source/sink 配置；
- 已接受静态分析结果仍需人工核验。

## 利用步骤

1. 编写实现 `Plugin` 接口的入口插件（参考 Tai-e 自带测试类 `CustomEntryPointPlugin`），在 `setSolver()` 里保存 `solver/hierarchy/typeSystem/heapModel`，在 `onStart()` 中 `hierarchy.getClass("<目标类名>")` 取类、`clz.getDeclaredMethod("<方法名>")` 取入口方法。
2. 为 this 与各参数用 `heapModel.getMockObj(Descriptor.ENTRY_DESC, "MethodParam{this|i}", <具体类型>, jMethod)` 造 mock 对象；接口形参的类型选该接口的实现类（如 `HttpServletRequest` → `HttpServletRequestWrapper` 或其子类），不能选只实现父接口的兄弟类。
3. 用 `SpecifiedParamProvider.Builder(jMethod).addThisObj(thisObj).addParamObj(0, p0)...setDelegate(new DeclaredParamProvider(jMethod, heapModel)).build()` 组装参数，再 `solver.addEntryPoint(new EntryPoint(jMethod, provider))`。
4. 在 `options.yml` 里追加 `appClassPath`（servlet-api、业务 jar 等）并设置 `analyses: pta: cs:ci;plugins:[<插件全限定类名>]`，运行后确认日志中出现目标方法并完成指针分析。
5. 配置 taint-config 的 source：`- { kind: call, method: "<实现类: 方法签名>", index: result }`，方法所在类必须是声明/重写了该方法的非接口类；先打印入口参数对象确认 mock 类型正确，再看 `Detected N taint flow(s)` 与 TFGDumper 的 Source/Sink nodes 是否非空。
6. 若 Source nodes 仍为空，按两条规则排查：mock 类型与形参接口是否有实现关系、source 方法声明类是否声明/重写了该方法；用 `dot -Tsvg` 转换 taint-flow-graph.dot 人工核验链路。

## PoC

```java
// 自定义入口插件骨架：把某个 Service 类的方法注册为入口
public class TomcatEntry implements Plugin {
    private Solver solver;
    private ClassHierarchy hierarchy;
    private HeapModel heapModel;

    @Override
    public void setSolver(Solver solver) {
        this.solver = solver;
        this.hierarchy = solver.getHierarchy();
        this.heapModel = solver.getHeapModel();
    }

    @Override
    public void onStart() {
        JClass clz = hierarchy.getClass("com.example.DecryptApplicationService2");
        JMethod m = clz.getDeclaredMethod("service");
        // 关键：mock 类型取形参接口的实现类，而非任意兄弟接口实现类
        JClass reqImpl = hierarchy.getClass("javax.servlet.http.HttpServletRequestWrapper");
        JClass respImpl = hierarchy.getClass("javax.servlet.http.HttpServletResponseWrapper");

        SpecifiedParamProvider.Builder b = new SpecifiedParamProvider.Builder(m);
        b.addThisObj(heapModel.getMockObj(Descriptor.ENTRY_DESC, "MethodParam{this}", clz.getType(), m))
         .addParamObj(0, heapModel.getMockObj(Descriptor.ENTRY_DESC, "MethodParam{0}", reqImpl.getType(), m))
         .addParamObj(1, heapModel.getMockObj(Descriptor.ENTRY_DESC, "MethodParam{1}", respImpl.getType(), m))
         .setDelegate(new DeclaredParamProvider(m, heapModel));
        solver.addEntryPoint(new EntryPoint(m, b.build()));
    }
}
```

```yaml
# options.yml 节选
appClassPath:
  - java-benchmarks/general/javax.servlet-api-4.0.0.jar
  - java-benchmarks/target/WEB-INF/lib/JSPSmart.jar
analyses:
  pta: cs:ci;plugins:[pascal.taie.analysis.pta.plugin.pumpkin.TomcatEntry];
```

```yaml
# taint-config 节选：source 必须指向声明/重写了该方法的实现类
sources:
  - { kind: call, method: "<javax.servlet.ServletRequestWrapper: java.lang.String getParameter(java.lang.String)>", index: result }
```

## 变体与关联

- 变体：无参入口方法直接用 `EmptyParamProvider.get()`；参数为可实例化具体类时用 `DeclaredParamProvider` 即可，无需 mock。
- 变体：Servlet 注解扫描版入口（遍历 `@WebServlet` 类、用容器 facade 类 mock）见 [[code-analysis-sast-taie-servlet-container-entrypoint-taint]]；本文适用于任意手工指定的非 main 方法。
- 变体：目标为封闭 jar 且无 main 时，WorldBuilder 阶段能执行，但指针分析会因缺入口直接结束，必须按本文方式补入口。
- 关联：[[code-analysis-sast-taie-java-taint-audit-toolchain]]（整体工程化与 only-app 断链补全）、[[code-analysis-sast-taie-custom-program-analysis-api-extraction]]（Tai-e 插件 API 抽取）。

## 检测与防御

- 审计方视角：手工入口点让 Tai-e 覆盖任意 Web 分派方法，但 mock 类型选错、source 声明类选错都会**静默零输出**，看起来像"没有漏洞"；必须先用已知有污点的样例验证 Source nodes 非空，再信任扫描结果。
- 开发方视角：请求参数进入文件/命令/表达式等危险 sink 前做白名单与类型校验，减少可被静态污点链串起的路径。
- 检测：把入口注册与 source 方法选择纳入分析脚本的固定回归用例，输出 Source/Sink 节点数量作为分析是否生效的健康检查。

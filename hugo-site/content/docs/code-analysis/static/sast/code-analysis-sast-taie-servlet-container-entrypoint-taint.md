---
id: code-analysis-sast-taie-servlet-container-entrypoint-taint
title: Tai-e 分析 Servlet 容器应用：@WebServlet 入口注入 + RequestFacade/ResponseFacade mock + doX 请求参数 source
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: taie-servlet-container-entrypoint-taint
tags:
- taie
- java
- sast
- servlet
- tomcat
- taint-analysis
- entry-point
- pointer-analysis
- mock-object
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V432
  verified_at: '2026-11-09T18:48:07+08:00'
  notes: 已对照原文核对：@WebServlet 入口扫描、RequestFacade/ResponseFacade mock、onNewCSMethod param0 source、getParameter transfer、exec sink 与原文代码及两张截图（RequestFacade@7401 调试视图、doPost→doSomething→exec TaintFlow）一致；未实际运行 Tai-e 验证插件 API 细节。版本原文未给，已 clear。dup-scan 早于建卡未覆盖本卡，dedup 显示与 tae-java-taint-audit-toolchain/mybatis 卡仅 related，非同链。
url: /docs/code-analysis/static/sast/code-analysis-sast-taie-servlet-container-entrypoint-taint/
draft: false
kb_aliases:
- Tai-e Servlet 适配
- '@WebServlet 入口点'
- RequestFacade mock 对象
- doGet 参数污点源
- Tomcat 白盒污点分析
---

## 一句话结论

Tai-e 默认以 `main` 为入口，分析以 Servlet 编程方式部署在 Tomcat 的 Java Web 应用时，需要写 Plugin 在 `onStart` 扫描 `@WebServlet` 类并把 `doGet/doPost/doPut/doDelete` 注册为入口点，用容器真实实现类 `RequestFacade`/`ResponseFacade` 的 mock 对象代替无法被堆模型直接模拟的 `javax.servlet` 接口参数，再在 `onNewCSMethod` 中把 do 方法第 0 个参数（request 对象）标成污点 source，配合 `getParameter` 的 base→result transfer 与 `Runtime.exec` 的 index 0 sink，即可得到从 HTTP 请求参数到命令执行的污点流。

## 原理

- **为什么要手工添加入口**：Tai-e 的指针分析默认从 `main` 方法出发构建调用图。Servlet 应用的业务方法由 Tomcat 容器在运行时按 HTTP 请求调用，静态代码里不存在从 `main` 到 `doGet/doPost` 的调用边，不补入口点这些方法根本不会进入分析范围。
- **入口如何选**：`@WebServlet` 注解声明 servlet 类及其 URL 路径，容器按请求方法分派到 `doGet/doPost/doPut/doDelete`。因此把带注解类的这些 do 方法注册为入口点，等价于把容器分派逻辑建模进分析。
- **接口参数怎么造对象**：入口点的参数需要 param provider 提供指向对象。`javax.servlet.http.HttpServletRequest/Response` 是接口，Tai-e 的堆模拟不能直接为接口类型造对象；而 Tomcat 实际传给 servlet 的实例类型是 `org.apache.catalina.connector.RequestFacade` 和 `org.apache.catalina.connector.ResponseFacade`，所以用 `heapModel.getMockObj` 以这两个具体类的类型构造 mock 对象，再通过 `SpecifiedParamProvider` 绑定到入口方法的 this 与第 0/1 个参数。
- **source 怎么给**：入口参数本身不会自动带污点，需要 SourcePoint。重写 `onNewCSMethod`，对每个 do 方法取 `IR` 的第 0 个参数变量（request），用 `ParamSourcePoint(IndexRef(VAR, 0))` 生成 taint，再 `addVarPointsTo(context, param, taint)` 把污点绑到该变量上；此后对 request 对象的方法调用即可用 transfer 继续传播污点。
- **传播与汇点**：`RequestFacade.getParameter(String)` 配置 `from: base, to: result`，污点从接收者流向返回值；`Runtime.exec(String)` 以 `index: 0` 标为命令执行 sink。Tai-e 在指针分析调用图上做污点传播，以上模型齐备后即可产出 `doPost → 业务方法 → Runtime.exec` 的 TaintFlow（原文截图中可见完整流图）。
- **已知局限**：上下文敏感分析下，Map 容器中的数据传播（如 `getParameterMap`）无法被精确识别，会出现污点中断；原文称已初步解决但不完善，必要时退回上下文不敏感分析或手工补 transfer。

## 触发条件

- 目标是采用 Servlet 编程（`@WebServlet` 注解声明；`web.xml` 声明方式未覆盖）的 Java Web 应用，部署容器为 Tomcat 或参数 mock 类可对应的同族容器；
- 能拿到应用的 class/jar 作为 application classes，并在本地运行 Tai-e 及其污点分析插件；
- 分析者可以编写 Plugin（入口点）与 taint 插件（source），并维护 `taint-config` 的 transfer/sink；
- 上下文敏感分析下若业务使用 Map 传递参数，需接受可能的漏报并按上下文不敏感模式复跑。

## 利用步骤

1. 遍历 `solver.getHierarchy().applicationClasses()`，筛出带 `javax.servlet.annotation.WebServlet` 注解的类，再筛出名为 `doGet/doPost/doPut/doDelete` 的声明方法。
2. 取 do 方法的参数类型（0 为 request、1 为 response），用 `org.apache.catalina.connector.RequestFacade`/`ResponseFacade` 的 JClass 作为 mock 对象类型，通过 `heapModel.getMockObj(ENTRY_DESC, "<参数类型>", facadeClass.getType(), jMethod)` 分别构造 mock request、mock response，并为 servlet 实例本身造一个 this mock 对象。
3. 用 `SpecifiedParamProvider.Builder(jMethod).addThisObj(mockServlet).addParamObj(0, mockRequest).addParamObj(1, mockResponse).build()` 组装参数，再 `solver.addEntryPoint(new EntryPoint(jMethod, provider))`。
4. 重写 `onNewCSMethod`：方法名匹配 do 方法时，取 `method.getIR().getParam(0)`，用 `new ParamSourcePoint(method, new IndexRef(IndexRef.Kind.VAR, 0, null))` 生成 taint，`solver.addVarPointsTo(context, param, taint)` 绑定污点。
5. 在 taint-config 中加 `RequestFacade.getParameter(String)` 的 base→result transfer 和 `Runtime.exec(String)` 的 index 0 sink，运行 Tai-e，检查输出 TaintFlow 是否覆盖预期链路。
6. `getParameterValues/getParameterMap/headers/cookies` 等复杂返回值的 transfer、Filter/Listener 入口、`web.xml` 声明解析与其它容器适配属于同类工作的延伸，需要分别补建模。

## PoC

```yaml
# taint-config 节选：请求参数读取传播 + 命令执行汇点
transfers:
- { method: "<org.apache.catalina.connector.RequestFacade: java.lang.String getParameter(java.lang.String)>", from: base, to: result }
sinks:
- { vuln: "Remote Code Execution", level: 1, method: "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>", index: 0 }
```

```java
// 入口点插件（按原文代码结构精简，API 细节依 Tai-e 版本调整）
public void onStart() {
    JClass reqFacade = World.get().getClassHierarchy().getClass("org.apache.catalina.connector.RequestFacade");
    JClass respFacade = World.get().getClassHierarchy().getClass("org.apache.catalina.connector.ResponseFacade");
    for (JClass c : solver.getHierarchy().applicationClasses().toList()) {
        boolean isServlet = c.getAnnotations().stream()
            .anyMatch(a -> a.getType().matches("javax.servlet.annotation.WebServlet"));
        if (!isServlet) continue;
        for (JMethod m : c.getDeclaredMethods()) {
            if (!m.getName().matches("\\b(doGet|doPost|doPut|doDelete)\\b")) continue;
            Obj req  = solver.getHeapModel().getMockObj(ENTRY_DESC, "<" + m.getParamType(0) + ">", reqFacade.getType(), m);
            Obj resp = solver.getHeapModel().getMockObj(ENTRY_DESC, "<" + m.getParamType(1) + ">", respFacade.getType(), m);
            Obj self = solver.getHeapModel().getMockObj(ENTRY_DESC, "<http-controller>", c.getType());
            solver.addEntryPoint(new EntryPoint(m, new SpecifiedParamProvider.Builder(m)
                .addThisObj(self).addParamObj(0, req).addParamObj(1, resp).build()));
        }
    }
}

// source 插件：do 方法第 0 个参数（request）标为污点
public void onNewCSMethod(CSMethod csMethod) {
    JMethod m = csMethod.getMethod();
    if (!m.getName().matches("\\b(doGet|doPost|doPut|doDelete)\\b")) return;
    Var p0 = m.getIR().getParam(0);
    SourcePoint sp = new ParamSourcePoint(m, new IndexRef(IndexRef.Kind.VAR, 0, null));
    solver.addVarPointsTo(csMethod.getContext(), p0, manager.makeTaint(sp, p0.getType()));
}
```

## 变体与关联

- 变体：`web.xml` 的 `<servlet>`/`<servlet-mapping>` 声明方式需改为解析 `web.xml` 获取入口（原文列为后续内容）；Filter/Listener 也需单独建模。
- 变体：换用 Jetty/Undertow 等容器时，mock 对象要换成该容器实际传给 servlet 的实现类（如对应的 Request/Response 实现）。
- 变体：`getParameterValues` 返回数组、`getParameterMap` 返回 Map、`getHeaders/getCookies` 返回枚举，transfer 规则更复杂；Map 场景还受上下文敏感分析精度限制。
- 关联：[[code-analysis-sast-taie-java-taint-audit-toolchain]]（Tai-e 离线审计整体工程化、only-app 断链与入口注入通法）、[[code-analysis-sast-taie-mybatis-field-taint-propagation]]（transfer 补全思路）。

## 检测与防御

- 审计方视角：Servlet 注解入口建模能显著扩大 Tai-e 对传统 Tomcat 应用的覆盖；但 mock 仅覆盖注解声明、仅覆盖 do 方法，`web.xml`、Filter、Listener 与自定义 servlet 分派（如 `service()` 重写）仍是盲区，不能把“没报”当成“没有”。
- 开发方视角：避免请求参数未经校验直达命令执行/表达式/反射等危险 sink；对 `getParameter` 等外部输入统一做白名单和类型约束。
- 检测：静态分析结果仍是候选，需人工核验调用链可达性；对上下文敏感分析下的 Map 传播漏报，用不敏感模式或补充 transfer 交叉验证。

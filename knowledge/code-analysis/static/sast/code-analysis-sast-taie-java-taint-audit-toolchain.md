---
id: code-analysis-sast-taie-java-taint-audit-toolchain
title: Tai-e Java 白盒污点分析工程化：classpath 分离 + 路由 source 提取 + 入口注入 + only-app 断链补全
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: taie-java-taint-audit-toolchain
aliases:
- Tai-e 污点分析
- Java 白盒审计工具
- 离线 jar 漏洞扫描
- 入口注入 Plugin
- only-app 断链
- LibraryBridgePlugin
tags:
- taie
- java
- sast
- taint-analysis
- pointer-analysis
- callgraph
- code-audit
- jar
- offline
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V137
  verified_at: '2026-11-06T05:46:38+08:00'
  notes: 已对照原文与3张图核对：classpath 分离、ASM 路由 source、sink 预扫描与 index/base、EntryPointPlugin 注入、TaintFlow 快照、子 JVM 隔离、only-app 断链与 LibraryBridgePlugin/transfers、@Autowired 无解边界均与正文一致；图01 SARIF 分类型报告/20.874s、图02 23423 原始流→6257 主报告/suppressed 15083、图03 PTA 统计（152070 可达方法、723884 调用边、16.05s）与原文一致。Tai-e 0.5.4 为工具版本而非受影响组件版本，未设 affected_versions。未验证点：未在本机运行 Tai-e 或复现扫描结果。
---

## 一句话结论

Tai-e 的 taint 分析以 PTA 调用图 + 外部 `taint-config.yml` 的 source/sink/transfer 规则为核心；把它工程化成可带进客户内网的离线 Java 白盒审计工具，关键在 classpath 分离、从路由表生成 source、用 Plugin 注入 Controller 入口、桥接结果快照，以及补齐 `only-app` 造成的库侧断链。

## 原理

- Tai-e 的 taint 分析分两步：PTA 先构建调用图，再按 source/sink/transfer 规则在图上寻找从污染源到危险点的 `TaintFlow`。规则全部在外部 `taint-config.yml`，与业务代码解耦。
- Tai-e 默认只从 `main` 出发；Web 应用需要写 `Plugin`，在 `onStart()` 中 `solver.addEntryPoint(...)` 把 Controller 等方法注册为 PTA 入口。
- `--app-class-path` 放要分析的业务代码，`--class-path` 只放参与类型解析的依赖库；不加 `--input-classes all` 时 `applicationClasses()` 只含业务类，分析范围显著缩小。
- source 有两类：`kind: param`（入口方法第 i 个参数）和 `kind: call`（某方法调用返回值，如 `request.getParameter()` 的 `index: result`）。
- sink 用方法签名 + index 定义：有参 sink 写参数下标；零参接收者 sink（如 `ObjectInputStream.readObject()`）必须写 `base`，否则不生效；`Method.invoke` 标参数 1。
- `only-app:true` 跳过库方法体后，库方法返回值的 points-to 集合也为空，`Runtime.getRuntime().exec(cmd)` 这类链的接收者类型缺失、调用边建不出来，会静默漏报。需要 `LibraryBridgePlugin` 在 `onNewCallEdge` 给工厂方法返回值补合成对象，或用 `transfers` 显式续上污点。
- `SourcePoint`/`SinkPoint` 是 package-private，且分析结果跑完即清空；需在 taint 插件包内放桥接类，在 `onFinish()` 把 `TaintFlow` 转成可序列化快照（source/sink 签名、语句索引、行号）。

## 触发条件

- 目标为 Java Web 应用，能拿到业务 jar 与依赖 jar，且可在离线环境运行本地分析。
- 有 Tai-e（0.5.4+ 对依赖解析问题更稳）及可嵌入调用的 API；需要自定义入口插件与 taint 规则。
- 已维护 `rules.yaml`（漏洞类型、严重度、sink 列表、业务包名、手工 source），并接受静态候选仍需人工核验。
- 分析机内存有限，需要子 JVM 隔离与资源预算。

## 利用步骤

1. **分离 classpath**：扫描所有 jar，按包名推断业务包；业务 jar 进 `--app-class-path`，依赖进 `--class-path`。多业务包时在 `rules.yaml` 的 `scan_packages` 列出多个包名重跑。
2. **提取 source**：用 ASM 扫 `@RequestMapping`/`@Path`/`web.xml` 等生成路由表，每个入口方法参数生成 `param` source；`rules.yaml` 里的方法型 source 转成 `call` source。可按 `@AnonymousValidator`/`@IgnoreAuth` 等注解过滤，只保留未授权接口（`-m api --filter-annotation ...`）。
3. **翻译 sink 并预扫描**：把 `rules.yaml` 翻成 `taint-config.yml` 的 `sinks`；先用 ASM 扫目标字节码，只保留实际被引用的 sink，避免 `Cannot find sink method` 并减少干扰。为 `only-app` 下的库方法、接口方法、DTO getter 补 `transfers`。
4. **注入入口**：用 `pta=cs:ci;only-app:true;taint-config:/path/taint-config.yml;implicit-entries:true;plugins:[com.example.EntryPointPlugin,...]` 配置；插件 `onStart()` 中解析方法签名并 `addEntryPoint`，注入前过滤 abstract/native/phantom（无 IR 会炸 `getIR()`），按 `JMethod` 去重。
5. **跑分析并抓结果**：`Options.parse(args)` → `WorldBuilder.build(options)` → `new AnalysisManager(plan).execute()`；桥接类在 `onFinish()` 把 `TaintFlow` 快照序列化，后续过滤/打分/报告基于快照。
6. **进程隔离**：把 Tai-e 放独立子 JVM，设 `-Xmx`、超时强杀、`-XX:+ExitOnOutOfMemoryError`、OOM 时 heap dump 与 GC log，结果走 JSON 回传。
7. **补断链**：用已知有漏洞的项目验证覆盖度；对 `only-app` 漏掉的库工厂返回值（`Runtime.getRuntime`、`DriverManager.getConnection`、`DocumentBuilderFactory.newInstance`）在 `LibraryBridgePlugin.onNewCallEdge` 补合成对象；对库方法/接口/DTO getter 补 `transfers`，直到能报出已知漏洞。

## PoC

```yaml
# taint-config.yml（节选）
sources:
- method: "<com.example.RuleEngineController: ... runGroovyScript(...)>"
  kind: "param"
  index: 0
- method: "<javax.servlet.http.HttpServletRequest: java.lang.String getParameter(java.lang.String)>"
  kind: "call"
  index: "result"
transfers:
- method: "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>"
  from: "0"
  to: "base"
- method: "<org.springframework.web.multipart.MultipartFile: java.io.InputStream getInputStream()>"
  from: "base"
  to: "result"
- method: "<java.util.List: java.lang.Object get(int)>"
  from: "base"
  to: "result"
```

```java
public class EntryPointPlugin implements Plugin {
    public void onStart() {
        for (String sig : entrySignatures) {
            JMethod m = resolve(sig);
            if (m == null || m.isAbstract() || m.isNative() || m.getDeclaringClass().isPhantom()) {
                continue; // 无 IR 的方法注入会在 getIR() 上抛异常
            }
            solver.addEntryPoint(new EntryPoint(m, new DeclaredParamProvider(m, solver.getHeapModel())));
        }
    }
}
```

```text
# 嵌入式启动
Options options = Options.parse(args);
WorldBuilder wb = options.getWorldBuilderClass().getConstructor().newInstance();
wb.build(options);
new AnalysisManager(plan).execute();
```

## 变体与关联

- 变体：Soot 方案（速度慢、依赖解析易崩）→ Tai-e 0.5.4+；也可用 tabby+Neo4j 做调用图查询，或 CodeQL 做规则化污点分析。
- 变体：误报压制可按精确去重、fan-in 聚合、sink 强度、是否落在业务包内分层；示例 23423 条原始流最终 6257 条进主报告。
- 变体：结合 SCA，从依赖版本先排除不可利用的第三方漏洞，减少人工核验量。
- 关联：[[code-analysis-sast-tabby-neo4j-controller-sink-callchain]]、[[code-analysis-sast-codeql-custom-taint-steps]]、[[code-analysis-sast-codeql-active-threat-model-source-coverage]]。

## 检测与防御

- 审计方：用已知漏洞项目做覆盖度回归，维护 transfer 与 LibraryBridge 白名单；对 `@Autowired` 注入 bean 字段当前无法建模的边界要心里有数，必要时人工补查。
- 开发方：对 taint 链上的入口参数做白名单/类型校验，危险 sink 前做编码或参数化；减少动态执行（Groovy/反射/命令拼接）面。
- 检测：将扫描结果按 sink 类型拆分 SARIF/调用链文本，结合人工确认；关注 `only-app` 漏报的库侧链，避免把“没报”当成“没有”。

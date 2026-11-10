---
id: code-analysis-sast-codeql-deserialization-named-method-sink
title: 用 CodeQL 定位反序列化链：Serializable 类入口 → ClassInstanceExpr 定位调用方 → 按方法名匹配 exeCmd/deserialize 定义 sink，RemoteFlowSource 接 cookie 形成完整 path-problem
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-deserialization-entry-named-sink-taint
aliases:
- CodeQL 反序列化挖掘
- Serializable 入口点
- ClassInstanceExpr 定位
- 按方法名匹配 sink
- deserialize 参数作为 sink
- RemoteFlowSource 覆盖入口
- Shiro 反序列化 CodeQL
- TaintTracking 配置
tags:
- codeql
- sast
- java
- deserialization
- taint-tracking
- dataflow
- path-problem
- sink-definition
- source-definition
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-6
  verified_at: '2026-11-08T01:53:03+08:00'
  notes: 已对照原文核对；原文图示给出的 6 跳路径（getValue→base64→base64→decode→base64Decode→bytes）与卡内描述一致，各 ql 片段（TypeSerializable 查询、ClassInstanceExpr/hasQualifiedName、hasName(exeCmd) 反查、deser 谓词、RemoteFlowSource 配置）均与原文一致；未验证点：原文未解释默认传播步为何能穿过 base64Decode，卡内该段属合理补充推断，PoC 中 @id 与配置名去掉了原文的 shiro/Struts 模板痕迹（步骤中已说明应改名）。
---

## 一句话结论

在没有现成模型的小型 Java/CTF 代码库里找反序列化链，可以用三步“由尾到头”的 CodeQL 查询快速锁定：先用 `Class.getASupertype() instanceof TypeSerializable and cls.fromSource()` 列出所有可序列化入口类；再用 `ClassInstanceExpr` + `hasQualifiedName` 找出这个类在哪个 Controller 被实例化、它的输入从哪来（`cookie.getValue()`）；最后用一个“方法名叫 `deserialize` 就取第 0 个参数”的自定义谓词把 sink 定义出来，配合 `RemoteFlowSource` 作为 source 跑 `TaintTracking::Configuration` + `path-problem`，把 `cookie → base64Decode → deserialize(bytes)` 的完整链一次画出来。

## 原理

- **反序列化漏洞的入口就是“可序列化的类”**：Java 反序列化只有在 `ObjectInputStream.readObject()` 读到某个类的字节流时才会触发该类的 `readObject`/`readResolve` 等魔术方法，因此凡是 `implements Serializable`（`TypeSerializable`）的业务类都可能是 gadget 链的起点或多态类型。用
  ```ql
  import java
  from Class cls
  where cls.getASupertype() instanceof TypeSerializable and cls.fromSource()
  select cls
  ```
  就把“本仓库自带的、可被外部数据构造出来的类”一次性列出来，比逐个 grep `implements Serializable` 精确（不会命中第三方依赖里的类）。
- **定位这个类怎么被用**：`ClassInstanceExpr` 覆盖所有 `new X(...)` 表达式，`hasQualifiedName(pkg, name)` 精确匹配包名+类名，两者结合即可找到实例化位置：
  ```ql
  class FindUser extends RefType {
    FindUser() { this.hasQualifiedName("com.summersec.shiroctf.bean", "User") }
  }
  from ClassInstanceExpr clie
  where clie.getType() instanceof FindUser
  select clie
  ```
  在示例中结果落在 `IndexController`，说明该类在某个 Web 入口被使用，值得继续看它周围的输入来源。
- **反向找危险方法**：把已知的危险方法（这里是 `exeCmd`，从工具类 `Tools` 的 `exeCmd` 定义）当锚点，用 `MethodAccess.getMethod().hasName("exeCmd")` 反查所有调用点，就能看到“哪些类调用了这个 sink”。示例中两处调用都在 `LogHandler`，说明这条链的尾部在日志处理逻辑里。
- **定义 sink 的实用技巧：按方法名而非精确签名匹配**：小型项目里反序列化包装函数常是 `Tools.deserialize(byte[])` 这类薄封装，方法名固定但声明类型/参数可变。用
  ```ql
  predicate deser(Expr arg) {
    exists(MethodAccess des |
      des.getMethod().hasName("deserialize") and
      arg = des.getArgument(0)
    )
  }
  ```
  把“任何名为 `deserialize` 的调用的第 0 个实参”视为 sink。好处是跨包、跨封装都能命中；代价是可能误命中同名业务方法（需人工看 path 过滤）。
- **source 不必自己枚举**：`semmle.code.java.dataflow.FlowSources` 里的 `RemoteFlowSource` 已覆盖 Servlet 参数、请求头、Cookie 等远端输入。示例把 `cookie.getValue()` 作为污点源，正是因为它被框架建模为远端流源；这样配置里只需一句
  ```ql
  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
  ```
  就能覆盖所有 HTTP 入口，避免自己维护 source 清单漏项。
- **为什么能打通**：污点从 `cookie.getValue()` 出发，经 `Tools.base64Decode`（框架默认的“参数→返回值”传播步骤已覆盖常见调用），到达 `Tools.deserialize(bytes)` 的第 0 个实参，即 `deser(arg)` 命中的 sink。示例的查询结果给出 6 步路径：`getValue(...)` → `base64` → `base64` → `decode(...)` → `base64Decode(...)` → `bytes`，与源码 `Tools.base64Decode(cookie.getValue())` + `(User)Tools.deserialize(bytes)` 完全对应。
- **配置名称要改**：示例里 `this = "StrutsUnsafeDeserializationConfig"` 是从 Struts 模板复制后忘记改名的痕迹，不影响结果，但复用模板时应改成自己的名字，否则多个配置同时存在时会混淆排查。
- **限制**：这是“按名匹配 + 框架默认传播”的轻量做法，适合小代码库/CTF 快速定位；大型项目仍应使用精确签名 sink、补充自定义 summary（见关联卡），否则同名方法与不传播的 JDK 方法会造成漏报/误报。

## 触发条件

- 已用 CodeQL 创建了 Java 数据库（`codeql database create`），且目标代码在数据库里（`fromSource()` 能取到）。
- 目标是小到中型 Java 项目，或 CTF/靶场代码，方法命名有迹可循（如统一 `Tools.deserialize`）。
- 想先确认“是否存在从 HTTP 输入到反序列化的可行链”，而不是直接照搬官方查询。
- 有 VS Code CodeQL 插件或 `codeql query run` 可用于看 path-problem 结果。

## 利用步骤

1. **列可序列化类**：跑 `TypeSerializable` 查询，挑出本体业务类（示例 `com.summersec.shiroctf.bean.User`）。
2. **找使用点**：用 `ClassInstanceExpr` + `hasQualifiedName` 查该类在哪里 `new`，得到入口类（示例 `IndexController`）。
3. **读入口代码**：确认它的参数/请求来源，找出可疑的字节流处理（`cookie.getValue()`、`request.getParameter`、`getInputStream()`）与工具类调用（`base64Decode`、`deserialize`、`serialize`）。
4. **列工具类方法**：用 `Method.getName()` + `getDeclaringType().getPackage().getName()` 把工具类里的 `serialize`/`deserialize`/`base64Encode` 等方法列出来，读实现确认是否直接 `ObjectInputStream.readObject()`。
5. **反向找危险 sink**：用 `MethodAccess` + `hasName("exeCmd")`（或项目中实际的命令执行/反射方法）反查调用点，确认链尾所在类。
6. **定义 sink 谓词**：把 `deser(arg)` 写成“方法名为 `deserialize` 的第 0 个实参”。
7. **写污点配置**：`isSource` 用 `RemoteFlowSource`，`isSink` 用 `deser(arg)` 且 `sink.asExpr() = arg`；用 `TaintTracking::Configuration`（老 API）或 `TaintTracking::Global`（新 API，会自动加默认传播步）。
8. **跑 path-problem**：`@kind path-problem` + `DataFlow::PathGraph` + `hasFlowPath`，在 Path Explorer 里逐跳核对，确认每跳在源码里真实存在且没有被净化。
9. **人工复核边界**：检查 sink 的第 0 个参数是否真由外部字节流控制（不是本地常量）、反序列化类是否在 classpath（否则 gadget 不可用）、是否还有白名单/`ObjectInputFilter` 拦截。

## PoC

源码骨架查询（列出全部自研可序列化类）：

```ql
import java
from Class cls
where cls.getASupertype() instanceof TypeSerializable and cls.fromSource()
select cls
```

定位实例化点：

```ql
import java
class FindUser extends RefType {
  FindUser() { this.hasQualifiedName("com.summersec.shiroctf.bean", "User") }
}
from ClassInstanceExpr clie
where clie.getType() instanceof FindUser
select clie
```

按名反查危险方法调用：

```ql
import java
from MethodAccess call
where call.getMethod().hasName("exeCmd")
select call, "调用 exeCmd 方法"
```

完整污点查询（path-problem）：

```ql
/**
 * @name Unsafe deserialization by named method
 * @kind path-problem
 * @id java/unsafe-deserialization-named-method
 */
import java
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

predicate deser(Expr arg) {
  exists(MethodAccess des |
    des.getMethod().hasName("deserialize") and
    arg = des.getArgument(0)
  )
}

class UnsafeDeserializationConfig extends TaintTracking::Configuration {
  UnsafeDeserializationConfig() { this = "UnsafeDeserializationConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Expr arg | deser(arg) and sink.asExpr() = arg)
  }
}

from UnsafeDeserializationConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe deserialization", source.getNode(), "user input"
```

预期结果：一条 6 跳路径 `getValue(...)` → `base64` → `base64` → `decode(...)` → `base64Decode(...)` → `bytes`，sink 落在 `Tools.deserialize(bytes)` 的实参上。

无 PoC（不可执行）：以上为分析查询，不是攻击载荷；真实利用仍需构造 gadget 字节流。

## 变体与关联

- 变体：sink 换成 `ObjectInputStream.readObject()` 的直接调用、`XStream.fromXML`、`readObject` 的包装方法，或 `SnakeYAML.load`——思路相同，只换 `deser` 谓词里的方法名/声明类型。
- 变体：把 source 换成 `ActiveThreatModelSource` 可覆盖框架未建模的自定义入口（见 `code-analysis-sast-codeql-active-threat-model-source-coverage`）。
- 变体：新 API 用 `module Flow = TaintTracking::Global<Config>`；老 API 的 `TaintTracking::Configuration` 不会自动叠加默认传播步，链路若在库方法处断掉，需要自己补 `isAdditionalFlowStep`。
- 关联：`code-analysis-sast-codeql-custom-taint-steps`（默认传播缺失时用 `TaintPreservingCallable` 与 `dataExtensions` 补全，解决本卡“按名匹配”在不传播方法处断链的问题）。
- 关联：`code-analysis-sast-codeql-struts-ognl-taint-modeling`（同样是“自定义 source/sink + isAdditionalFlowStep + isBarrier”的模板，本卡是反序列化场景）。
- 关联：`code-analysis-sast-codeql-spring-missing-auth-annotation`、`code-analysis-sast-codeql-spring-multipartfile-upload-endpoints`（用 CodeQL 按注解/类型枚举入口的同类“先找入口再找 sink”方法）。
- 边界：按名字匹配 sink 在小项目里高效，在大项目里会引入同名方法噪声；示例配置名沿用了 Struts 模板名，复用时务必改掉。

## 检测与防御

- 检测（防守方/审计方视角）：CI 中固定跑“自研 Serializable 类 + 反序列化 sink”查询，作为新代码门禁；把 `readObject`/`deserialize`/`fromXML`/`load` 等方法列入 sink 白名单式建模。
- 检测：对所有 `ObjectInputStream.readObject()` 的调用检查是否有 `ObjectInputFilter`/类白名单；Spring/Shiro 等框架类库关注 `rememberMe`、`session` 反序列化点。
- 防御：不要对不可信字节流调用原生反序列化；用 JSON/Protobuf 等无 gadget 的格式，或启用 `ObjectInputFilter` 严格白名单（allow-list 类名、限制深度与数组长度）。
- 防御：升级有 gadget 的第三方库（CommonsCollections、CCK、Beanutils 等），并移除 classpath 中不需要的 gadget 依赖。
- 防御：对 CodeQL 查询做“查询质量”维护：定期用已知漏洞样本回归（漏报）、用历史误报样本收紧（误报），并把自定义模型纳入版本管理。

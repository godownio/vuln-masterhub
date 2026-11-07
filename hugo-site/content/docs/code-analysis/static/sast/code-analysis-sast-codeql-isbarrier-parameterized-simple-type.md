---
id: code-analysis-sast-codeql-isbarrier-parameterized-simple-type
title: CodeQL isBarrier 泛型净化：把 List<Long> 等简单类型判为净化点消除 SQL 注入误报
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-isbarrier-parameterized-simple-type
tags:
- codeql
- sast
- java
- taint-analysis
- isbarrier
- false-positive
- sqli
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:18:11+08:00'
  notes: 已对照原文核对：SimpleType 与 isBarrier 的 ParameterizedType 扩展代码与原文一致，List<Long> 误报示例与图1/图3 告警变化吻合，关联卡存在；未验证点：本线程未实际运行 CodeQL
url: /docs/code-analysis/static/sast/code-analysis-sast-codeql-isbarrier-parameterized-simple-type/
draft: false
kb_aliases:
- CodeQL 净化流优化
- isBarrier 泛型误报
- List<Long> SQL 注入误报
- CodeQL SQL 注入误报处理
- SimpleType isBarrier
---

## 一句话结论

CodeQL 官方 Java SQL 注入规则的 `isBarrier` 只把基本类型、包装类型、数字、UUID、Date、Calendar、BitSet、时间类型和枚举判为净化，未覆盖 `List<Long>` 等“简单类型的泛型容器”；在规则中加入“参数化类型的类型参数是简单类型即视为净化”的判断，即可消除这类把 `List<Long>` 请求体误报为 SQL 注入的假阳性。

## 原理

- CodeQL 污点分析中，`isBarrier(node)` 定义净化点：污点流到该节点即中断，不再继续传播到 sink。
- 官方 CWE-089 SQL 注入查询的 source 选取范围较宽，会把 Controller 的请求体参数都当作污点；`List<Long>` 这类参数虽然流到了 SQL 拼接/查询 sink，但其元素只能是整数，无法承载注入字符串，因此是误报。
- 官方 `isBarrier` 的 `SimpleType` 判断覆盖了 `PrimitiveType`、`BoxedType`、`NumberType`、`UUID`、`Date`、`Calendar`、`BitSet`、`TemporalAmount`、`TemporalAccessor`、`EnumType`，但 `node.getType()` 对 `List<Long>` 返回的是 `ParameterizedType`，不等于上述任一类型，所以未被净化。
- 把判断扩展为“节点类型本身是 SimpleType，或其类型参数（`getATypeArgument()`）是 SimpleType”，就能让 `List<Long>`、`List<Integer>`、`List<UUID>` 等容器整体成为净化点；对 `List<String>` 不生效，不会误伤真实污点。
- 之所以成立：这是对“数据能力”的精确建模——整数容器不具备构造 SQL 注入载荷的能力，因此可以在数据流层直接截断，而不是靠抑制告警。

## 触发条件

- 使用 CodeQL 官方 Java SQL 注入查询（CWE-089）或基于其 `isBarrier` 的自定义查询；
- 被测代码存在 `List<Long>`、`List<Integer>` 等简单类型集合作为 Controller 入参，并流入 SQL sink；
- 规则未对参数化类型做递归/类型参数判断；
- 结果中出现“入参为数字集合却被报 SQL 注入”的告警。

## 利用步骤

1. 用官方查询跑一遍目标工程，确认误报样例（如 `@RequestBody List<Long>` 进入查询方法）。
2. 在查询的 `isBarrier` 中加入 `SimpleType` 类，并把 `ParameterizedType` 的类型参数纳入判断。
3. 重新编译查询并复跑，对比告警差异：目标误报应消失，真实字符串注入仍应保留。
4. 按业务补充“绝对安全的工具方法/校验方法”为自定义净化节点，进一步压低误报。
5. 若要处理嵌套泛型（如 `List<List<Long>>`），对类型参数递归判断，而不是只看一层。

## PoC

```ql
class SimpleType extends Type {
  SimpleType() {
    this.getType() instanceof PrimitiveType or
    this.getType() instanceof BoxedType or
    this.getType() instanceof NumberType or
    this.getType().(RefType).hasQualifiedName("java.util", "UUID") or
    this.getType().(RefType).getASourceSupertype*().hasQualifiedName("java.util", "Date") or
    this.getType().(RefType).hasQualifiedName("java.util", "Calendar") or
    this.getType().(RefType).hasQualifiedName("java.util", "BitSet") or
    this.getType().(RefType).getASourceSupertype*()
        .hasQualifiedName("java.time.temporal", "TemporalAmount") or
    this.getType().(RefType).getASourceSupertype*()
        .hasQualifiedName("java.time.temporal", "TemporalAccessor") or
    this.getType() instanceof EnumType
  }
}

predicate isBarrier(DataFlow::Node node) {
  node.getType() instanceof SimpleType or
  node.getType().(ParameterizedType).getATypeArgument() instanceof SimpleType
}
```

误报样例（应被净化）：

```java
@PostMapping("/longin")
public List<Student> longin(@RequestBody List<Long> user_list) {
    return indexLogic.getStudentWithInLong(user_list);
}
```

## 变体与关联

- 容器变体：`List<Long>`、`Set<Integer>`、`Optional<Long>`、数组 `Long[]`；递归处理嵌套泛型可覆盖 `List<List<Long>>`。
- 净化节点变体：把业务中已做严格类型转换/白名单校验的方法声明为 `isBarrier`；或反向收窄 source（只把 String 类型参数作为污点）。
- 关联：[[code-analysis-vuln-discovery-python-adjacent-string-concat]]（另一类规则实现缺陷导致的检测失真）；SQL 注入本体见 [[web-generic-sqli-keyword-double-write-bypass]]。
- 影响边界：本卡是 SAST 规则优化，不产生攻击效果；错误净化可能漏报真实注入，必须用正样本回归验证。

## 检测与防御（规则质量保障）

- 为 `isBarrier` 变更维护正/负样本：数字集合、字符串集合、嵌套泛型、真实拼接注入各一组，变更后必须全部符合预期。
- 禁止把“看起来安全”的复杂对象整体加入净化，除非能证明其字段/元素均为不可注入类型。
- 对官方规则升级做差异回归，避免自定义 `isBarrier` 覆盖官方新增的类型判断。

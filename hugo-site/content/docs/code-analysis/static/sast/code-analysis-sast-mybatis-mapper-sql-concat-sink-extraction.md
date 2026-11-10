---
id: code-analysis-sast-mybatis-mapper-sql-concat-sink-extraction
title: MyBatis SQL 注入 sink 提取：遍历 classpath 解析 Mapper XML/注解的 ${} 拼接点，按 @Param/JavaBean/Map/List 映射到方法参数
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: mybatis-mapper-sql-concat-sink-extraction
tags:
- sast
- taint-analysis
- mybatis
- java
- sql-injection
- sink
- mapper-xml
- code-audit
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V404-fix
  verified_at: '2026-11-09T13:34:21+08:00'
  notes: V404 核对指出：PoC 单参数 JavaBean 分支用 m.getDeclaringClass().getDeclaredField(field) 查找字段有误——声明类是 Mapper 接口，无业务字段，照抄会漏掉全部 JavaBean 字段 sink；原文按参数类型 getParamType(0) 的类查找。已改为 paramClassOf(t) 取参数类型的 JClass 并加注释说明不能对 Mapper 接口取字段。其余解析/映射逻辑与原文一致。
url: /docs/code-analysis/static/sast/code-analysis-sast-mybatis-mapper-sql-concat-sink-extraction/
draft: false
kb_aliases:
- MyBatis Sink 提取
- Mapper XML 解析
- ${} 拼接点
- MyBatis SQL 注入审计
- '@Param sink 匹配'
- MybatisSink
- Mapper 注解 SQL
---

## 一句话结论

MyBatis 的 SQL 注入面藏在 Mapper XML/注解里：只有 `${}` 是字符串拼接（危险），`#{}` 是预编译占位符（安全）。要让 Tai-e 等污点分析器扫到 MyBatis，先要遍历 classpath 中所有 `*Mapper.xml`（或 `@Select/@Update/@Insert/@Delete` 注解），把 namespace→Mapper 接口、id→方法、顶级 SQL 与 `where/set/trim/if/choose/foreach/include/sql` 标签拼成完整 SQL，再用 `\$\{(\w+|\w+\.\w+)\}` 抓出拼接参数名，并按方法参数类型（单个简单类型、`@Param`、`paramN`、JavaBean 字段、Map/List）映射成 `(方法, 参数下标, 字段)` 三元组形式的 sink。

## 原理

- **`${}` vs `#{}`**：`#{}` 被 MyBatis 转成 JDBC `?` 占位符并绑定参数，不改变 SQL 结构；`${}` 是纯文本替换，参数直接拼进 SQL，是注入点。因此 SAST 只需要针对 `${}` 提取 sink。
- **SQL 不在方法体里**：Mapper 接口方法是抽象的，SQL 写在 XML 的 `<select>/<insert>/<update>/<delete>` 或注解 `@Select("...")` 中；普通 Java 污点分析看不到 SQL 字符串与参数的关系，必须自己建立映射。
- **XML 结构解析**：根元素 `namespace` 对应 Mapper 接口全类名；顶级标签的 `id` 对应接口方法名；SQL 文本由顶级标签正文与嵌套的动态标签（`where/set/trim/if/choose/when/otherwise/foreach`）正文拼接得到；`<include refid>` 需要递归合并 `<sql id>` 片段，否则拼接点会漏。
- **参数名到参数的映射**：Soot/Tai-e 生成的接口 IR 不保留抽象方法形参名，只能靠规则推断：
  - 方法只有一个参数且是简单类型/String：第 0 个参数就是 `${value}` 对应的 sink；
  - 多参数且某个参数有 `@Param("x")` 且 x 等于 `${}` 里的名字：该参数是 sink；
  - 多参数无 `@Param`：MyBatis 内部按 `param1/param2/...` 命名，`${paramN}` 映射到第 N−1 个参数；
  - 单个 JavaBean 参数：`${name}` 会反射调用 `getName()`，sink 应记为 `(方法, 0, "name")`，即字段级 sink；
  - Map/List 参数：底层是数组/哈希表，指针分析无法按 key/下标精确关联，只能把整个集合参数记为 sink（宁可多报）。
- **为什么值得单独建 sink**：Tai-e 的默认 sink 匹配针对有方法体的方法；MyBatis 抽象方法没有 IR、调用边也是靠 MockObj 补出来的，且默认只判断“整个对象是否有污点”，不会精确到 JavaBean 字段。自定义 `MybatisSink` 结构（method/index/field）能让后续匹配阶段按字段粒度判断污点。

## 触发条件

- 待审计项目使用 MyBatis（XML Mapper 或注解方式），且存在 `${}` 拼接或 `@Select` 等注解 SQL。
- 能拿到完整 classpath/jar 以遍历 `*Mapper.xml`，并能解析 Mapper 接口的类与方法（Tai-e `World`/`JClass` 可用）。
- SQL 片段使用了 `<include>/<sql>` 或动态标签，需要正确展开才能得到可匹配的 SQL 文本。
- 分析目标是“发现候选 SQL 注入点”，接受一定误报（无 `@Param` 时全部参数标记）。

## 利用步骤

1. 遍历 `Options.getAppClassPath()`：对每个 `.jar` 用 `JarFile` 枚举 entry，对目录用 `Files.walk`，筛选文件名以 `Mapper.xml` 结尾的文件。
2. 用 DOM 解析每个 XML：取根元素 `namespace`，通过 `World.getClassHierarchy().getClass(namespace)` 找到 Mapper 接口。
3. 对每个顶级 `insert/update/delete/select`：取 `id` 找到 `JMethod`；把标签正文与嵌套动态标签正文拼接；遇到 `include` 时用 `refid` 到根下找对应 `<sql>` 片段展开（可递归）。
4. 对拼接后的 SQL 跑正则 `\$\{(\w+|\w+\.\w+)\}`，收集所有 `concatArgName`。
5. 按方法参数形态决定 sink：
   - 单参数 JavaBean → 解析 `${a.b}` 的首段/字段名，记录 `field`；
   - 单参数非 JavaBean → `(method, 0, null)`；
   - 多参数 → 优先 `@Param` 的 value 匹配 concatArgName，其次 `paramN`，匹配不到则把所有非简单类型参数都记为 sink；
   - Map/List → 整个参数记为 sink。
6. 对注解方式：扫描 Mapper 方法上的 `org.apache.ibatis.annotations.(Select|Delete|Insert|Update)`，取 `value` 字符串作为 SQL，套用同一套 `${}` 与参数映射逻辑。
7. 把得到的 `MybatisSink` 列表注入污点分析配置（例如扩展 `TaintConfig` 增加 mybatisSinks 字段），或作为外部 sink 清单供扫描器使用。

## PoC

最小解析与 sink 判定逻辑（伪代码，按原文思路重写）：

```java
Pattern CONCAT = Pattern.compile("\\$\\{(\\w+|\\w+\\.\\w+)\\}");
Pattern PARAM_N = Pattern.compile("^param(\\d+)$");

List<MybatisSink> parseMapperXml(InputStream in) {
    Document doc = new SAXReader().read(in);
    Element root = doc.getRootElement();
    JClass mapper = World.get().getClassHierarchy().getClass(root.attributeValue("namespace"));
    List<MybatisSink> out = new ArrayList<>();
    for (Element top : root.elements()) {
        if (!top.getName().matches("insert|update|delete|select")) continue;
        JMethod m = mapper.getDeclaredMethod(top.attributeValue("id"));
        StringBuilder sql = new StringBuilder(top.getText().strip());
        appendDynamic(root, top, sql);           // where/set/trim/if/choose/foreach + include
        out.addAll(toSinks(sql.toString(), m));
    }
    return out;
}

List<MybatisSink> toSinks(String sql, JMethod m) {
    Set<String> names = new HashSet<>();
    Matcher mt = CONCAT.matcher(sql);
    while (mt.find()) names.add(mt.group(1));
    List<MybatisSink> sinks = new ArrayList<>();
    if (names.isEmpty()) return sinks;
    if (m.getParamCount() == 1) {
        Type t = m.getParamType(0);
        if (isJavaBean(t)) {
            JClass bean = paramClassOf(t);   // 参数类型对应的 JClass；不能对 Mapper 接口 getDeclaredField（接口无业务字段）
            for (String n : names) {
                String field = n.contains(".") ? n.split("\\.")[1] : n;
                if (bean.getDeclaredField(field) != null)
                    sinks.add(new MybatisSink(m, 0, field));
            }
        } else {
            sinks.add(new MybatisSink(m, 0, null));
        }
        return sinks;
    }
    for (String n : names) {
        boolean matched = false;
        for (int i = 0; i < m.getParamCount(); i++) {
            Annotation p = m.getParamAnnotation(i, "org.apache.ibatis.annotations.Param");
            if (p != null && ("\"" + n + "\"").equals(p.getElement("value").toString())) {
                sinks.add(new MybatisSink(m, i, null)); matched = true; break;
            }
        }
        if (!matched) {
            Matcher pn = PARAM_N.matcher(n);
            if (pn.find()) { sinks.add(new MybatisSink(m, Integer.parseInt(pn.group(1)) - 1, null)); matched = true; }
        }
        if (!matched) {                       // 名字无法映射时保守处理：全部参数
            for (int i = 0; i < m.getParamCount(); i++)
                if (!isPrimitive(m.getParamType(i))) sinks.add(new MybatisSink(m, i, null));
        }
    }
    return sinks;
}
```

注解方式等价逻辑：

```java
for (Annotation a : method.getAnnotations())
    if (a.getType().matches("org\\.apache\\.ibatis\\.annotations\\.(Select|Delete|Insert|Update)"))
        sinks.addAll(toSinks(a.getElement("value").toString(), method));
```

## 变体与关联

- **`@SelectProvider` 等动态 SQL 提供者**：SQL 在 Java 方法里拼字符串返回，静态解析更难，可退化为“把 provider 方法标记为 source/人工审计”。
- **`${}` 中带表达式**（如 `${ew.sqlSegment}`、`${param.field}`）：正则要支持点号与更复杂表达式；无法静态确定时应整体标记参数。
- **`<foreach>` 拼接**：循环体里的 `${item.xxx}` 可能造成批量注入，展开时保留 item 变量名并映射回集合元素字段。
- **`#{}` 误伤**：正则只匹配 `${`，不要匹配 `#{`；同时注意 XML 转义（`\${}` 在部分配置里是字面量）。
- **关联**：本卡产出的 sink 需要配合“Tai-e 分析抽象 Mapper 方法”“JavaBean 字段级污点匹配与 Map/List/setter 传播”两类工程改造，才能在完整污点分析中生效。

## 检测与防御

- **代码层防御**：业务 SQL 一律用 `#{}`；必须动态拼接表名/列名/排序字段时，用白名单枚举校验后拼入，禁止直接拼用户输入。
- **审计检索**：全局搜索 Mapper XML/注解中的 `${`，逐个人工确认参数来源；结合 MyBatis 日志/插件打印最终 SQL。
- **SAST 集成**：把本卡的 sink 提取器接入 Tai-e/CodeQL 等扫描器，并维护 MyBatis 常见动态标签的解析覆盖；对无法解析的 XML（include 循环、provider）输出“需人工审计”清单而不是静默跳过。
- **误报控制**：对 `@Param` 精确匹配、JavaBean 字段级匹配以降低误报；Map/List 场景保留集合级 sink，接受一定误报换取不漏报。
- **验证**：在已知含 `${}` 注入的项目上回归，确认 sink 数量、参数下标与字段名正确；对修复为 `#{}` 的版本确认不再产生 sink。

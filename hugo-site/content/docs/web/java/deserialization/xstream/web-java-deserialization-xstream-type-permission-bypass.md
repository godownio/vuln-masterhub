---
id: web-java-deserialization-xstream-type-permission-bypass
title: XStream 4 类型白名单绕过四特性：属性豁免、层级豁免、final 可改与 transient 不写
type: scenario
domain: web
path: web/java/deserialization/xstream
technique: xstream-type-permission-property-hierarchy-bypass
tags:
- java
- xstream
- deserialization
- whitelist-bypass
- type-permission
- gadget
- hashset
- reflection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V105
  verified_at: '2026-11-05T23:03:19+08:00'
  notes: 已对照原文Mini4Features/MiniHashCode核对属性豁免、Throwable/Map/Collection层级豁免、final可改写、transient不写与HashSet hashCode/equals触发；属XStream 4 harness级演示，原文未展示运行输出，未复现；该卡可独立作为白名单绕过技术复用。
url: /docs/web/java/deserialization/xstream/web-java-deserialization-xstream-type-permission-bypass/
draft: false
kb_aliases:
- XStream 属性豁免
- XStream 层级豁免
- XStream final 字段改写
- XStream transient 不写
- allowTypeHierarchy Throwable
- NoTypePermission.NONE 绕过
- HashSet hashCode 触发
- XStream 白名单绕过
---

## 一句话结论

即使 XStream 4 配置了 `NoTypePermission.NONE` 并只 `allowTypes` 少量宿主类，攻击者仍可利用四个语言/框架特性绕过类型白名单：无 `class=` 的元素按字段声明类型实例化（属性豁免）、`allowTypeHierarchy(Throwable/Map/Collection/Number)` 放行大量子类（层级豁免）、非 transient 的 `final` 字段可被反射改写、`transient` 字段不会被 XML 写入；再配合集合反序列化时自动调用 `hashCode/equals`，即可把“只能反序列化几个类”扩大成任意 gadget 链的构造能力。

## 原理

- **属性豁免（field-type exemption）**：XStream 在把 XML 元素映射到对象字段时，如果元素没有 `class=` 属性，会用宿主字段的声明类型来实例化。例如宿主类 `H` 有 `public BasicDataSource ds;`，XML 写 `<ds>...`（不写 `class`），XStream 就直接 `new BasicDataSource()` 并填充其属性，不经过 `SecurityMapper` 的类型权限检查。于是即使 `BasicDataSource` 不在 `allowTypes` 白名单，只要它出现在某个可反序列化宿主的字段类型上，就能被构造。原文用这一点把 DBCP 数据源藏进 `myDataSource` 字段。
- **层级豁免（type hierarchy）**：`allowTypeHierarchy(Throwable.class)` 允许任意 `Throwable` 子类（包括非 JDK 的 `org.hsqldb.HsqlException`、TeamCity 内部异常类）；`allowTypeHierarchy(Map.class)`/`Collection.class` 允许 `linked-hash-map`、`HashSet`、`HashBag` 等实现；`Number` 同理。很多应用为了兼容集合/异常，会保留这些层级豁免，攻击者即可用 `class=` 显式指定白名单之外的子类。
- **final 字段可写**：XStream 通过反射设置字段，非 transient 的 `final String` 字段也能被 XML 值覆盖（示例 `public final String fi = new String("x")` 被 `<fi>y</fi>` 改成 `y`）。这让攻击者能改写对象中本应不可变的配置/常量字段。
- **transient 不写**：`transient` 字段不会被反序列化写入，保持构造后的默认值。攻击者可利用它控制对象初始状态（例如让某个字段保持默认，避免在错误时机触发副作用），也可反推哪些字段可由 XML 控制。
- **集合触发器**：反序列化 `HashSet` 时，XStream 的 `CollectionConverter` 会对每个元素调用 `add`；`HashSet.add` 会计算 `hashCode`，哈希碰撞时调用 `equals`。因此只要能把恶意对象塞进 `HashSet`（或 `HashBag` 等集合），就能在反序列化阶段触发 `hashCode`/`equals` 链，而无需等待业务代码调用。原文的 `MiniHashCode` 演示了元素 `Trigger.hashCode()` 在反序列化时被自动调用。
- **组合效果**：属性豁免提供“白名单外类型的构造”，层级豁免提供“子类入口”，final 改写提供“字段级控制”，transient 提供“状态控制”，集合触发器提供“调用时机”。四者叠加，足以把有限的类型白名单扩展成完整的 gadget 构造面；TeamCity 的 `HashAdapter` 链正是用属性豁免构造 `BasicDataSource`、用层级豁免放行 `Throwable`/`Collection`、用 `HashSet` 触发 `DefaultMapBag.equals`。

## 触发条件

- 目标使用 XStream 4 反序列化不可信 XML，并启用了类型白名单（`NoTypePermission.NONE` + `allowTypes`）但保留了至少一个宽泛层级豁免（常见：`Throwable`、`Map`、`Collection`、`Number`）。
- 存在可反序列化的宿主类，其字段声明类型是攻击者想构造的类（属性豁免），或该字段类型本身在白名单/层级内。
- 目标 classpath 中存在可用于后续链的类（如 DBCP `BasicDataSource`、FreeMarker `HashAdapter`、Commons Collections `HashBag` 等）。
- XML 元素可省略 `class=`（XStream 默认按字段名/别名映射）且宿主字段可见/可写。
- 反序列化流程会处理集合类型（`HashSet`/`HashBag` 等），从而触发 `hashCode`/`equals`。
- 目标 XStream 版本对 final 字段反射写入未做额外限制（原文以 XStream 4 演示；不同版本/安全框架配置可能有差异）。

## 利用步骤

1. **找宿主类**：在目标 classpath 中寻找可反序列化、字段类型包含危险类（数据源、模板引擎、脚本引擎、文件类）的类；字段名和 XML 元素名的映射关系要能从代码/别名推断。
2. **用属性豁免构造**：在 XML 中写 `<字段名>...` 而不加 `class=`，让 XStream 按字段声明类型实例化；逐步填充危险属性（如 JDBC URL、`connectionInitSqls`、模板/脚本内容）。
3. **用层级豁免放行子类**：对需要显式 `class=` 的对象，选择 `Throwable`、`Map`、`Collection` 等已放行层级的子类；把内部类/异常类当作“容器”携带其他字段。
4. **用 final/transient 调状态**：改写非 transient 的 `final` 配置字段；把不希望被 XML 覆盖的字段设为 `transient`，让其在构造后保持默认值，避免提前触发或用于区分对象状态。
5. **用集合触发**：把恶意对象放入 `<set>`/`HashSet`/`HashBag` 等集合；反序列化时 `add` 触发 `hashCode`，碰撞触发 `equals`，进入 gadget 链。
6. **验证**：在本地用与目标相同的 XStream 配置和 classpath 写 harness（原文 `Mini4Features`/`MiniHashCode`），确认四个特性均生效，再迁移到真实 payload。

## PoC

四特性一屏演示（原文 harness 简化）：

```java
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.XppDriver;
import com.thoughtworks.xstream.security.NoTypePermission;
import org.apache.commons.dbcp2.BasicDataSource;

public class Mini4Features {
  static class H {
    public transient String t = new String("keep");  // ④ transient: XML 不写，保持 keep
    public final String fi = new String("x");        // ③ final(非折叠): 反射可改成 y
    public Exception ex;                             // ② 层级豁免: class= 显式用 Throwable 子类
    public BasicDataSource ds;                       // ① 属性豁免: 无 class=，按字段类型实例化
  }
  public static void main(String[] a) {
    XStream x = new XStream(new XppDriver());
    x.addPermission(NoTypePermission.NONE);
    x.allowTypes(new Class[]{H.class, String.class});   // 白名单仅宿主+String
    x.allowTypeHierarchy(java.util.Map.class);
    x.allowTypeHierarchy(java.util.Collection.class);
    x.allowTypeHierarchy(Throwable.class);              // ← HsqlException 靠这层
    x.allowTypeHierarchy(Number.class);
    x.alias("h", H.class);
    H h = (H) x.fromXML(
      "<h><fi>y</fi>" +
      "<ex class=\"org.hsqldb.HsqlException\">boom</ex>" +
      "<ds><driverClassName>org.hsqldb.jdbc.JDBCDriver</driverClassName>" +
      "<url>jdbc:hsqldb:mem:x</url><userName>SA</userName><closed>false</closed></ds>" +
      "</h>");
    // 预期：t=keep（transient 未写）、fi=y（final 被改）、
    //       ex=HsqlException（层级豁免）、ds=BasicDataSource（属性豁免，未在白名单）
  }
}
```

集合触发 hashCode 演示：

```java
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.XppDriver;
import com.thoughtworks.xstream.security.NoTypePermission;
import java.util.HashSet;

public class MiniHashCode {
  static class Trigger {
    public String s;
    public int hashCode() { System.out.println("hashCode triggered: s=" + s); return 1; }
  }
  static class H { public HashSet<Trigger> set; }
  public static void main(String[] a) {
    XStream x = new XStream(new XppDriver());
    x.addPermission(NoTypePermission.NONE);
    x.allowTypes(new Class[]{H.class, Trigger.class, String.class});
    x.allowTypeHierarchy(java.util.Collection.class);   // HashSet 靠这层
    x.alias("h", H.class);
    x.alias("t", Trigger.class);
    H h = (H) x.fromXML("<h><set><t><s>a</s></t><t><s>b</s></t></set></h>");
    // 反序列化 Hashset 时 CollectionConverter 调 add → Trigger.hashCode() 自动执行
  }
}
```

## 变体与关联

- **别名/隐式映射**：XStream 的 `alias`、字段名映射和 `class=` 省略规则决定了属性豁免是否可用；不同应用可能用注解或自定义 Mapper，需按目标配置调整。
- **层级豁免的具体类**：除 `Throwable`/`Map`/`Collection`/`Number` 外，常见的 `Comparable`、`Serializable` 等层级也可能被放行；每多一个层级就多一批子类入口。
- **final 字段的例外**：折叠（folded）final 字段或 JDK 内部受限字段可能无法改写；原文的 `final String` 示例是非折叠情况，实际需按 XStream 版本验证。
- **集合触发器变体**：`HashSet`、`TreeSet`（依赖 `compareTo`）、`HashBag`（`equals`/`hashCode`）、`LinkedHashMap` 等都能在反序列化阶段触发不同方法；选哪种取决于目标 gadget 的入口方法。
- **与 TeamCity 链的关系**：TeamCity 的 R7 链就是这四个特性的组合应用——属性豁免藏 `BasicDataSource`、层级豁免放行 `Throwable`/`Collection`、`HashSet` 触发 `DefaultMapBag.equals`、final/transient 控制对象状态。
- **关联卡片**：[[web-java-deserialization-xstream-teamcity-agent-error-defaultmapbag-rce]]（完整 TeamCity RCE 链）、[[web-java-deser-commonscollections-cc7-hashtable-equals-lazymap]]（equals/hashCode 触发器思路）。

## 检测与防御

- **收紧 XStream 权限**：只 `allowTypes` 明确需要的类，避免 `allowTypeHierarchy(Throwable/Map/Collection/Number)` 等宽泛层级；升级到最新 XStream，启用其安全框架的默认黑名单/白名单。
- **禁止字段类型隐式实例化**：对不可信 XML 使用严格的类型校验（XML schema、允许的类白名单、禁止 `class=` 任意指定）；不要把危险类型（数据源、模板引擎、脚本引擎）作为可反序列化宿主的字段。
- **保护 final/transient 语义**：不要把安全关键配置放在可被 XStream 反射改写的非 transient final 字段；对敏感对象使用只读视图或不可变包装。
- **集合入口监控**：在反序列化入口记录解析到的类名与集合类型；告警 `HashSet`/`HashBag`/`TreeSet` 中出现异常对象、`hashCode`/`equals` 在反序列化阶段被调用。
- **最小化 classpath**：移除不必要的 DBCP/HSQLDB/FreeMarker/Commons Collections 等 gadget 依赖，降低链可用性；对 CI/TeamCity 等暴露面做网络隔离和认证。
- **测试与审计**：用与生产一致的 XStream 配置做反序列化 harness 测试，验证四个特性是否可被触发；对历史 payload 与公开 gadget 做回归检测。

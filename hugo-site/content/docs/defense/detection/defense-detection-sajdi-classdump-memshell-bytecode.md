---
id: defense-detection-sajdi-classdump-memshell-bytecode
title: sa-jdi ClassDump 从运行中 JVM 提取真实字节码：按接口/父类黑名单筛类 + ASM/CFR 检测内存马
type: scenario
domain: defense
path: defense/detection
technique: sajdi-classdump-memshell-bytecode-detection
tags:
- java
- memshell
- detection
- sa-jdi
- classdump
- asm
- cfr
- jvm
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V279
  verified_at: '2026-11-08T00:04:18+08:00'
  notes: 已对照原文核对：sa-jdi ClassDump 命令行（PackageNameFilter/pkgList/outputDir/pid）、API 自定义 ClassFilter（类名/风险包、getTransitiveInterfaces、getSuper）、ASM ClassPrinter 与 visitMethodInsn 检测 Runtime.exec、CFR 反编译、sa-jdi 与 javaagent 的版本兼容/字节码缓存差异均与正文及 img/02-04 一致。该卡是一条检测工作流（dump 真实字节码→ASM/CFR 分析），非并列多技术，按原子卡保留；dump 与 ASM/CFR 为同一链路的前后步骤。dedup 首位自身，其余为不同检测路线（Tomcat scanner/Arthas、heapdump、agent transformer），非重复。
url: /docs/defense/detection/defense-detection-sajdi-classdump-memshell-bytecode/
draft: false
kb_aliases:
- sa-jdi
- ClassDump
- InstanceKlass
- PackageNameFilter
- 内存马字节码 dump
- ASM visitMethodInsn
- CFR 反编译检测
- jdi dump class
---

## 一句话结论

应急排查 Java 内存马时，可用 JDK 自带 sa-jdi 的 `ClassDump`（命令行或反射 API）从目标 JVM dump 真正的 `InstanceKlass` 字节码，按类名/实现接口/父类黑名单筛出 Filter、Servlet、ServletRequestListener、HttpServlet 子类及可疑包，再用 ASM 检查方法调用（如 `Runtime.exec`）或 CFR 反编译确认是否恶意；sa-jdi 直接读取 JVM 当前类字节码，不受 javaagent `redefineClasses`/transformer 字节码缓存影响，准确性高于 `Instrumentation.getAllLoadedClasses()` 路线。

## 原理

- **sa-jdi 的能力**：sa-jdi（Serviceability Agent JDI）通过 HotSpot 的调试接口读取目标 JVM 内部结构；`sun.jvm.hotspot.tools.jcore.ClassDump` 可以把已加载类写成 class 文件。它拿到的是 JVM 中的 `InstanceKlass`（JVM 内部类元数据），因此是当前真实字节码，而不是类路径上的原始文件。
- **按特征筛类**：一个 JVM 有大量类，全部 dump 成本高。`ClassDump` 支持 `ClassFilter` 接口（`canInclude(InstanceKlass)`），可自定义筛选：
  - 类名黑名单/包名黑名单：如 `net/rebeyond/`、`com/metasploit/` 等常见内存马工具包；
  - 实现接口黑名单：`javax/servlet/Filter`、`javax/servlet/Servlet`、`javax/servlet/ServletRequestListener`；
  - 父类黑名单：`javax/servlet/http/HttpServlet`。
  命令行可用 `PackageNameFilter` + `sun.jvm.hotspot.tools.jcore.PackageNameFilter.pkgList` 按包 dump；更细的特征筛选需用 API 方式自定义 `ClassFilter`。
- **为什么比 javaagent 准**：javaagent 路线通过 `Instrumentation.getAllLoadedClasses()` 拿 `Class`，再 `retransform`/dump；若类已被别的 transformer 改写，`retransform` 使用的“初始字节码缓存”可能不是当前真实字节码，甚至会把类回滚，检测者看不到攻击者最后写入的逻辑。sa-jdi 直接读 JVM 内存中的 `InstanceKlass`，不受该缓存影响。
- **兼容性代价**：sa-jdi 与目标 JVM 版本强绑定；文中实测 `jdk1.8.0_65` 的 sa-jdi 无法从 `jdk1.8.0_71` 的 Tomcat 进程 dump 类，需要同版本 JDK 的 sa-jdi，或改用 javaagent（兼容性更好、准确性较差）。
- **ASM 分析**：`ClassReader` 读取 dump 出的 class，`ClassVisitor.visitMethod` 返回 `MethodVisitor`，重写 `visitMethodInsn` 即可看到每个方法里调用的 owner/name/descriptor。可据此匹配 `java/lang/Runtime.exec` 等危险调用；也可用 CFR 把 class 反编译成 Java 源码后做字符串/逻辑审查。
- 该方法是“发现可疑类 → 取证确认”的检测链：黑名单只用于缩小范围，最终仍需人工反编译判断；攻击者可用反射、ProcessBuilder、自定义类加载等方式绕过单一 `Runtime.exec` 规则。

## 触发条件

- 目标为 HotSpot JVM（Tomcat、Spring Boot 等），排查者拥有与目标进程相同权限或可 attach/读取进程的权限，并知道 PID。
- JDK 8 环境自带 `lib/sa-jdi.jar`；JDK 9+ 需确认 `jdk.hotspot.agent` 模块及 `sun.jvm.hotspot.tools.jcore.ClassDump` 是否可用，且 sa-jdi 版本最好与目标 JVM 一致。
- 能执行 Java 代码运行自定义 `ClassFilter`（API 方式），或能用命令行 `ClassDump` 按包 dump。
- 已准备 ASM（如 9.x）与 CFR（如 0.152）依赖用于后续分析。
- 若攻击者使用 Agent 型内存马且 javaagent 缓存被污染，sa-jdi 路线的准确性优势更明显。

## 利用步骤

1. 找到目标 JVM 的 PID（`jps`、`ps` 或进程管理工具），确认 JDK 版本，准备同版本 `sa-jdi.jar`。
2. 方式一（命令行按包 dump）：
   `java -cp "<JDK>/lib/sa-jdi.jar" -Dsun.jvm.hotspot.tools.jcore.filter=sun.jvm.hotspot.tools.jcore.PackageNameFilter -Dsun.jvm.hotspot.tools.jcore.PackageNameFilter.pkgList=<可疑包> -Dsun.jvm.hotspot.tools.jcore.outputDir=<输出目录> sun.jvm.hotspot.tools.jcore.ClassDump <pid>`
3. 方式二（API 自定义筛选）：实现 `ClassFilter.canInclude(InstanceKlass)`，按类名、`getTransitiveInterfaces()`、`getSuper()` 匹配 Filter/Servlet/Listener/HttpServlet 和可疑包；用反射调用 `sun.jvm.hotspot.tools.Tool.start(String[])` 启动 `ClassDump`，结束后 detach。
4. 检查输出目录：可疑类通常没有对应磁盘文件、类名带 `$`（JSP 匿名类）或来自陌生包；过滤掉常见框架类。
5. 用 ASM 的 `ClassReader`/`ClassVisitor` 解析 dump 出的 class：类名、父类、字段、方法；再用 `MethodVisitor.visitMethodInsn` 匹配危险调用（如 owner=`java/lang/Runtime`、name=`exec`），或匹配 `ProcessBuilder`、`defineClass`、反射/Base64 解码等特征。
6. 对可疑类用 CFR 反编译为 Java 源码，人工审查 `doFilter`/`service`/`requestInitialized`/`transform` 等入口是否有读取请求参数并执行命令的逻辑。
7. 确认后按内存马类型移除组件或删除入口，并修复注入根因；dump 文件按敏感数据保管。

## PoC

```bash
# 命令行按包 dump（JDK 8）
java -classpath "<JDK>/lib/sa-jdi.jar" \
  -Dsun.jvm.hotspot.tools.jcore.filter=sun.jvm.hotspot.tools.jcore.PackageNameFilter \
  -Dsun.jvm.hotspot.tools.jcore.PackageNameFilter.pkgList=com.example.filter \
  -Dsun.jvm.hotspot.tools.jcore.outputDir=/tmp/ClassOut \
  sun.jvm.hotspot.tools.jcore.ClassDump <pid>
```

```java
// API 自定义 ClassFilter（筛选 Filter/Servlet/Listener 与可疑包）
static class MyFilter implements ClassFilter {
    private static final String[] DANGEROUS_INTERFACES = {
        "javax/servlet/Filter", "javax/servlet/Servlet", "javax/servlet/ServletRequestListener"
    };
    private static final String[] RISK_PACKAGES = {"net/rebeyond/", "com/metasploit/"};
    private static final String[] RISK_SUPERCLASSES = {"javax/servlet/http/HttpServlet"};

    @Override
    public boolean canInclude(InstanceKlass kls) {
        String name = kls.getName().asString();
        for (String p : RISK_PACKAGES) {
            if (name.startsWith(p)) return true;
        }
        KlassArray interfaces = kls.getTransitiveInterfaces();
        for (int i = 0; i < interfaces.length(); i++) {
            for (String itf : DANGEROUS_INTERFACES) {
                if (interfaces.getAt(i).getName().asString().equals(itf)) return true;
            }
        }
        Klass superKlass = kls.getSuper();
        if (superKlass != null) {
            for (String sup : RISK_SUPERCLASSES) {
                if (sup.equals(superKlass.getName().asString())) return true;
            }
        }
        return false;
    }
}
```

```java
// ASM 检测 Runtime.getRuntime().exec 调用（仅示例，需扩展其他 sink）
class ExecMethodVisitor extends MethodVisitor {
    public ExecMethodVisitor(int api) { super(api); }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name,
                                String descriptor, boolean isInterface) {
        if (owner.equals("java/lang/Runtime") && name.equals("exec")
                && descriptor.equals("([Ljava/lang/String;)Ljava/lang/Process;")) {
            System.out.println("suspicious: " + owner + "." + name + descriptor);
        }
        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
    }
}
```

```java
// CFR 反编译 dump 出的 class，便于人工审查
CfrDriver driver = new CfrDriver.Builder().withBuiltOptions(options).build();
driver.analyse(Collections.singletonList(classFile));
```

## 变体与关联

- 筛选特征变体：按注解、字段名、字符串常量（`cmd`、`shell`、`pass`）、是否有磁盘 code-source、类名是否伪装框架类等组合筛选；Controller 型内存马无接口特征，需见 [[defense-detection-spring-mvc-mapping-registry-controller-memshell]]。
- dump 方式变体：javaagent `getAllLoadedClasses` + `retransform`（兼容性好但可能受字节码缓存影响）、Arthas `dump`/`jad`、heap dump 离线搜索 `cafebabe`/`yv66`。
- 分析变体：ASM 可匹配 `ProcessBuilder`、`ClassLoader.defineClass`、`Unsafe`、反射、Base64 解码等；CFR/JADX 反编译后做字符串与数据流审查；也可结合 JDK 自带 `javap` 快速看结构。
- 关联卡片：[[defense-detection-tomcat-memshell-scanner-arthas]]（在线组件枚举与 Arthas）、[[defense-detection-arthas-agent-memshell-detect-remove]]（Agent transformer 检测）、[[defense-forensics-java-memshell-heapdump-bytecode]]（无法 attach 时的离线取证）、[[web-java-component-tomcat-dynamic-filter-memshell]]、[[web-java-framework-spring-mvc-dynamic-controller-memshell]]（攻击面）。
- 边界：sa-jdi 版本与目标 JVM 不一致会失败；非 HotSpot JVM（OpenJ9 等）不适用；只能 dump 已加载类，攻击者若已卸载/隐藏类需结合其他手段；黑名单规则无法覆盖所有内存马，必须人工确认。

## 检测与防御

- 检测（对防守方自身工具使用）：dump 出的类中出现黑名单接口/父类实现、可疑包、无磁盘来源的类、JSP `$1` 匿名类；ASM 发现 `Runtime.exec`/`ProcessBuilder`/`defineClass` 调用；CFR 源码出现请求参数到命令执行的直接数据流。
- 防御：限制 `jmap`/attach/sa-jdi 所需权限，非应急场景关闭或审计进程 attach；监控异常的类 dump、Arthas/Copagent 运行痕迹。
- 加固：应用最小权限运行；Web 目录只读、禁止 JSP；对 `StandardContext` 动态注册 API 做 RASP/Agent 监控；保留同版本 sa-jdi 与 ASM/CFR 工具链用于应急。
- 注意：dump 出的 class 可能包含业务源码与密钥，按敏感数据加密保管并及时清理临时目录。

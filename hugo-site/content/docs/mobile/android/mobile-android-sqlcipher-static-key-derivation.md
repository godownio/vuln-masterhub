---
id: mobile-android-sqlcipher-static-key-derivation
title: Android 应用 SQLCipher 数据库静态密钥还原：逆向 keyBase（MD5 前 6 位）解密应用数据库
type: scenario
domain: mobile
path: mobile/android
technique: android-sqlcipher-static-key-derivation
tags:
- android
- sqlcipher
- sqlite
- forensics
- reverse-engineering
- jadx
- key-derivation
- mobile
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T02:03:51+08:00'
  notes: 已对照原文第8-9题与图19-26核对：Keys 类 one=116、ones={-1,0,3,5,1,-5}，keyDb 逐字节相加得 stwyuo.db；keyBase=MD5(ones).substring(0,6)，本地复算 MD5(b'\xff\x00\x03\x05\x01\xfb')=c258ba7634...，前6位 c258ba 与原文一致；DataHandler 调用 SQLiteDatabase.openOrCreateDatabase(file, Keys.keyBase(), ...)，图21 显示 SQLCipher 4 默认/4096/256000/SHA512；图25/26 确认 picture(time,phone,gps_key,gps,data BLOB) 与 JPEG 记录。未复跑整库解密（无 stwyuo.db/APK）；无 CVE/版本；frontmatter 无 sources/source_url。
url: /docs/mobile/android/mobile-android-sqlcipher-static-key-derivation/
draft: false
kb_aliases:
- Android SQLCipher 静态密钥
- keyBase MD5 前 6 位
- 应用数据库解密
- jadx 定位 openOrCreateDatabase
- 手机取证数据库
- stwyuo.db
---

## 一句话结论

Android 应用用 SQLCipher 加密本地 SQLite 数据库时，密钥必须由客户端在打开数据库前派生；若应用把密钥派生写成 Java/Kotlin 里的静态常量与 MD5 截断（如 `MD5(ones).substring(0,6)`），取证方无需运行应用或读取进程内存，只要用 jadx 逆向 APK 复现 `keyBase()`，就能用该密钥直接打开数据库并导出照片、GPS、手机号等记录。

## 原理

- SQLCipher 是 SQLite 的加密分支，数据库页用密钥加密；应用调用 `SQLiteDatabase.openOrCreateDatabase(file, key, ...)` 或 `net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase()` 时把口令传给 SQLCipher，由 SQLCipher 内部做 KDF 派生实际密钥。
- 加密后的 SQLite 文件不再以 `SQLite format 3\0` 开头，而是随机 salt；直接用普通 SQLite 工具打开会报 “file is not a database”。要读取必须提供口令。
- 如果口令由客户端静态派生（硬编码字节数组、MD5/SHA 截断、BuildConfig 常量、字符串拼接），那么 APK 里必然包含派生逻辑与常量；逆向 DEX 即可离线复现，不需要设备在运行、也不需要 root 或内存抓取。
- 本例中 `Keys` 类用 `one = 116` 与 `ones = {-1,0,3,5,1,-5}` 逐字节相加得到数据库文件名 `stwyuo.db`（116-1='s', 116='t', 116+3='w', 116+5='y', 116+1='u', 116-5='o'，再拼 `.db`），`keyBase()` 返回 `MD5(ones)` 的前 6 个十六进制字符（`c258ba`）。用该口令在 DB Browser for SQLite 的 SQLCipher 4 模式下打开，即可读出 `picture` 表的 `time/phone/gps_key/gps/data` 字段与内嵌 JPEG。
- 这类设计的根本问题：密钥与设备、用户、安装实例无关，所有安装共用同一口令；一旦 APK 泄露或设备镜像被获取，数据库即可被离线解密。

## 触发条件

- 已获取目标 Android 设备镜像或应用数据目录（如 `apps/<package>/` 下的 `.db` 文件）以及对应 APK。
- 应用使用 SQLCipher（或类似整库加密），且密钥在 Java/Kotlin/原生代码中静态派生或硬编码。
- 数据库文件可读；APK 未加壳或可脱壳；关键类/方法未被强混淆到不可读（或可通过字符串/调用链定位）。
- 取证/分析已获授权，遵守隐私与合规要求。

## 利用步骤

1. 定位数据库：在镜像的 `apps/<package>/`、`databases/` 或应用私有目录查找 `.db` 文件；检查文件头不是 `SQLite format 3`，确认是加密库（本例为 `stwyuo.db`）。
2. 提取 APK：从镜像或应用市场获取对应版本 APK；用 jadx 打开，搜索 `openOrCreateDatabase`、`SQLiteDatabase`、`net.sqlcipher`、`SupportOpenHelper`、`keyBase`、`keyDb` 等关键词。
3. 还原密钥逻辑：阅读 `Keys`/`DataHandler` 等类，确认密钥来源（静态数组、MD5/SHA、BuildConfig、字符串拼接、native 方法）；本例 `keyBase() = MD5(ones).substring(0,6)`，`keyDb()` 生成数据库文件名。
4. 复现密钥：用 Python/Java 对相同字节数组做 MD5 并截取前 6 位，得到 `c258ba`；若逻辑复杂，可在本地跑该函数或写等价脚本。
5. 打开数据库：用支持 SQLCipher 的工具（DB Browser for SQLite 选择 “SQLCipher 4 默认”，或 sqlcipher CLI）输入密钥；若 KDF 参数不同（SQLCipher 3/4、页大小、迭代次数），按应用实际配置调整。
6. 导出与分析：查询 `sqlite_master` 获取表结构，导出业务表（如 `picture` 的 time/phone/gps/data），从 BLOB 中提取 JPEG，关联时间与位置。
7. 交叉验证：用应用内其他数据（SharedPreferences、日志、缓存）验证解密结果；记录 APK 版本与数据库 schema，便于复现。

## PoC

```java
// 示例：从 APK 逆向得到的密钥派生逻辑
class Keys {
    private static byte one = 116;
    private static byte[] ones = {-1, 0, 3, 5, 1, -5};

    static String keyDb() {
        byte[] b = new byte[ones.length + 3];
        for (int i = 0; i < ones.length; i++) b[i] = (byte)(one + ones[i]);
        b[ones.length] = '.'; b[ones.length + 1] = 'd'; b[ones.length + 2] = 'b';
        return new String(b); // "stwyuo.db"
    }

    static String keyBase() throws Exception {
        byte[] d = MessageDigest.getInstance("md5").digest(ones);
        StringBuilder sb = new StringBuilder();
        for (byte x : d) sb.append(String.format("%02x", x));
        return sb.substring(0, 6); // "c258ba"
    }
}
```

```python
import hashlib
ones = bytes((x & 0xff) for x in [-1, 0, 3, 5, 1, -5])
print(hashlib.md5(ones).hexdigest()[:6])  # c258ba
```

```sql
-- 用 SQLCipher 打开后查询
SELECT name, sql FROM sqlite_master WHERE type='table';
SELECT time, phone, gps_key, gps, data FROM picture;
```

PoC 为静态复现逻辑示意，未在本机执行；实际 KDF/页大小/迭代次数需与目标应用一致。

## 变体与关联

- 变体：密钥来自 `BuildConfig`、字符串资源、`SharedPreferences` 或 native `.so`（需 IDA/Frida 还原）；可能是 SHA-256、PBKDF2、Base64 或多段拼接。
- 变体：每个安装随机生成密钥并存放在 SharedPreferences/Keystore，此时静态分析只能拿到包裹后的密钥，需要结合设备数据或动态 Hook。
- 变体：SQLCipher 3 与 4 的默认 KDF 参数不同（页大小、迭代次数、HMAC 算法），用错参数会报 “file is not a database”。
- 关联卡片：[[defense-forensics-sqlcipher-im-db-memory-key-extraction]]（Windows IM 客户端从进程内存提取 SQLCipher 密钥）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（APK 脱壳与 jadx 分析）、[[mobile-android-anti-detection-root-emulator-proxy]]（Android 反检测环境）。
- 注意：手机取证涉及个人隐私，必须取得合法授权并遵守当地法律；本卡只描述静态分析与解密方法。

## 检测与防御

- 防御：不要把数据库密钥硬编码或仅用常量 MD5 派生；使用 Android Keystore 生成/保护每安装随机密钥，结合用户口令或服务端密钥。
- 防御：对密钥派生代码做混淆与完整性校验只能提高门槛，不能替代密钥管理；数据库加密应配合设备加密、应用沙箱与远程擦除。
- 检测（取证侧）：APK 中出现 `SQLCipher`、`openOrCreateDatabase`、`keyBase`、`MD5` 与静态字节数组组合；数据库文件头非 `SQLite format 3`；应用私有目录存在 `.db` + `-wal`/`-shm`。
- 检测（防御侧）：应用启动时对密钥派生函数做完整性校验；监控调试器/Frida 附加；对数据库文件做访问审计。
- 响应：确认数据库泄露范围，评估其中个人信息/凭据，按合规流程通知与轮换相关密钥。

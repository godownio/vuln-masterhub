---
id: mobile-android-multilevel-checker-frida-transform-chain
title: Android 多关卡校验逆向：Frida dump 8 关 target + 逐关自定义变换/流水线逆运算
type: scenario
domain: mobile
path: mobile/android
technique: multilevel-checker-frida-transform-chain
tags:
- mobile
- android
- reverse
- frida
- apk
- custom-cipher
- multistage
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:30+08:00'
  notes: 已对照原文核对：8 关 RuleRepository/AOp-BOp-COp-DOp-EOp、Frida dump target/answer_hash、Togepi/Psyduck key、各关逆变换（XOR/奇偶反转/去交错+ROR+XOR/AES-CBC/key1/key2）与逐关口令，和原文/截图一致；已修正 libpoke->libpokemon、DOp key/iv 为 .rodata 直接常量（原文 exp 直接使用 0x15A40/0x15A50）。未验证点：未本机复跑 APK；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/mobile/android/mobile-android-multilevel-checker-frida-transform-chain/
draft: false
kb_aliases:
- RuleRepository
- Badge 关卡
- AOp/BOp/COp/DOp/EOp
- Frida dump target
- 多关流水线
---

## 一句话结论

APK 用 8 个 badge 关卡，每关由 `RuleRepository` 返回一组 `Op` 对象对输入做变换并比对 target；用 Frida hook `ChallengeActivity.onCreate` 与 `RuleRepository.forBadge` 一次性 dump 全部 badge 的 `answer_hash`、`target` 与 `caseSensitive`，再按每关 Op 的逆变换（循环 XOR、奇偶位反转、去交错 + ROR + XOR、AES-CBC、key1/key2 XOR、以及多 Op 流水线）逐关解出口令，最后拼出终极 flag。

## 原理

- `RuleRepository.forBadge(int)` 按 badge 编号返回 `List<Op>`：1=AOp、2=BOp、3=COp、4=DOp、5=EOp、6=AOp+BOp+COp、7=BOp+COp+DOp、8=EOp+…（多 Op 流水线）；执行器 `Fl(all(Collection,...), null, true)` 依次调用每个 Op 的 `apply`。
- `Op` 各有独立可逆变换：
  - **AOp**：从 `res/raw/key.txt` 读取 key（本题 `Togepi`），`b[i] ^= key[i % len]`；逆变换同 XOR。
  - **BOp/COp**：把十六进制串的偶数下标字符整体反转（`reverseEvenPositions`/`reverseOddPositionsBased`）；逆变换是同一置换再做一次。
  - **Level3 nativeProcess（libpokemon）**：读取 `res/raw/key2.txt`（`Psyduck`），去交错（奇偶列反转）→ 每字节右旋 `(i*3)%8` → 循环 XOR key2，并在尾部加 2 位校验和；逆变换按相反顺序。
  - **DOp**：AES/CBC/PKCS5Padding，key/iv 由 JNI `nativeGetKey`/`nativeGetIv` 返回（`.rodata` 中的 16 字节常量，native 函数直接返回）；逆变换为 AES 解密。
  - **EOp**：`key1 = bytes((KEY1_P1[i]&0xff) ^ (KEY1_P2[i]&0xff))`、`key2 = b"sQVSUVUd"`；逆序：反转 → 去交错 → XOR key2 → 反转 → XOR key1。
- **多 Op 流水线**：关卡 6/7/8 把多个 Op 串起来，解密时按 `List<Op>` 的逆序逐个撤销；每步都要保持编码（hex/ASCII/字节）一致。
- Frida hook 的价值：`RuleRepository` 里有每关的 `target` 与 `caseSensitive`，`ChallengeActivity` intent 里有 `badge_id/badge_name/answer_hash`；直接打印即可跳过哈希/校验逻辑，专注于逆变换。

## 触发条件

- APK 使用 badge/关卡式校验，规则对象（target/op 列表）在运行时可见。
- 可运行 Frida（root/可调试 APK）或能静态导出 RuleRepository 数据。
- 每关 Op 是可逆变换（XOR、置换、旋转、AES），且能拿到 target。
- 各关口令/最终 flag 由字符串拼接或逐关提交得到。

## 利用步骤

1. 用 jadx 找 `ChallengeActivity`、`RuleRepository`、`Op` 子类（AOp~EOp）与 `SuccessDialogFragment`。
2. 写 Frida 脚本 hook `ChallengeActivity.onCreate(Bundle)` 与 `RuleRepository.forBadge(int)`，打印 `badge_id/name/answer_hash/target/caseSensitive`。
3. 逐个 badge 进入关卡（或直接调用 `forBadge`），收集 8 组 target。
4. 按 Op 子类实现逆变换；对多 Op 关卡按列表逆序应用。
5. 用每关解出的口令触发 SuccessDialog，最后按题目要求拼接/提交终极 flag。

## PoC

```javascript
Java.perform(() => {
  const Challenge = Java.use('com.example.pokemon.ChallengeActivity');
  const Repo = Java.use('com.example.pokemon.verifier.RuleRepository');
  Challenge.onCreate.overload('android.os.Bundle').implementation = function (b) {
    this.onCreate(b);
    const it = this.getIntent();
    console.log('[Intent]', 'badge_id=', it.getIntExtra('badge_id', -1),
      'badge_name=', it.getStringExtra('badge_name'),
      'answer_hash=', it.getStringExtra('answer_hash'));
  };
  Repo.forBadge.overload('int').implementation = function (id) {
    const r = this.forBadge(id);
    console.log('[Rule]', 'id=', id, 'caseSensitive=', r.caseSensitive.value,
      'target=', r.target.value);
    return r;
  };
});
```

```python
KEY1_P1 = [115, 8, 90, 16, 48, 72, -18, 17]
KEY1_P2 = [16, 63, 39, 114, 15, 51, -86, 65]
key1 = bytes(((a & 0xff) ^ (b & 0xff)) for a, b in zip(KEY1_P1, KEY1_P2))
key2 = b"sQVSUVUd"

def ror8(x, r):
    r &= 7
    return ((x >> r) | ((x << (8 - r)) & 0xff)) & 0xff

def deinterleave(hp):
    od_rev, ev_rev = hp[0::2], hp[1::2]
    od, ev = od_rev[::-1], ev_rev[::-1]
    out, ie, io = [], 0, 0
    for i in range(len(hp)):
        if i % 2 == 0:
            out.append(ev[ie]); ie += 1
        else:
            out.append(od[io]); io += 1
    return ''.join(out)

# level5: 反转 -> 去交错 -> XOR key2 -> 反转 -> XOR key1
hp = cipher[::-1]
b = bytearray(bytes.fromhex(deinterleave(hp)))
for i in range(len(b)): b[i] ^= key2[i % len(key2)]
b.reverse()
for i in range(len(b)): b[i] ^= key1[i % len(key1)]
print(b.decode())
```

说明：各关 target/密文从 Frida 输出替换；AES 关使用 native 返回的 key/iv，按 CBC+PKCS5 解密后再继续逆 Op。未在本机复跑原 APK。

## 变体与关联

- **单关自定义变换**：若只有一关，直接按 Op 逆变换；多关的难点是编码/流水线顺序。
- **Frida 批量 dump**：同类 badge/规则系统可用 `Java.choose` 枚举所有 `Op` 实例，避免逐关进入。
- **JNI 加密**：Level3/4 的 key 来自 so；见 [[mobile-android-jni-xxtea-blocktea-aes-sbox-multilayer]]。
- **AES 固定 key/iv**：Android 题常用 native 返回 key/iv + CBC；见 [[mobile-android-aes-random-key-hook-fixed-iv-decrypt]]。

## 检测与防御

- 检测：APK 中存在 badge/关卡规则表、多个 Op 子类、target 常量；Frida 可 hook 到 RuleRepository。
- 分析：先 dump 规则与 target，再按 Op 类型逐个实现逆函数；注意 hex/字节/字符串编码。
- 防御（对恶意样本）：不要把校验目标放在可被 hook 的 Java 对象中；关键校验下沉到 native 并做完整性/反调试。

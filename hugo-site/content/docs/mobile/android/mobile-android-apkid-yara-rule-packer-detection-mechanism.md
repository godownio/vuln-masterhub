---
id: mobile-android-apkid-yara-rule-packer-detection-mechanism
title: APKiD 壳检测机制：is_apk 通用规则 + 壳特征文件 Yara 规则 + zip 成员二次扫描，可自写规则扩充加固识别
type: scenario
domain: mobile
path: mobile/android
technique: apkid-yara-rule-apk-packer-identification
tags:
- android
- apk
- packer
- yara
- apkid
- reverse
- detection
- tencent-legu
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V664
  verified_at: '2026-11-13T08:20:10+08:00'
  notes: 已对照原文与10张图逐张核对：img01/02 BlackHat 两个议题（PEiD for Android / Fast Identification of Mobile RASP SDKs）、img03 APKiD 2.1.5 CLI 输出（packer Tencent's Legu；classes.dex anti_disassembly non-zero link offset/size、compiler dexlib 2.x、packer Mobile Tencent Protect）与卡内 PoC 完全一致、img06 rules 目录树与 tencent_legu 规则源码、img07 assets 下 dexopt/ 与 0OO00l111l1l、o0oooOO0ooOo.dat、tosversion、img08/09 PK 50 4B 03 04 文件头与 AndroidManifest.xml 找到2次、img10 工作流（Unpacks files in ZIP/Read magic numbers/Apply Yara rules/Print results）均一致。修正：『所有壳规则 condition 都以 is_apk 为前提』改为『APK 层壳规则』（dex/elf 规则并不用 is_apk）；『dexopt/0OO00l111l1l』改为 assets 下 dexopt/ 目录与 0OO00l111l1l 并列（截图如此）。与既有 APKiD 脱壳卡 mobile-android-packer-apkid-frida-dexdump-jadx（使用流程）差异已在卡内关联与 dedup_review 写清（本卡为工具实现/规则编写视角），判 related/new。原文无受影响版本，affected_versions 保持 null。未验证点：未本地跑 APKiD 复现。
url: /docs/mobile/android/mobile-android-apkid-yara-rule-packer-detection-mechanism/
draft: false
kb_aliases:
- APKiD 原理
- APK 查壳
- Yara 规则识别加固
- is_apk 规则
- tencent_legu 规则
- APK packer detection
- APKiD 2.1.5
---

## 一句话结论

APKiD（"Android 版 PEiD"）本质是一个 Yara 规则驱动的 APK 特征扫描器：先用通用 `is_apk` 规则确认目标是 APK（文件头 `PK` 且 `AndroidManifest.xml` 出现 ≥2 次），再用 `packers/protectors/obfuscators/anti-vm` 等规则匹配 `assets/`、`lib/`、`classes.dex` 中的特征文件/字符串——如腾讯乐固规则要求 `assets/0OO00l111l1l` 存在且 `assets/tosversion`、`assets/0OO00oo01l1l`、`assets/o0oooOO0ooOo.dat` 之一命中；Scanner 先对整文件跑 `rules.match`，发现是 zip 再解压对 `classes* / AndroidManifest.xml / lib/ / *.so / *.dex / *.apk` 逐个成员扫描。理解规则结构后即可自写/扩充壳检测（原文用同一思路对比了 ApkDetecter 的文件名关键字字典）。

## 原理

- **APK = ZIP**：APK 是 zip 容器，包含 `META-INF/`（签名）、`lib/<abi>/*.so`、`assets/`、`AndroidManifest.xml`、`classes.dex`、`resources.arsc` 等。加固壳会在 APK 中留下特征文件（如腾讯乐固的 `assets/0OO00l111l1l`、`tosversion`、`o0oooOO0ooOo.dat`），或改写 `classes.dex`（如 dexlib 编译特征、非零 link offset/size 的 anti-disassembly）。
- **Yara 规则三要素**：每条规则由 `meta`（描述/URL/样本哈希/作者）、`strings`（要匹配的字符串或字节）、`condition`（布尔表达式）组成。APKiD 的规则按类型放在 `rules/apk/common.yara`、`packers.yara`、`protectors.yara`、`obfuscators.yara`、`rules/dex/*`、`rules/elf/*`，`prep-release.py` 会编译成 `rules.yarc`。
- **通用 is_apk 规则**：`rule is_apk : file_type { strings: $zip_head = "PK" $manifest = "AndroidManifest.xml" condition: $zip_head at 0 and $manifest and #manifest >= 2 }`——文件头为 `50 4B 03 04`（PK），且文件中 `AndroidManifest.xml` 字符串至少出现 2 次（zip 目录项 + 文件内容），避免把普通 zip 误判为 APK。APK 层的壳规则 condition 以 `is_apk` 为前提（原文示例 tencent_legu 即如此）。
- **腾讯乐固规则**：`rule tencent_legu : packer` 的 strings 为 `assets/tosversion`、`assets/0OO00l111l1l`、`assets/0OO00oo01l1l`、`assets/o0oooOO0ooOo.dat`，condition 要求 `is_apk and $b and ($a or $c or $d)`——即强特征 `assets/0OO00l111l1l` 必须存在，其余之一命中。打开加壳样本的 assets 目录可见 `dexopt/` 目录以及 `0OO00l111l1l`、`o0oooOO0ooOo.dat`、`tosversion` 等文件，与规则完全对应。
- **Scanner 工作流**：`scan_file_obj` 先 `self.rules.match(data=file.read())` 对整文件匹配；若 `_is_zipfile` 则认为 APK/zip，`_scan_zip` 解压后对每个成员判断 `_should_scan`（filename 模式下：以 `classes`/`AndroidManifest.xml`/`lib/` 开头，或以 `.so`/`.dex`/`.apk` 结尾）再匹配，结果以 `file_path!entry_name` 记录。因此既能命中 zip 目录层（如 assets 文件名），也能命中 dex/so 内部特征。
- **为什么有效/局限**：壳特征文件与 dex 结构特征稳定、易规则化，适合快速识别厂商与保护类型（packer/protector/compiler/anti_debug/anti_hook）；但规则是"已知特征黑名单"，厂商只需换壳/删特征文件/自定义壳即可 miss（假阴性），不能替代实际脱壳分析。

## 触发条件

- 拿到待分析的 APK（无需安装运行），需要快速判断是否加壳、哪家厂商、编译器/保护类型，以决定后续逆向路线。
- APKiD 版本与规则库覆盖目标壳的特征（文中为 APKiD 2.1.5）。

## 利用步骤

1. 安装：`pip install apkid`（或 `git clone` 源码后 `./prep-release.py` 生成 `rules.yarc`，便于断点调试和改规则）。
2. 命令行扫描：`apkid target.apk`，输出按文件/成员分组：`packer : Tencent's Legu`、`classes.dex -> anti_disassembly : non-zero link offset, non-zero link size`、`compiler : dexlib 2.x`、`packer : Mobile Tencent Protect`。
3. Python API 扫描（便于集成）：`Options(json=True)` → `options.rules_manager.load()` → `Scanner(rules, options).scan(apk_path)`。
4. 结论用于选型：识别到壳/保护后，选择对应脱壳方式（如 frida-dexdump 内存 dump，见关联卡）；识别到 compiler/dexlib 特征可辅助判断真实 dex 的编译器。
5. 扩充规则：在 `rules/apk/packers.yara` 仿照 tencent_legu 增加新厂商的特征文件/字符串，重跑 `prep-release.py`；也可参考 ApkDetecter 的字典式检测（`self.protectflag_dict = {"libsecexe.so": "梆梆加固", "libprotectClass.so": "360加固", ...}` + 文件名包含判断 + `key.dat`/`apkprotect.com` 组合条件）。

## PoC

```bash
pip install apkid
apkid ./tmp/litiaotiao.apk
# [*] ./tmp/litiaotiao.apk
#  |-> packer : Tencent's Legu
# [*] ./tmp/litiaotiao.apk!classes.dex
#  |-> anti_disassembly : non-zero link offset, non-zero link size
#  |-> compiler : dexlib 2.x
#  |-> packer : Mobile Tencent Protect
```

```python
from apkid.apkid import Options, Scanner
options = Options(json=True)
rules = options.rules_manager.load()
scanner = Scanner(rules, options)
scanner.scan("./tmp/litiaotiao.apk")
```

```yara
rule tencent_legu : packer
{
  meta:
    description = "Tencent's Legu"
  strings:
    $a = "assets/tosversion"
    $b = "assets/0OO00l111l1l"
    $c = "assets/0OO00oo01l1l"
    $d = "assets/o0oooOO0ooOo.dat"
  condition:
    is_apk and $b and ($a or $c or $d)
}
```

## 变体与关联

- 关联：[[mobile-android-packer-apkid-frida-dexdump-jadx]]（APKiD 识别壳后 frida-dexdump 内存 dump + jadx/apktool 审计的完整脱壳流程；本卡补充其"APKiD 为什么能识别"的规则机制）。
- 关联：defense/detection 下的 Yara 规则编写卡（内存/样本特征扫描）——同一 Yara 方法在不同载体的应用。
- 变体：其他查壳工具采用字典/文件名匹配（ApkDetecter）而非 Yara，特征更新方式不同；商业壳（梆梆、360、爱加密、娜迦、阿里、百度、通付盾等）各有对应 so/dat 特征文件。
- 边界：加壳样本的 assets/dex 可被定制修改以躲避规则；APKiD 结果需与运行时行为（脱壳后 dex）交叉验证。

## 检测与防御

- 用途定位：APKiD 属于分析/检测工具，本身不是攻击手法；对防守方可用于批量识别 App 是否加壳、评估加固覆盖面。
- 规则维护：关注新壳特征文件/字符串、dex/so 结构变化，定期更新规则库并做误报/漏报回归（is_apk 规则避免普通 zip 误报）。
- 对抗提示：仅依赖特征文件的检测可被删特征、换壳绕过；高价值场景应结合运行时脱壳与代码审计。

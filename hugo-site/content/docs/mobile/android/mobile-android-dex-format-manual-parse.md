---
id: mobile-android-dex-format-manual-parse
title: DEX 结构手工解析：按 header 偏移定位 string/type/proto/field/method 与 class_defs
type: scenario
domain: mobile
path: mobile/android
technique: dex-format-manual-parse
tags:
- android
- dex
- reverse-engineering
- file-format
- uleb128
- apk
- parsing
- dexlib2
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V228
  verified_at: '2026-11-07T07:07:03+08:00'
  notes: 已对照原文与41张图核对：header各段size/off（string 29/type 9/proto 7/field 3/method 10/class 1）、string_id[0]=<clinit>@0x2DA、type/proto/field/method/class_def逐级解析与dexlib2示例输出（HelloWorld2/static String b/int a/<clinit>/<init>/main/getNumber）均一致；卡已注明string_ids_size等为u4（原文“占1字节”为笔误）。未验证点：未用样本执行卡内Python片段；frontmatter无sources/source_url；无版本。
url: /docs/mobile/android/mobile-android-dex-format-manual-parse/
draft: false
kb_aliases:
- DEX 文件结构解析
- DexHeader 手工解析
- dex_string_ids
- dex_class_defs
- class_data_item 解析
- ULEB128 DEX
- dexlib2 读取 DEX
---

## 一句话结论

DEX 是 Android 的 Dalvik/ART 可执行文件，其头部按固定偏移存有各索引段的 `size`/`off`；按 `header → string_ids → type_ids → proto_ids → field_ids → method_ids → class_defs → class_data_item → code_item` 逐级解引用，即可在没有 jadx 的情况下定位任意类、字段、方法及其字节码偏移，用于 APK 逆向、加固/混淆分析和工具失效时的手工核对。

## 原理

- DEX 整体采用小端存储，文件以 `magic`（`dex\n035\0` 等）开头，随后是 `checksum`（u4，Adler-32，不含 magic 与自身）、`signature`（20 字节 SHA-1）、`file_size`、`header_size`（通常 `0x70`）、`endian_tag`（通常 `0x12345678`）。
- `header_item` 之后依次给出各段的条目数量与文件偏移：`string_ids`、`type_ids`、`proto_ids`、`field_ids`、`method_ids`、`class_defs`，以及 `data_size`/`data_off`；`map_off` 指向 `map_list`，可用于交叉验证各段范围。
- `string_id_item` 只有一个 u4 `string_data_off`，指向 `string_data_item`：ULEB128 编码的 `utf16_size`（UTF-16 码元数，不是字节数）+ MUTF-8 数据 + 0 结尾。`type_id_item.descriptor_idx` 指向字符串表，得到 `I`、`Ljava/lang/String;` 等类型描述符。
- `proto_id_item` 由 `shorty_idx`（短描述符，如 `III`）、`return_type_idx`、`parameters_off`（指向 `type_list`：u4 size + u2 type_idx 数组）组成；`field_id_item` 为 `class_idx`/`type_idx`/`name_idx`；`method_id_item` 为 `class_idx`/`proto_idx`/`name_idx`。
- `class_def_item` 包含 `class_idx`、`access_flags`、`superclass_idx`、`interfaces_off`、`source_file_idx`、`annotations_off`、`class_data_off`、`static_values_off`；`class_data_off` 指向 `class_data_item`，其中四个 ULEB128 计数后跟 `encoded_field`/`encoded_method` 数组。
- `encoded_field` 为 `field_idx_diff`（与前一字段索引的差值）+ `access_flags`；`encoded_method` 为 `method_idx_diff` + `access_flags` + `code_off`；`code_off` 指向 `code_item`（`registers_size`/`ins_size`/`outs_size`/`tries_size`/`debug_info_off`/`insns_size`/`insns[]`），即真正的 Dalvik 字节码。
- 索引差值是 DEX 压缩体积的关键：字段/方法列表按索引升序排列，只存相邻差值；解析时必须累加还原绝对索引。

## 触发条件

- 已获取 `classes.dex`（从 APK 解包或加固脱壳得到），需要枚举类/字段/方法、定位方法字节码，或核验加固/混淆后的 DEX 是否被篡改。
- 反编译工具（jadx、baksmali）失败、结果不可信，或需要绕过其解析限制时，可手工按结构解析。
- 需要理解 `checksum`/`signature` 与 `header` 字段以做完整性校验或修改后重算。

## 利用步骤

1. 确认文件头：前 8 字节为 `dex\n035\0`（其他版本可能是 036/037/038/039），`header_size` 应为 `0x70`，`endian_tag` 为 `0x12345678`。
2. 从固定偏移读取各段数量与偏移：`string_ids`（0x38/0x3C）、`type_ids`（0x40/0x44）、`proto_ids`（0x48/0x4C）、`field_ids`（0x50/0x54）、`method_ids`（0x58/0x5C）、`class_defs`（0x60/0x64）。
3. 解析字符串表：每个 `string_id` 是 u4 偏移，跳到 `string_data_item` 先读 ULEB128 `utf16_size`，再按 MUTF-8 读取字符串。
4. 解析类型/原型/字段/方法：按索引到 `string_ids` 取描述符与名称，按 `parameters_off` 读 `type_list` 还原参数类型。
5. 解析类定义：由 `class_def.class_data_off` 进入 `class_data_item`，依次读取 static/instance 字段与 direct/virtual 方法的差值索引和访问标志；`code_off` 非 0 时进入 `code_item` 取字节码。
6. 交叉验证：用 `map_off` 指向的 `map_list` 检查各段起止偏移是否与 header 一致；修改 DEX 后需重算 `checksum` 与 SHA-1 `signature`（若目标校验它们）。
7. 自动化可用 dexlib2：`DexFileFactory.loadDexFile(file, Opcodes.forApi(19))` 后遍历 `getClasses()`、`getFields()`、`getMethods()`，避免手写全部结构。

## PoC

最小手工解析片段（Python，读取 header 与字符串表；仅用于自有样本分析）：

```python
import struct

d = open("classes.dex", "rb").read()
assert d[:8] == b"dex\n035\0"

def u4(off):
    return struct.unpack_from("<I", d, off)[0]

def uleb(off):
    result = shift = 0
    while True:
        b = d[off]; off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7

print("file_size", hex(u4(0x20)), "header_size", hex(u4(0x24)))
strings_size, strings_off = u4(0x38), u4(0x3C)
type_size, type_off = u4(0x40), u4(0x44)
proto_size, proto_off = u4(0x48), u4(0x4C)
field_size, field_off = u4(0x50), u4(0x54)
method_size, method_off = u4(0x58), u4(0x5C)
class_size, class_off = u4(0x60), u4(0x64)
print(strings_size, type_size, proto_size, field_size, method_size, class_size)

for i in range(strings_size):
    size, data = uleb(u4(strings_off + i * 4))
    # 样例字符串均为 ASCII；非 ASCII 需按 MUTF-8 解码，size 是 UTF-16 码元数而非字节数
    print(i, d[data:data + size].decode("utf-8", "replace"))
```

完整读取类/字段/方法可参考 dexlib2 的 `DexFileFactory.loadDexFile` + `ClassDef.getFields()`/`getMethods()`；原文样例输出可正确还原 `HelloWorld2` 的 `static String b`、`int a` 与 `<clinit>`/`<init>`/`main`/`getNumber`。

## 变体与关联

- **多 DEX**：APK 中可能存在 `classes2.dex`、`classes3.dex` 等，需逐个按同样方式解析；加固应用可能在运行时才解密出真实 DEX。
- **DEX 版本**：magic 中的版本号会变化（035/036/037/038/039），头部字段布局基本一致，但新版本可能增加特性；`endian_tag` 可标记反向端序。
- **加固/壳**：第一代壳常把 DEX 加密藏在 assets，运行时 `attachBaseContext` 解密并替换 `mClassLoader`；手工解析可用于核对脱壳产物是否完整。
- **关联**：与 APK 字符串混淆还原、DEX 加固脱壳、JNI 逆向等卡配合；解析 `code_item` 后可用 baksmali/IDA 进一步反汇编。

## 检测与防御

- **本卡性质**：属于 APK/DEX 逆向分析基础技巧，不是可直接利用的漏洞；防御重点是提高逆向成本与完整性校验。
- **加固**：使用商业壳/DEX 加密、字符串加密、类名与方法名混淆、控制流平坦化，避免真实 DEX 以明文落在 APK 中。
- **完整性**：应用启动时校验 DEX `checksum`/`signature` 或签名证书，检测重打包与二次修改；服务端结合签名校验与风控。
- **检测**：监控异常的 APK 解包/重打包、DEX 修改后重算校验值、调试器附加与内存 dump 行为。

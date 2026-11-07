---
id: code-analysis-reverse-linux-cpp-stl-container-layout-disassembly
title: C++ STL 容器内存布局与反汇编识别：string SSO、vector 三指针、map 红黑树、unordered_map 桶数组
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: cpp-stl-container-layout-disassembly-identification
tags:
- reverse-engineering
- cpp
- stl
- libstdc++
- disassembly
- memory-layout
- gdb
- binary-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:57:33+08:00'
  notes: 已对照原文与7张图核对：图01确认 string 0x20、指针/长度/SSO；图02确认 vector 0x18 三指针；图03确认 vector<string> 连续 0x20 元素；图04确认 map 红黑树哨兵；图05-07确认 unordered_map 13 桶及 bucket 3/6/12。布局描述与 libstdc++ 一致；示例地址非通用常量，卡内已声明。未运行代码
url: /docs/code-analysis/reverse/linux/code-analysis-reverse-linux-cpp-stl-container-layout-disassembly/
draft: false
kb_aliases:
- STL 容器内存布局
- std::string 布局
- std::vector 布局
- std::map 红黑树
- std::unordered_map 哈希桶
- C++ 反汇编
- libstdc++ ABI
---

## 一句话结论

libstdc++ 的常用容器在 x86-64 下有一套稳定的内存布局：`std::string` 为 0x20 字节（数据指针 + 长度 + 16 字节 SSO/容量）、`std::vector` 为 0x18 字节（begin/end/capacity 三指针）、`std::map` 为红黑树（哨兵节点 + 节点计数，节点内是 `pair<const Key,T>`）、`std::unordered_map` 为桶数组指针 + 桶数/模数 + 元素链表；在 IDA 反汇编中识别这些构造/访问函数与栈上对象大小，就能还原 C++ 对象的字段、迭代器语义和潜在的越界/类型混淆点。

## 原理

- **Itanium C++ ABI 的朴素布局**：GCC/libstdc++ 在 x86-64 上按字段顺序布局，不做额外的句柄/间接层；对象多按 8 字节对齐。因此反汇编里看到连续的 `_QWORD`/`_BYTE` 数组，往往就是某个容器的完整对象。
- **std::string（0x20 字节）**：
  - `+0x00`：`char *` 数据指针；
  - `+0x08`：`size_t` 字符串长度；
  - `+0x10`：16 字节的联合体——短字符串时是 SSO 内联缓冲区，长字符串时是 `capacity`。
  - libstdc++ 的 SSO 阈值为 15 字节：`size <= 15` 时数据指针指向 `this+0x10`，不分配堆；超过才 `operator new`，此时 `+0x10` 为容量。gdb 中可直接看到短字符串对象的指针指向自身 +0x10，长字符串指针指向堆地址、第三 qword 与长度相同或更大。
  - 反汇编特征：频繁调用 `std::string::basic_string<std::allocator<char>>(this, "literal", &alloc)`；析构调用 `std::string::~string`；`operator[]`、`find`、`compare` 等以对象地址为首参。
- **std::vector（0x18 字节）**：
  - `+0x00`：`begin`（首元素地址）；
  - `+0x08`：`end`（最后一个有效元素的下一个位置）；
  - `+0x10`：`capacity_end`（已分配内存末尾）。
  - `size() = (end - begin) / sizeof(T)`，`capacity() = (cap - begin) / sizeof(T)`；空 vector 三个指针全为 0。`vector<string>` 的元素是连续的 0x20 字节 string 对象，不是指针数组；gdb 中可以看到相邻 string 的指针/长度字段。
  - 反汇编特征：`std::vector<int>::vector(this, count, value)`、`std::vector<T>::vector(this, first, last)`、`std::move`、`begin/end` 调用；构造后常出现 `__new_allocator<T>::~__new_allocator`（临时 allocator 参数）。
- **std::map（红黑树）**：
  - map 对象通常 0x30 字节（视 ABI/比较器是否为空），核心是 `_Rb_tree_node_base` 哨兵：颜色（4 字节 + padding）、`parent`、`left`、`right` 三个指针；其后是节点计数（`size()` 的缓存）。
  - 每个节点由 `_Rb_tree_node_base`（约 0x20 字节）+ `pair<const Key, T>` 组成；`map<string,int>` 的 `pair` 为 0x28 字节（0x20 的 string + 4 字节 int + padding），因此 `it->second` 在 `pair` 基址 + 0x20，节点总大小约 0x48（以实际 ABI 为准）。
  - `begin()` 返回最左节点，`end()` 返回哨兵；迭代器本质是指向节点的指针，`it->first/second` 通过节点内 `pair` 偏移访问。gdb 中可看到哨兵的 parent 指向根、left 指向最小节点、right 指向最大节点，节点计数与插入数量一致。
  - 反汇编特征：`std::map<K,V>::insert(this, pair*)` 先构造 `std::pair` 再插入；`emplace` 原地构造、少一次 pair 拷贝；`operator[]` 返回 value 引用（不存在则插入默认值）；`find` 返回迭代器再与 `end()` 比较；范围构造先取 `begin/end` 再建树。
- **std::unordered_map（哈希表）**：
  - 对象前几个字段（libstdc++ 示意）：`+0x00` 桶数组指针、`+0x08` 桶数（质数模数，默认 13）、`+0x10` 指向首节点的指针（before_begin/链表头）、`+0x18` 元素计数；后续还有 rehash 策略、hash、key_equal、allocator 等。
  - 桶数组是 `_Hash_node*` 数组；每个桶是一条单链表，插入在链表头（LIFO，类似 glibc fastbin）。`bucket(key)` 用 `hash(key) % bucket_count` 定位桶；`bucket_size(n)` 返回该桶元素数；`begin(n)/end(n)` 是桶内局部迭代器。
  - 扩容：`_Prime_rehash_policy` 默认 `max_load_factor=1.0`，元素总数超过 `bucket_count` 时 rehash 到下一个质数（13 → 29 → 59 …），所有元素按新模数重新分桶；`reserve(n)` 可预分配，避免频繁 rehash。
  - 反汇编特征：`std::unordered_map<K,V>::insert/emplace/operator[]/find/bucket/bucket_size/begin/end`，以及 `std::__detail::_Local_iterator<...>` 类型；`std::copy` 从局部迭代器复制到 `std::pair*` 输出时，元素按 `pair` 大小连续写入。
- **为什么这些布局对漏洞分析重要**：知道对象大小就能在栈帧中定位容器；知道字段顺序就能把 IDA 的扁平 `_QWORD` 还原为结构体；知道迭代器/`operator[]` 语义就能识别“返回引用后写入”“按 bucket_size 复制”“按 size 读取”等危险模式；知道 SSO/堆分配边界就能判断输入多长会触发堆操作。

## 触发条件

- 目标是 x86-64 Linux、使用 GCC/libstdc++（Itanium ABI）编译的 C++ 程序；静态链接或动态链接均可，但需能定位 libstdc++ 符号或识别其调用签名。
- 有 IDA/Ghidra 等反汇编器与 gdb/pwndbg 调试环境；能在关键构造/访问处下断点观察内存。
- 容器类型与元素类型已知或可从调用签名推断（如 `map<string,int>`、`unordered_map<unsigned int,unsigned long>`）。
- 布局随 libstdc++ 版本、`_GLIBCXX_USE_CXX11_ABI`、编译器优化、32/64 位而变化；使用前需在目标二进制/库上核对。

## 利用步骤

1. **定位容器构造**：在 `main` 或业务函数中搜索 `basic_string`、`vector<...>::vector`、`map<...>::map`、`unordered_map<...>::unordered_map` 调用；第一个参数通常是栈上的对象地址，IDA 会把它显示为 `_BYTE vN[32]`（string）、`_QWORD vN[3]`（vector）、`_QWORD vN[6]`（map）等。
2. **确定对象大小与生命周期**：观察连续对象在栈帧中的间距（string 0x20、vector 0x18、map 约 0x30、unordered_map 约 0x40），以及析构调用顺序（逆序析构）。
3. **gdb 断点观察字段**：在构造后/插入后 `tele` 或 `x/` 查看内存；对照本文的字段偏移确认指针、长度、容量、桶数、桶数组内容。短字符串检查数据指针是否指向对象内部（SSO），长字符串检查是否指向堆。
4. **还原 IDA 结构体**：按容器类型建立 local type（string/vector/map/unordered_map），把 `v4 + 32` 这类偏移标注为 `it->second` 或 pair 字段，提升伪代码可读性。
5. **识别危险访问模式**：重点看 `bucket_size()` 的结果是否被用作 `std::copy`/`memcpy` 的长度而目标缓冲区固定；`operator[]` 是否在未检查存在性时写入；`size()`/`capacity()` 是否被用于循环边界；迭代器是否在插入/删除后继续使用。
6. **用于漏洞利用**：由布局推出对象大小、可控字段和越界距离（例如 unordered_map 单桶复制到栈缓冲区的元素数 × pair 大小），再设计溢出/类型混淆链（见 [[binary-pwn-stack-unordered-map-bucket-copy-stack-overflow]]）。

## PoC

最小 C++ 样例与 gdb 观察（不执行）：

```cpp
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
int main() {
    std::string s = "12345678901234";           // 14 字节，SSO
    std::string l(0x20, 'a');                   // 32 字节，堆
    std::vector<int> v(10, 42);                 // begin/end/cap
    std::map<std::string,int> m; m["aa"] = 1;   // 红黑树
    std::unordered_map<unsigned int,unsigned long> u;
    for (unsigned i = 0; i < 14; i++) u[1 + i * 29] = i;  // 触发 13→29 rehash
}
```

```gdb
# string：对象地址 +0x0 指针、+0x8 长度、+0x10 SSO/容量
tele 0x7fffffffd9a0
# vector：三个 qword 分别是 begin/end/cap
x/3gx 0x7fffffffd9c0
# map：哨兵 color/parent/left/right + 节点计数
x/6gx 0x7fffffffd9e0
# unordered_map：桶数组指针、bucket_count、链表头、元素数
x/4gx 0x7fffffffda20
# 桶数组内容：bucket_count 个 _Hash_node*
x/13gx *(void**)0x7fffffffda20
```

原文用 pwndbg 的 `tele` 展示了六种 string 构造、vector 的 begin/end/cap、`vector<string>` 的连续 0x20 字节元素、map 哨兵的 parent/left/right 与元素数 3、unordered_map 的 13 个桶及第 3/6/12 个桶中的链表；本卡不执行代码。

## 变体与关联

- **libc++（LLVM）**：`std::string` 布局与 SSO 阈值不同（通常 24 字节、22 字符 SSO），`unordered_map` 实现也不同；不能直接套用 libstdc++ 偏移。
- **MSVC STL**：string 为 32 字节（16 字节联合 + size + capacity），vector 仍为三指针，map/unordered_map 结构不同；Windows 逆向需另建模型。
- **32 位与调试模式**：指针/长度为 4 字节，对象大小减半；`_GLIBCXX_DEBUG` 会改变容器布局；自定义 allocator/hash/比较器会增加字段。
- **C++11 ABI 切换**：`_GLIBCXX_USE_CXX11_ABI=0` 的旧 string 是非 SSO 的写时复制实现，布局与本文不同。
- **关联**：[[binary-pwn-stack-unordered-map-bucket-copy-stack-overflow]]（利用 unordered_map 单桶复制造成栈溢出）、[[code-analysis-reverse-linux-protobuf-c-descriptor-recovery]]（另一种 C/C++ 结构逆向）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（C++ 对象/虚表利用）。
- **边界**：本卡是布局识别与反汇编阅读方法，不是漏洞本身；具体偏移必须以目标 libstdc++ 版本和编译器实测为准，不能把示例地址/大小当常量。

## 检测与防御

- **对防御方**：容器布局不是安全边界，不能依赖“符号剥离/优化”阻止逆向；应使用栈保护、ASLR/PIE、CFI、`FORTIFY_SOURCE`、现代编译器加固，并修复真正的越界/未检查长度问题。
- **代码审计**：重点检查把 `bucket_size()`、`size()`、`capacity()` 直接作为 `memcpy`/`std::copy` 长度且目标是固定栈数组的代码；检查 `operator[]` 在不可信键上的隐式插入；检查迭代器失效后继续使用。
- **检测**：崩溃/ASAN 报告中的栈溢出或堆越界；反汇编中异常的 `std::copy` 到栈缓冲区；C++ 容器对象附近出现越界写入。测试环境启用 ASAN/UBSAN、`_GLIBCXX_ASSERTIONS` 可在开发期提前暴露。
- **缓解**：对不可信键的哈希表使用带随机种子的哈希（如 `std::hash` 的加盐封装）可提高攻击者预测桶分布的难度，但不能替代边界检查；对桶遍历复制使用动态扩容容器并校验目标容量。

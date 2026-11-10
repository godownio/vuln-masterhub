---
id: defense-detection-fnv1a-project-id-bruteforce-attribution
title: 活动 ID 归因：FNV-1a 32 位哈希暴力破解 IcedID Project ID，还原汽车/品牌/NATO 主题词并关联威胁行为者
type: scenario
domain: defense
path: defense/detection
technique: fnv1a-project-id-bruteforce-attribution
tags:
- defense
- detection
- threat-intelligence
- attribution
- fnv1a
- icedid
- latrodectus
- campaign-id
- project-id
- clustering
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V461
  verified_at: '2026-11-10T14:05:09+08:00'
  notes: 已对照原文核对：原文 Project ID 表 23 项用标准 FNV-1a 复算全部命中（Cherry 实为 Chevy 品牌 Chery 拼写）；Supted 注释与 group=510584660 不一致已在卡内作为边界说明；未验证点：主题到 TA 映射为厂商评估。dup-scan.json 早于建卡，无涉及本卡 pair。
url: /docs/defense/detection/defense-detection-fnv1a-project-id-bruteforce-attribution/
draft: false
kb_aliases:
- FNV-1a 活动 ID 破解
- IcedID Project ID 还原
- Latrodectus group 字段
- 活动 ID 主题归因
- TA578 汽车主题
- TA551 NATO 字母
- 恶意样本归因
---

## 一句话结论

IcedID bot 配置中的数字 `ProjectID`、Latrodectus 回连字段 `group` 都是活动/项目名字符串的 **FNV-1a 32 位哈希**（初始值 `0x811c9dc5`、乘数 `0x01000193`）；哈希虽不可逆，但活动名是低熵的人选词，用汽车品牌、城市/地名、NATO 字母、意大利语等主题词表暴力枚举即可还原（如 `Pontiac=1501064257`、`Hyundai=2262657793`），再按主题把活动聚类并辅助归因到 TA578/TA544/TA551 等威胁行为者。

## 原理

- **FNV-1a 32 位**：`h = 0x811c9dc5`；对字符串每个字节 `h = ((h ^ byte) * 0x01000193) & 0xffffffff`。实现简单、无密钥，适合嵌入式配置生成；同一活动名的哈希在所有样本中稳定，可直接作为活动标识。
- **为什么可破解**：活动名不是随机密钥，而是人挑的短字符串（汽车型号、城市、NATO 字母等），搜索空间有限；对候选词表逐个哈希并与配置中的数字比对即可还原。原文解出的 IcedID Project ID 表中，`Pontiac 1501064257`、`Hyundai 2262657793`、`Chevrolet 904247735`、`Ascari 3524611504`、`Italdesign 3681413287`、`Porsche 310022019`、`Kappa 2143020712` 等均可用标准 FNV-1a 复算命中。
- **归因价值**：不同威胁行为者长期使用固定主题——TA578 常用 `Pontiac`/`Hyundai` 等汽车词，TA544 使用意大利相关词（`Ascari`/`Italdesign` 等），TA551 常引用 NATO 拼音字母（`Kappa`/`Juliet`/`Kilo` 等），TA579/TA581 的关联或异常也可从主题分布观察。把解码结果与活动时间、基础设施（C2/T2）关联，可在加载器配置改变后仍保持活动聚类与归因能力。
- **Latrodectus 的同类字段**：Latrodectus 用 FNV-1a 对解密出的活动名求哈希，作为 check-in 的 `group` 值（原文样本注释为活动名 `Supted`），说明该哈希方式被同源家族沿用，可用于跨家族关联。
- **边界与校验**：原文中 `Supted` 的注释与 check-in `group=510584660` 并不等于标准 FNV-1a(`Supted`)=1081065992，说明样本注释/实际参与哈希的字符串可能不一致（或被截断/改写）。实战必须以“可复现哈希匹配”为准，不能只凭反编译注释下结论；主题到 TA 的映射也是厂商评估，不是绝对归属。

## 触发条件

- 从 IcedID bot/loader 配置、Latrodectus check-in 或同类样本中取得数字型 `ProjectID`/`group`/campaign id 字段。
- 具备候选主题词表（汽车品牌/型号、城市/国家、NATO 字母、意大利语词、历史报告中出现过的活动名）。
- 用于威胁情报聚类、事件归因或检测规则增强；仅限授权分析。

## 利用步骤

1. 从样本配置/流量中提取数字 ID（如 IcedID bot `ProjectID`、Latrodectus `group`）。
2. 构建候选词表：先覆盖已知家族主题（汽车、地名、NATO 字母、意大利语），再叠加历史报告中出现过的活动名。
3. 对每个候选字符串计算 FNV-1a 32 位哈希，与目标数字比对；命中即得活动名。
4. 对同一样本族/时间段的所有 ID 批量还原，按主题聚类，绘制活动时间线与基础设施关联。
5. 将还原出的活动名与数字 ID 写入威胁情报库、YARA/配置解析规则与狩猎查询，用于后续样本快速归类。

## PoC

```python
def fnv1a32(s: str) -> int:
    h = 0x811c9dc5
    for b in s.encode():
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h

# 与原文 Project ID 表一致
for w in ["Pontiac", "Hyundai", "Chevrolet", "Porsche", "Ascari", "Italdesign", "Kappa"]:
    print(w, fnv1a32(w))
# Pontiac 1501064257 / Hyundai 2262657793 / Chevrolet 904247735
# Porsche 310022019 / Ascari 3524611504 / Italdesign 3681413287 / Kappa 2143020712

# 暴力破解示例
target = 1501064257
for w in ["Pontiac", "Hyundai", "Chevrolet"]:
    if fnv1a32(w) == target:
        print("decoded:", w)
```

## 变体与关联

- **词表变体**：按已知 TA 主题扩充（汽车、意大利品牌、NATO 字母、地名、动物等）；也可对疑似活动名做大小写/后缀/数字拼写变体。
- **同类字段**：除 IcedID `ProjectID` 外，Latrodectus `group`、其他加载器的 campaign/group 字段若为 32 位数字且与活动名相关，都可先尝试 FNV-1a 校验。
- **关联**：Latrodectus 的 FNV-1a `group` 与协议细节见 [[code-analysis-reverse-windows-latrodectus-loader-behavior-c2]]；字符串解密见 [[code-analysis-reverse-obfuscation-latrodectus-string-decrypt]]；基础设施关联见 [[defense-detection-c2-infra-fingerprint-netflow-t2-lifecycle]]。

## 检测与防御

- **情报侧**：把还原出的活动名/数字 ID 作为活动聚类键，跟踪同一 TA 的基础设施与投递链变化；对主题异常的新 ID 保持人工复核。
- **检测侧**：在样本配置提取与流量解密流程中自动计算 FNV-1a 并匹配已知活动表；命中即提升告警优先级。
- **防御侧**：结合 C2/T2 封禁与邮件投递链拦截；对同一 TA 的新活动提前部署检测规则。
- **注意**：归因结论受词表覆盖度和厂商评估影响，单次哈希命中只能证明活动名，不足以独立证明归属；需与基础设施、时间线、TTP 交叉验证。

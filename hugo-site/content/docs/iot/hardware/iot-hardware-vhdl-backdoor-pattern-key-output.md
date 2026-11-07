---
id: iot-hardware-vhdl-backdoor-pattern-key-output
title: VHDL 硬件后门识别：固定 16 位 pattern 触发后直接输出密钥
type: scenario
domain: iot
path: iot/hardware
technique: vhdl-backdoor-pattern-key-output
tags:
- iot
- hardware
- vhdl
- fpga
- backdoor
- tpm
- rtl
- security-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:40:26+08:00'
  notes: 已对照原文与全部29张图片核对：pattern 0xFFE9、key 0x63E1、E(0)/E(6)/E(13) 取反、tpm case 输出 Key/Encrypted 均一致；Python 模拟为按原文逻辑整理，未在库内复跑。
url: /docs/iot/hardware/iot-hardware-vhdl-backdoor-pattern-key-output/
draft: false
kb_aliases:
- VHDL 后门
- FPGA 硬件后门
- TPM 后门
- 固定 pattern 触发
- 密钥旁路输出
- RTL 逻辑审计
---

## 一句话结论

在 VHDL/FPGA 设计中，后门可以只是一个隐藏的比较器：当输入等于硬编码的 16 位 pattern（如 `1111111111101001`/`0xFFE9`）时，把输出多路选择器从“加密结果”切到“密钥寄存器”，直接泄露固定密钥；审计 RTL 时沿“常量比较 → 控制信号 → 输出 mux”追踪即可发现。

## 原理

- **组件结构**：本例系统由 `tpm`（主控制器）、`ckey`（密钥生成）、`encryption`（加密模块）、`backdoor`（后门检测）四个 VHDL 模块组成；正常路径是 `Output <= Encrypted`，后门路径是 `Output <= Key`。
- **后门触发器**：`backdoor.vhdl` 中 `constant pattern : STD_LOGIC_VECTOR(15 downto 0) := "1111111111101001";`，当输入 `D` 等于该常量时，后门信号 `B` 置 `'1'`。这是一个纯组合比较器，综合后可能被优化成几个 LUT，静态阅读时容易漏掉。
- **密钥旁路**：`key.vhdl` 中 `constant key : STD_LOGIC_VECTOR(15 downto 0) := "0110001111100001";`（0x63E1）。`tpm.vhdl` 的 case 语句在 `B='1'` 时把 `Key` 直接送到 `Output`，跳过加密；正常模式下才输出 `Encrypted`。
- **加密逻辑**：`encryption.vhdl` 大部分位是 `E(i) <= D(i) XOR K(i)`，但 `E(0) <= NOT K(0)`、`E(6) <= NOT K(6)`、`E(13) <= NOT K(13)` 三个特殊位取反；这说明“加密”只是 XOR 混淆，密钥一旦泄露即可解密/伪造。
- **为什么是后门而不是普通功能**：常量 pattern 不对应任何公开功能/调试接口，且命中后直接输出密钥而不是正常加密结果；这是典型的“隐藏测试/调试后门”模式。
- **审计方法**：枚举所有常量比较（`=`、`case`、`when`）、未使用/隐藏信号、输出 mux 的非常规分支；对每个常量尝试触发并观察输出是否变成密钥/明文/调试信息。形式化验证/等价性检查可发现“正常功能之外”的分支。

## 触发条件

- 拿到 VHDL/Verilog RTL 源码或可综合网表，且没有经过混淆/加密。
- 设计中存在硬编码常量比较器，其输出控制数据通路的多路选择器。
- 触发 pattern 可通过输入端口/测试平台送入；输出端口可观察。
- 有仿真器（GHDL/ModelSim/Vivado）或 FPGA 开发板可验证。

## 利用步骤

1. 枚举模块与端口：列出 `tpm`/`ckey`/`encryption`/`backdoor` 等模块及输入输出信号。
2. 搜索常量：在 RTL 中搜索 `constant`、`STD_LOGIC_VECTOR`、`when`、`=`，记录所有硬编码 pattern 和 key。
3. 追踪控制信号：从比较器输出（如 `B`）追到输出 mux/case 语句，确认命中后数据通路切换到哪个源（Key/明文/调试寄存器）。
4. 仿真验证：写 testbench，先输入正常值观察 `Encrypted`，再输入 pattern（`0xFFE9`）观察 `Output` 是否变为 `Key`。
5. 提取密钥：从 `key.vhdl`/输出端口读取 16 位 key，按加密逻辑反推明文或伪造数据。
6. 评估影响：确认后门是否可通过外部接口触发（卫星通信、传感器输入、调试口），以及密钥是否用于保护敏感数据。

## PoC

```vhdl
-- backdoor.vhdl（关键逻辑）
constant pattern : STD_LOGIC_VECTOR(15 downto 0) := "1111111111101001";
B <= '1' when D = pattern else '0';

-- key.vhdl
constant key : STD_LOGIC_VECTOR(15 downto 0) := "0110001111100001";

-- tpm.vhdl（输出旁路）
process(B, Key, Encrypted)
begin
  if B = '1' then
    Output <= Key;        -- 后门：直接泄露密钥
  else
    Output <= Encrypted;  -- 正常：输出加密结果
  end if;
end process;
```

Python 侧模拟触发与密钥恢复：

```python
pattern = int("1111111111101001", 2)  # 0xFFE9
key = int("0110001111100001", 2)      # 0x63E1

def normal_encrypt(d, k=key):
    e = d ^ k
    # 特殊位取反（按 16 位）
    for bit in (0, 6, 13):
        e = (e & ~(1 << bit)) | ((~k >> bit & 1) << bit)
    return e

print(hex(pattern), hex(key))
print("backdoor output:", hex(key) if pattern == 0xFFE9 else None)
```

## 变体与关联

- **Verilog/SystemVerilog**：同样的常量比较 + 输出 mux 模式；注意 `casez`/`casex` 通配符可能隐藏更宽的触发条件。
- **网表级后门**：综合后常量被优化进 LUT/ROM，需要从网表反推逻辑或做形式化等价性检查；可对比 RTL 与网表功能差异。
- **调试接口后门**：JTAG/UART 隐藏命令、未文档化寄存器、芯片 ID 匹配后解锁，也属于同一“隐藏触发”思路。
- **关联卡片**：[[iot-hardware-bes2300-rom-bootloader-uart-dump]]（硬件 UART/固件提取）；[[code-analysis-reverse-firmware-8051-eeprom-protocol-mac]]（固件状态机逆向）。

## 检测与防御

- **RTL 审计**：对常量比较、未使用信号、输出 mux 的非常规分支做人工/工具审查；把“硬编码 pattern 直接输出密钥”列为高危模式。
- **形式化验证**：用等价性检查/属性检查证明输出只依赖正常加密路径；对综合后网表做功能比对，防止综合工具/第三方 IP 插入后门。
- **供应链**：只使用可信 IP/工具链，校验综合/布局布线产物哈希；对第三方 VHDL 做代码审查与仿真。
- **运行时**：对关键输出做一致性校验；密钥不要以常量形式硬编码在 RTL/比特流中，使用 OTP/安全元件/密钥派生。

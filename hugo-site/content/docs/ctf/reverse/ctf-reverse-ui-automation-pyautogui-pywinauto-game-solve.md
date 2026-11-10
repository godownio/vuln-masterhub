---
id: ctf-reverse-ui-automation-pyautogui-pywinauto-game-solve
title: 不逆算法，直接 GUI 自动化通关：pyautogui 点击+输入 + pywinauto UIA 读弹窗文本，用「已访问集合」剪枝跑 BFS
type: scenario
domain: ctf
path: ctf/reverse
technique: ui-automation-pyautogui-pywinauto-state-graph-bfs
tags:
- ctf
- reverse
- pyautogui
- pywinauto
- gui-automation
- bfs
- pruning
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:16:45+08:00'
  notes: 已对照原文核对（pyautogui.click/typewrite、pywinauto Application(backend=uia).connect(title=Right!)、child_window(control_type=Text).window_text()、start_x/start_y+38*(id%31//31) 坐标换算、visited 剪枝、true/nothing 分支、t[i][7:10] 与 t[i][-17:-1] 解析均与原文一致）；本次核对未读取图片，仅依据正文；原文起始格子 565 与 key 9fc82e15d9de6ef2 保留，坐标需按实际窗口校准，未复现
url: /docs/ctf/reverse/ctf-reverse-ui-automation-pyautogui-pywinauto-game-solve/
draft: false
kb_aliases:
- pyautogui 自动玩游戏题
- pywinauto 读取对话框文本
- 不逆向直接脚本通关
- 状态图 BFS 剪枝 自动化点击
- 游戏类 RE 题的懒人解法
---

## 一句话结论

遇到「每个格子要用一把 key 解锁、解锁后吐出相邻格子及其 key」的游戏型 RE 题，正常解法是逆出算法再爆破；但如果算法复杂（甚至带反调试），可以直接让机器替你玩：`pyautogui` 按坐标点击格子并 `typewrite` 输入 key，`pywinauto` 用 UIA 后端读取弹窗里的文本拿到「下一批格子+key」，再用一个 `visited` 集合剪枝做 BFS/DFS 遍历整张状态图，走到底就拿到 flag。

## 原理

- 这类题的可玩性来自「界面即协议」：每次点击格子、输入 key 后，程序把结果渲染成文本（`Right!` 弹窗里列出可去的格子编号与对应 key）。既然输入输出都能通过 UI 观察与注入，那就不必理解内部算法——把 UI 当 RPC 调用即可。
- `pyautogui.click(x, y)` 与 `pyautogui.typewrite(s + '\n')` 提供输入侧原语；坐标由格子编号线性换算（本例 `start_x + 38*(id % 31) + 5`、`start_y + 38*(id // 31) + 16`），所以只要知道格子编号就能点到它。
- `pywinauto` 的 UIA backend 能按 `control_type="Text"` 直接从弹窗控件树里 `window_text()` 取文本，比 OCR 稳定得多：OCR 对 `0/O`、`1/l/I` 这类字符误识率高，而 UIA 拿到的是程序自己塞进去的字符串，零误识。
- 状态图遍历：把「已访问格子编号」放进 `set`，新解析出的格子只在未访问时入队——这就是剪枝，避免在环上无限点击（题目的格子图通常有环）。栈（`pop()`）即 DFS，换成 `collections.deque` 的 `popleft()` 就是 BFS，二者都能收敛，DFS 内存更省。
- 终止条件直接读文本：出现 `true` 就是通关，出现 `nothing` 说明该格子无新线索，直接跳过；这两条判断让脚本不需要知道图的结构。
- 为什么「自动化」也算一种 RE 技巧：它把「理解算法」的成本换成「理解交互协议」的成本，在算法被混淆/反调试保护时反而是更短的路径；代价是必须能实时看到并操作界面（本地运行、非 headless）。

## 触发条件

- 题目是可交互的本地程序（GUI 游戏、带弹窗的校验器），且**通关过程本身**会逐步泄露下一步所需信息。
- 输入可以靠坐标/键盘模拟完成（无验证码、无随机延迟对抗、无鼠标轨迹检测）。
- 输出可以用 UIA/控件文本读取（Win32/UIA 可访问），或退一步用 OCR。
- 题目允许长时间运行（每步 0.3s 级延迟，几百步几分钟内跑完）。
- 有明确终止信号（`true`/`flag` 字样）可用于自动停机。

## 利用步骤

1. 手动玩两步，记下交互协议：点哪里、输入什么、弹窗文本格式（本例每行形如 `grid[N] ... key`，取 `t[i][7:10]` 得编号、`t[i][-17:-1]` 得 key）。
2. 量出坐标系：起始点 + 格子边长（截图量像素），写成 `id -> (x, y)` 的换算函数，注意加内边距避开边框。
3. 用 `pywinauto.Application(backend="uia").connect(title="Right!")` 连上弹窗，`child_window(control_type="Text").window_text()` 取文本；连不上时 `continue` 跳过而不是崩掉。
4. 用 `visited` 集合做剪枝，栈/队列驱动遍历；每步点击 → 输入 key → 读文本 → 解析新边 → 关闭弹窗（`typewrite('\n')`）。
5. 命中 `true` 立即 `break`，把当前文本/截图里的 flag 取出；全程打印 `visited` 大小便于判断是否卡住。
6. 卡住时排查：坐标偏移（换个格子验证）、输入法/焦点丢失（点击后 `sleep` 加长）、弹窗标题变化（`connect` 用正则匹配）。

## PoC

```python
import time, pyautogui
from pywinauto.application import Application

time.sleep(3)                                  # 留时间切到游戏窗口
start_x, start_y = 900, 210
STEP = 38
grid, key = [565], ['9fc82e15d9de6ef2']        # 起始格子 + 初始 key
visited = {565}

while grid:
    cur, k = grid.pop(), key.pop()             # pop() = DFS；deque.popleft() = BFS
    x = start_x + STEP * (cur % 31) + 5
    y = start_y + STEP * (cur // 31) + 16

    pyautogui.click(x, y); time.sleep(0.3)
    pyautogui.typewrite(k + '\n'); time.sleep(0.3)

    try:
        app = Application(backend="uia").connect(title="Right!")
        text = app.window(title="Right!").child_window(control_type="Text").window_text()
    except Exception as e:
        print("connect failed:", e); continue

    pyautogui.typewrite('\n')                  # 关掉弹窗
    if 'true' in text.lower():
        print("FLAG:", text); break
    if 'nothing' in text.lower():
        continue

    for line in text.split('\n')[:4]:
        try:
            nxt = int(line[7:10]); nk = line[-17:-1]
        except (ValueError, IndexError):
            continue
        if nxt not in visited:                 # 剪枝：环上不重复点
            visited.add(nxt); grid.append(nxt); key.append(nk)
```

## 变体与关联

- 变体：UIA 读不到文本（自绘界面、DirectX 渲染）时退回截图 + OCR，但要先做字符白名单（本题 `0-9a-f`）并加多帧投票降误识。
- 变体：需要点击的坐标带随机偏移（防脚本）时，可先用模板匹配定位控件再点击。
- 变体：状态图过大时把 `visited` 落盘，支持断点续跑；或用并查集式「每个格子只解一次 key」的记录表。
- 变体：同类思路可用于自动化注册/登录表单、批量点击后台按钮——但那是自动化测试范畴，不属于漏洞利用。
- 关联：[[code-analysis-dynamic-debugging-crackme-password-check-patch]]（正统做法：改寄存器/ZF 直接绕过校验，比 UI 自动化更快，能逆就别玩）。
- 关联：[[ctf-reverse-python-str-eq-monkey-patch-comparison-log]]（同为「不硬逆算法，改运行环境观察行为」的思路）。

## 检测与防御

- 出题侧对抗：给弹窗加随机延迟、坐标抖动、鼠标轨迹检测，或把关键信息只渲染到自绘 surface 上（UIA 不可读）。
- 出题侧对抗：把「格子→key」的映射做成必须理解算法才能预测（不给文本反馈），使自动化无从下手。
- 工程侧（真实软件）：不要把敏感状态以明文控件文本暴露给 UIA——辅助技术可访问性接口同样可被自动化滥用；对关键操作加人机校验。
- 检测：同一进程内出现固定间隔（约 0.3s）的等距点击序列、大量重复 `typewrite` 与弹窗开关，是典型的脚本行为指纹。

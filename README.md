# dsh-electron-dialog-focus-fix

> 修一个 Electron 在 Windows 上的老毛病：**原生对话框（`alert` / `confirm` / `prompt`）关掉之后，窗口看着正常、鼠标右键粘贴也能用，但键盘打不了字、点输入框没反应 —— 切到别的窗口再切回来就好了。**

本仓库用**二进制补丁 + 一个小工具进程**把这件事彻底修掉，不改一行业务代码。
补丁点**全自动定位**，不依赖任何硬编码地址。

---

## 症状

在 Electron 桌面应用里触发 `window.confirm`（或 `alert` / `prompt`），把弹出来的框关掉：

- 窗口标题栏正常，鼠标点得动，右键菜单、粘贴都能用
- 但**键盘输入完全失效**，点输入框没有光标
- 开发者工具里 `document.hasFocus()` 返回 `false`
- **手动切到别的窗口再切回来，立刻恢复正常**

关键在于最后一条：这不是"窗口卡死"，而是**焦点状态没恢复**。

## 根因

### 一、Electron 里有两个"前台"

| 层 | 判据 | 对话框关闭后 |
|---|---|---|
| Windows 前台窗口 | `GetForegroundWindow()` | **已恢复**成应用主窗口 |
| 进程内激活状态 | `WM_ACTIVATE` / 线程焦点 / `document.hasFocus()` | **没有恢复** |

于是出现"假前台"：从系统角度看窗口就在最前面，但 Chromium 的渲染进程认为自己没被激活，
**键盘事件因此不投递给页面**。这就是"看得见、点得动、就是打不了字"的由来。

### 二、Electron 漏了一步

`alert` / `confirm` / `prompt` 底层走 Win32 的 **`TaskDialogIndirect`**（comctl32）。

按 Electron 官方 PR [#52188](https://github.com/electron/electron/pull/52188) 的描述，正常的激活链是：

```
OnWidgetActivationChanged(active=true)
  → NotifyWindowFocus()
  → BrowserWindow::OnWindowFocus()
  → web_contents()->RestoreFocus() + Focus()
```

**模态子窗口**关闭时，Electron 会显式调用 `parent->Focus(true)` 把这条链走完
（`shell/browser/native_window_views.cc` 的 `NativeWindowViews::OnWidgetDestroying`，约 1929-1936 行）。

但 **TaskDialog 这条路径上没有任何对应的代码** —— 于是 `RestoreFocus()` 从来没被调用。

上游状态：issue [#41602](https://github.com/electron/electron/issues/41602)
（重复件 [#41603](https://github.com/electron/electron/issues/41603)）被标记 `not_planned` 关闭；
修复 PR [#50770](https://github.com/electron/electron/pull/50770) 仍 open，
[#52188](https://github.com/electron/electron/pull/52188) 已 closed —— **都没进入任何 Electron 版本**。

### 三、Windows 的前台锁定让窗口无法自救

实测（在"假前台"状态下逐个试）：

| 做法 | 结果 |
|---|---|
| `SetForegroundWindow(自己)` | ❌ 窗口已在前台，**空操作**，连激活消息都不发 |
| 伪造 `WM_ACTIVATEAPP` / `WM_ACTIVATE` / `WM_SETFOCUS` | ❌ 无效 |
| **切到别的窗口、再切回自己** | ✅ **有效** |
| 补丁在进程内自己做上面这套 | ❌ **"切回"那一步被前台锁定拒绝**（`SetForegroundWindow` 返回 0） |
| `AllowSetForegroundWindow(-1)` 在切走之后调用 | ❌ 那时已经不是前台进程，授权为空 |
| 用桌面窗口中转（让前台变 NULL） | ❌ 拿回了权限，但**不产生激活序列** |
| `AttachThreadInput` 挂到前台线程 | ❌ 无效 |
| **让另一个新进程做"切走再切回"** | ✅ **有效** |

**结论：修复必须由一个全新的进程去执行"切走再切回"。** 新进程才拥有设置前台的权限。

## 修法

两半，缺一不可：

```
补丁（跑在应用自己的 UI 线程上，对话框刚关闭的那一刻）
  1. AllowSetForegroundWindow(-1)      ← ⭐ 此刻本进程还是前台，这是唯一能让授权生效的时机
  2. CreateProcessW 拉起 focus-helper.exe
  ↓
helper（全新进程，因此有前台权限）
  3. 造一个 1×1 的隐形窗口（WS_EX_TOOLWINDOW，不进 Alt+Tab）并把前台交给它  = "切走"
  4. 等 120ms
  5. 把前台交还给应用主窗口                                              = "切回"
  → Chromium 的激活链被真正走了一遍，RestoreFocus() 执行，键盘回来了
```

之所以把"授权"放在补丁里而不是 helper 里：**`AllowSetForegroundWindow` 只在前台进程里调用才有效**。
helper 启动的时候应用已经不是前台了，它自己去授权只会拿到一个空授权（这一点是实测出来的，
见下面"踩坑"第 12 条）。

### 为什么 hook 打在调用**之后**

补丁不修改 `TaskDialogIndirect` 的 `call` 本身，而是 hook **紧随其后的那条指令**。

原因：comctl32 的导入是**延迟导入（delay-import）**的，第一次调用要经过一个 thunk 去解析真实地址。
**那个 thunk 只能从它原本所在的位置被调用** —— 把它搬到别处再调用，会直接 `0xC0000005`。
（这是踩坑清单第 3 条，用崩溃换来的教训。）

### 为什么补丁点必须自动定位

`TaskDialogIndirect` 在 comctl32 里是**按导出序号**导入的，导入表里**只有序号 `#345`、没有名字**。
所以：

- 二进制里**搜不到 `"TaskDialogIndirect"` 这个字符串**；
- 也不能靠"找 `call` 后面的符号名"来定位。

本工具的做法是反过来推：

```
1. 解析导入表 / 延迟导入表
2. 找 COMCTL32.DLL 里 ordinal == 345 的那一项 → 拿到它的 IAT 槽地址
3. 扫描所有可执行段，找形如 `FF 15 <disp32>`（= call qword ptr [rip+disp32]）
   且 disp32 解出来的目标正好等于该 IAT 槽的指令
4. 那个位置就是调用点
```

这样无论应用版本怎么变、基址怎么随机化，都能找到。

## 安装

### 1. 编译 helper

```powershell
pwsh -NoProfile -File helper/build-helper.ps1
```

需要一个 C# 编译器（.NET Framework 4 自带的 `csc.exe` 就够，脚本会自动探测；也会去找 VS 的 Roslyn）。
产出 `helper/focus-helper.exe`。

### 2. 探测（不写盘，**强烈建议先跑**）

```powershell
python patch-focus-fix.py --probe
```

输出示例：

```
目标 exe : C:\...\DeepSeek Harness.exe
IAT 槽（TaskDialogIndirect） : 0x14E2829C0（来自延迟导入表）
调用点                       : 0x143A1B585
hook 点                      : 0x143A1B58B（吞 5 字节）
恢复执行地址                 : 0x143A1B590
.fix 段                      : 0x14EA7D000，代码 348 字节
可用调用点                   : 1 / 共 1
```

### 3. 打补丁

```powershell
# 生成打过补丁的副本
python patch-focus-fix.py --out patched.exe

# 或者直接安装到目标位置（自动备份成 <原名>.bak-focusfix-<日期>）
python patch-focus-fix.py --install
```

打完**重启应用**生效。

### 4. 回滚

把备份覆盖回去即可，或用 `dsh-focus-patch.ps1 -Revert`。

## 用法

### `patch-focus-fix.py`

| 参数 | 说明 |
|---|---|
| `--exe <路径>` | 目标 exe。不填则依次尝试 `$DSH_EXE` 环境变量 → 常见安装位置 |
| `--out <路径>` | 输出副本，默认 `<exe>.patched.exe` |
| `--helper <路径>` | helper 可执行文件。不填则依次尝试 `$DSH_FOCUS_HELPER` → exe 同目录 → 脚本目录 → `helper/` 子目录 |
| `--site <N>` | 有多个可用调用点时必须指定打第几个（从 0 开始） |
| `--probe` | 只探测不写盘 |
| `--install` | 生成后直接安装到目标位置（先自动备份） |

环境变量：`DSH_EXE`、`DSH_FOCUS_HELPER`。

> **注意**：helper 的路径会被**写进补丁**。如果之后把 helper 挪走了，需要重新生成补丁
> （或者用 `DSH_FOCUS_HELPER` 指定后再生成）。

### `dsh-focus-patch.ps1`

给不习惯敲 Python 的人用的一层壳：

```powershell
pwsh -File dsh-focus-patch.ps1 -Status    # 看看当前是什么状态
pwsh -File dsh-focus-patch.ps1 -Apply     # 打补丁（幂等，已打则跳过）
pwsh -File dsh-focus-patch.ps1 -Revert    # 回滚
```

## 补丁做了什么（`.fix` 段逐条）

| 要求 | 做法 | 为什么 |
|---|---|---|
| 段属性 | `0xE0000020`（CODE\|EXECUTE\|READ\|**WRITE**） | 补丁要写自己的计数器，只读段会直接 `0xC0000005` |
| 寻址 | 全部 **RIP 相对** | 目标开了 ASLR + HIGH_ENTROPY_VA，绝对地址一重启就失效 |
| `GUARD_CF` | **清掉**（`DllCharacteristics` 的 `0x4000`） | 新段里的代码不是 CFG 的合法间接调用目标，不清掉一旦有回调式调用进入就会 `__fastfail` |
| `NumberOfSections` | +1 | 新增 `.fix` 段 |
| `SizeOfImage` | 重新对齐 | 段变多了 |
| PE 校验和 | 重算（`pefile.generate_checksum`） | 保持头部自洽 |

补丁代码本身很朴素：**计数器 +1 → 授权 → 拉起 helper → 重放被覆盖的指令 → 跳回原流程**。
被覆盖的指令会被**逐字节原样搬进 `.fix` 段**再执行一遍，等价于没改过。

## 踩坑清单（12 条，全部有实测数据）

这些都是**做这个补丁时真踩过的**，记下来省得后来人再踩一遍。

| # | 坑 | 现象 | 解法 |
|---|---|---|---|
| 1 | 绝对地址在 ASLR 下失效 | 换一次启动就崩 | 全部改 RIP 相对寻址 |
| 2 | 想从 `TASKDIALOGCONFIG` 里读父窗口 | 读到 `0xFFFFFFFF` 之类的垃圾（结构体偏移猜错） | 别猜私有结构体，改用 `GetForegroundWindow()` / `EnumWindows` |
| 3 | 从别处调用 **delay-import thunk** | `0xC0000005` | **hook 点必须在 `call` 之后**，让原调用留在原位 |
| 4 | 探针数据放在补丁代码**内部** | 计数器读出来是天文数字（代码把自己覆盖了） | 探针槽偏移必须**大于补丁代码长度** |
| 5 | 从补丁里调 `Sleep` | `0xC0000005` | 改纯 CPU 忙等，或干脆不等待 |
| 6 | 段属性漏了 WRITE | `0xC0000005` | `0xE0000020` |
| 7 | `EnumWindows` 回调被 CFG 拦 | `0xC0000409`（`__fastfail`） | 清 `GUARD_CF` |
| 8 | 用**自己新建**的窗口当"切走"目标 | 切回后前台又跑回那个小窗口 | 换成**别的进程的真实窗口** |
| 9 | 用 `GetDesktopWindow()` 当切走目标 | 前台变成 NULL，**不产生激活序列**，等于白切 | 用 `EnumWindows` 找一个**别的进程的真实可见窗口** |
| 10 | 补丁在进程内自己"切走再切回" | `SetForegroundWindow(自己)` 返回 0（前台锁定） | **交给新进程 helper** |
| 11 | 进程内切换期间消息循环不跑 | `WM_ACTIVATE` 发出来没人处理，前台被回滚 | 同上：切换动作交给 helper |
| 12 | 授权时机错了 | helper 从"非前台"状态启动时，`SetForegroundWindow` 全部返回 `False` | **补丁在"自己仍是前台"的瞬间先 `AllowSetForegroundWindow(-1)`** |

### 错误码速查

| 错误码 | 含义 | 常见原因 |
|---|---|---|
| `0xC0000005` | 访问冲突 | 坑 3 / 5 / 6；或探针槽被代码覆盖（坑 4） |
| `0xC0000409` | 栈保护 / `__fastfail` | **CFG 拦了回调**（坑 7） |
| 进程静默退出、无错误码 | 可能是被杀软拦 | 补丁后 exe 签名失效，见下 |
| `SetForegroundWindow` 返回 0 | 前台锁定拒绝 | 你不是前台进程；需要坑 12 的授权时机 |

## 常见问题

**Q：补丁会不会破坏应用的数字签名？**
A：会。**任何**对 exe 的字节修改都会让签名失效，可能触发 SmartScreen 提示。
杀软（如 360、ESET）也可能对修改过的 exe 报警或拦截。请保留备份，出问题就回滚。

**Q：应用升级之后补丁就没了？**
A：对。升级会替换整个 exe，需要重新跑一次 `--probe` + `--install`。
好消息是**补丁点全自动定位**，版本变了也不用改任何东西。

**Q：为什么非要一个 helper 进程？不能全在补丁里做完吗？**
A：不能，这是 Windows 的规则不是实现问题。见根因第三节的实测表 ——
"切回"那一步必须由**另一个进程**做。

**Q：桌面上会闪一下吗？**
A：不会。helper 用的是 1×1 像素、`WS_EX_TOOLWINDOW` 的窗口（既不在 Alt+Tab 里，也几乎不可见），
前台交给它再交回来，肉眼看不出来。

**Q：`--probe` 说找不到 IAT 槽？**
A：说明这个应用没有用 comctl32 的 `TaskDialogIndirect`（那就不是这个 bug），
或者它用的是 WPF / 自绘对话框。这种应用不需要本补丁。

**Q：多个调用点怎么办？**
A：工具会列出所有可用调用点并让你用 `--site <N>` 指定。选哪个都可以 ——
它们都指向同一个 `TaskDialogIndirect`。

## 已验证的环境

- DeepSeek Harness 桌面版（Electron 44，Chromium 内核），Windows 10/11 x64
- 实测：原版必现"关框后打不了字"；打补丁后**弹框关闭后约 0.25 秒内焦点恢复**，
  且多种入口（主窗口 `confirm`、iframe 内的 `confirm`）都生效

## 相关

- 同一问题的**插件方案**（不需要改二进制）：[dsh-focus-guard](https://github.com/wqzhellohhwy/dsh-focus-guard)
- 上游 issue：[electron#41602](https://github.com/electron/electron/issues/41602)（`not_planned`）
- 上游 PR：[electron#50770](https://github.com/electron/electron/pull/50770)（open）

## 许可证

MIT。脚本与文档为原创；引用的 Electron 源码片段遵循其 MIT 许可。

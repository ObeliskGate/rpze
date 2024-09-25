# rpze

Remote Python, Zombie Endless (or endless rp?)

一个远程 Python 的 Plants vs. Zombies (pvz) TAS / 修改器 及 I, Zombie Endless (ize) 测试框架.

## 介绍

rpze 是一个用于 ize 测试的框架, 旨在保持一定性能、高精度、少崩溃的同时大幅简化 ize 非定态测试脚本的编写.  
通过与注入游戏的`.dll`进行 ipc 以实现理论100%精度和不崩溃的原版函数调用.

## 支持平台
仅支持 Windows 上的 CPython >= 3.11:
- 3.11及以上的 CPython 仅支持 **Windows 10 及以上**平台
- [pypi](https://pypi.org/project/rpze/) 上提供了64位 cp311, cp312 的预编译`.whl`.
- 32位平台原则上支持, 但需要自行[构建](#构建)

仅支持1.0.0.1051版本 pvz , 测试以[ pt 站上的英语原版 (lcx 版)](https://pvz.tools/download/)为准. 原则上支持各类汉化版, **不支持 [jspvz](http://jspvz.com/download.htm) 上的英语原版.** 各种其他来源的“英语原版”有不小概率出自 jspvz 或者同样没去登录壳, 请注意.

## 安装
在满足上述平台要求后, 执行`python -m pip install rpze`即可.  
若想确认安装成功, 执行`python -m rpze --path "your\path\to\PlantVsZombies.exe"`, 若游戏正常启动且在加载界面加载到一半时自动运行生物钟脚本, 则安装成功.
### 常见安装 FAQ

> 为什么弹出一个黑色窗口显示 console set? 

这是正常现象, 无须多注意. 用于确认成功以及在跳帧时关闭游戏等.

> 游戏正常启动但并不自动运行脚本 / invalid command / failed to find shared memory?

重新阅读[支持平台](#支持平台). 请考虑你使用的版本是否符合上述要求. 请注意, **仅确保兼容 [lcx 版](https://pvz.tools/download/)!!!**

> failed to create shared memory / 未找到文件?

请再运行一次试试, 可能和杀毒有关; 若一直这样请和我反馈.

> xmake is not installed?

重新阅读[支持平台](#支持平台). 你使用的 Python 没有预编译`.whl`, 你可以选择**换一个 Python** 或者[构建](#构建).

> DLL load failed while importing rp_extend?

原因未知, 请跟我反馈. 一定有效但非常麻烦的方法是自行[构建](#构建), 一个不确定是否好用的解决方法是`python -m pip install msvc-runtime`.

> 怎么联系?

加 QQ 群 884871715 或通过 GitHub issue / pr.


## 使用
 一个简单的完整 rpze 脚本示例如下:
```python
from rpze.iztest import *

with InjectedGame(r"your\path\to\pvz.exe") as game:
    iz_test = IzTest(game.controller).init_by_str('''
                 1000 -1
                 3-0 4-0 5-0 3-3
                 .....
                 .....
                 bs3_c
                 b2ljh
                 blyl_
                 cg   cg   xg   ww
                 0    1    300  700
                 4-6  4-6  4-6  4-6''')
    print(iz_test.start_test(True))
```

## 结构
总体分成五个包:
- `rp_extend`: 对控制 pvz 游戏本地运作的基本操作的封装
- `basic`: `.dll`注入, 游戏启动, 汇编代码等基础功能
- `structs`: pvz 内数据结构以及部分 method 的的封装
- `flow`: coroutine-like 测试编写相关的函数
- `iztest`: `IzTest`测试功能以及工具函数
- `examples`: `iztest`编写例子

其中, 若仅对 Python pvz 框架感兴趣则只需关注前三个包, 对 ize 测试感兴趣则着重模仿`examples`并大致了解`structs`的成员(`Plants`和`Zombies`).


## 优缺点
优点:
- 使用普及度最高的 Python 编写, 尽可能做到低上手难度
- 稳定性大幅领先几乎所有远程工具, 并且实现100%精度
- 作为普通 Python 包发布, 无须编译 C++ 繁琐的配置环境
- 相比于 AvZ 等方案更能和原有语言生态整合, 可以简单直接引用外部库, 处理测得数据等
- 兼容过去的 [iztools](https://github.com/sqrt07/iztools) 工具以及各类简写, 对已有习惯友好

缺点:
- 跳帧性能不如 [AvZ](https://github.com/vector-wlc/AsmVsZombies), [iztools](https://github.com/sqrt07/iztools) 等注入框架
- 相比于向`.exe`静态添加汇编和`.dll`注入等方案, 不够原生而存在大量性能浪费.
- 支持平台过少 (>=win10, >=cpy311) 使得大量 win7 玩家无法使用
- 对 ize 以外模式的键控暂无支持, 操控游戏底层实现(如跳帧)可能因为和`Board`耦合过高而不够通用.
- 作者太菜了, 对软件工程和操作系统变成没有基本认知, 会存在大量浪费时间的试错和重构

## 鸣谢
[Reisen](https://github.com/alumkal) - 提供初始思路, 模型以及解答各种问题,   
[63enjoy](https://github.com/POP63enjoy), [Ghastasaucey(BiliBili)](https://space.bilibili.com/384775811) 等 - 反汇编结论参考以及教学,  
[vector-wlc/AsmVsZombies](https://github.com/vector-wlc/AsmVsZombies) - 重要功能汇编函数参考,  
[sqrt07/iztools](https://github.com/sqrt07/iztools)  -  测试字符串, 功能和简写标准参照,

以及指针表, 函数表等资源工具和各位玩家的鼎力支持.

## 使用的开源项目
- [pybind/pybind11](https://github.com/pybind/pybind11), [LICENSE](https://github.com/pybind/pybind11/blob/master/LICENSE)
- [TsudaKageyu/minhook](https://github.com/TsudaKageyu/minhook), [LICENSE](https://github.com/TsudaKageyu/minhook/blob/master/LICENSE.txt)
- [keystone-engine/keystone](https://github.com/keystone-engine/keystone), [FOSS License Exception](https://github.com/keystone-engine/keystone/blob/master/EXCEPTIONS-CLIENT)

## 构建
> 100% certified works on my two machines

本框架采用 [xmake](https://xmake.io) 构建, 管理二进制依赖; 使用 MSVC 编译.

安装二者后, 构建 Python `.whl`只需`python -m pip install build`后`python -m build`即可.

可以用`python hatch_build.py -other_xmake_args`来自动设置 xmake config 的编译 arch

## 贡献
*请向 `dev`分支提交pull request*, 请遵循 [PEP 8](https://peps.python.org/pep-0008/) 和项目原有的命名, 文档规范.

作者水平很菜但热爱吹毛求疵, 请不要感到气馁, 他真的很欢迎每一个帮助本项目越来越好的人.

## 许可
Copyright © 2024 ObeliskGate

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
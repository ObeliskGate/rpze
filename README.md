# rpze

Remote Python, Zombie Endless(or endless rp?)

一个远程Python的Plants vs. Zombies TAS及ize测试框架.

## 介绍

rpze是一个用于ize测试的框架, 旨在保持一定性能、高精度、少崩溃的同时大幅简化ize非定态测试脚本的编写.  
通过与注入游戏的DLL进行ipc以实现理论100%精度和不崩溃的原版函数调用.

## 支持平台
所需CPython版本 >= 3.11, 仅支持**Windows10及以上**的x64平台.

仅支持1.0.0.1051版本pvz, 测试以[pt站上的英语原版(lcx版)](https://pvz.tools/download/)为准. 原则上支持各类汉化版, **不支持jspvz上的英语原版.** 各种其他来源的“英语原版”有不小概率出自jspvz或者同样没去登录壳, 请注意.

## 安装
在满足上述平台要求后, 执行`python -m pip install rpze`即可.  
若想确认安装成功, 执行`python -m rpze --path "your\path\to\PlantVsZombies.exe"`, 若游戏正常启动且在加载界面加载到一半时自动运行生物钟脚本, 则安装成功.
### 常见安装Q&A
- 
    - 为什么弹出一个黑色窗口显示create shared memory success? 
    - 这是正常现象, 无须多注意. 用于确认成功以及在跳帧时关闭游戏等.
-
    - create shared memory failed / 未找到文件?
    - 请再运行一次试试, 可能和杀毒有关; 若一直这样请和我反馈.
-
    - 游戏正常启动但并不自动运行脚本/invalid command?
    - 重新阅读[支持平台](#支持平台). 请考虑你使用的版本是否符合上述要求. 请注意, *仅确保兼容[pt站上的英语原版(lcx版)](https://pvz.tools/download/)!!!*

## 优缺点
优点:
- 使用普及度最高的Python编写, 尽可能做到低上手难度
- 稳定性大幅领先几乎所有远程工具, 并且实现100%精度
- 作为普通Python包发布, 无须C++繁琐的配置环境
- 相比于AvZ等方案更能和原有Python生态整合, 可以简单直接处理测得数据.
- 兼容过去的iztools工具以及各类简写, 对已有习惯友好

缺点:
- 跳帧性能不如[AvZ](https://github.com/vector-wlc/AsmVsZombies), [iztools](https://github.com/sqrt07/iztools)等注入框架
- 相比于向exe静态添加汇编和DLL注入等方案, 不够原生而存在大量性能浪费.
- 支持平台过少(>=win10, >=cpy311)使得大量win7玩家无法使用
- 对ize以外模式的键控暂无支持, 操控游戏底层实现(如跳帧)可能因为和`Board`耦合过高而不够通用.
- 作者太菜了, 对软件工程和操作系统变成没有基本认知, 会存在大量浪费时间的试错和重构

## 鸣谢
[Reisen](https://github.com/alumkal) - 提供初始思路, 模型以及解答各种问题,   
[63enjoy](https://github.com/POP63enjoy), [Ghastasaucey(BiliBili)](https://space.bilibili.com/384775811)等 - 反汇编结论参考以及教学,  
[vector-wlc/AsmVsZombies](https://github.com/vector-wlc/AsmVsZombies) - 重要功能汇编函数参考,  
[sqrt07/iztools](https://github.com/sqrt07/iztools)  -  测试字符串, 功能和简写标准参照,

以及指针表, 函数表等资源工具和各位玩家的鼎力支持.

## 使用的开源项目
- [pybind/pybind11](https://github.com/pybind/pybind11), [LICENSE](https://github.com/pybind/pybind11/blob/master/LICENSE)
- [keystone-engine/keystone](https://github.com/keystone-engine/keystone), [FOSS License Exception](https://github.com/keystone-engine/keystone/blob/master/EXCEPTIONS-CLIENT)

## 构建
> 100% certified works on my two machines

仅可用MSBuild编译二进制依赖. 本框架使用VS2022.

Python依赖`pip install pybind11 pywin32 keystone-engine setuptools build`   
执行`python config.py --config`配置msbuild文件, `--build`打包生成.whl文件, 具体说明见`config.py`

## 许可
Copyright © 2024 ObeliskGate

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
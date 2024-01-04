# rpze

Remote Python, Zombie Endless(or endless rp?)

一个远程Python的Plants vs. Zombies TAS及ize测试框架.

## 介绍

rpze是一个用于ize测试的框架, 旨在保持一定性能、高精度、少崩溃的同时大幅简化ize非定态测试脚本的编写.  
通过与注入游戏的DLL进行ipc以实现理论100%精度和不崩溃的原版函数调用.

## 支持平台
所需Python版本 >= 3.11, 仅支持**Windows10及以上**的x64平台.  
仅支持1.0.0.1051版本pvz, 测试以[pt站上的英语原版(lcx版)](https://pvz.tools/download/)为准. 原则上支持各类汉化版, **不支持jspvz上的英语原版.**

## 优缺点
优点:
- 使用普及度最高的Python编写, 尽可能做到低上手难度
- 稳定性大幅领先几乎所有远程工具, 并且实现100%精度
- 作为普通Python包发布, 无须C++繁琐的配置环境
- 兼容过去的iztools工具以及各类简写, 纯上手难度低

缺点:
- 跳帧性能不如[AvZ](https://github.com/vector-wlc/AsmVsZombies), [iztools](https://github.com/sqrt07/iztools)等注入框架
- 支持平台过少, 对电脑性能要求偏高
- 对survival endless键控没什么支持
- 作者太菜了

## 鸣谢
[Reisen](https://github.com/alumkal) - 提供初始思路, 模型以及解答各种问题,   
[63enjoy](https://github.com/POP63enjoy), [Ghastasaucey(BiliBili)](https://space.bilibili.com/384775811)等 - 反汇编结论参考以及教学,  
[vector-wlc/AsmVsZombies](https://github.com/vector-wlc/AsmVsZombies)  - 重要功能汇编函数参考,  
[sqrt07/iztools](https://github.com/sqrt07/iztools)  -  测试字符串, 功能和简写标准参照,

以及指针表, 函数表等资源工具和各位玩家的鼎力支持.

## 使用的开源项目
- [pybind/pybind11](https://github.com/pybind/pybind11), [LICENSE](https://github.com/pybind/pybind11/blob/master/LICENSE)
- [keystone-engine/keystone](https://github.com/keystone-engine/keystone), [FOSS License Exception](https://github.com/keystone-engine/keystone/blob/master/EXCEPTIONS-CLIENT)

## 编译
    
### MSBuild

> 100% certified works on my two machines

Python依赖`pip install pybind11 pywin32 keystone-engine`
执行`python -m pybind11 --includes` 将结果中不带`-I`的两个路径替换到./rp_extend/rp_extend.vcxproj文件中目标buildmode和Platform的`<AdditionalIncludeDirectories>`标签中, 并向该文件对应编译方式中`<AdditionalLibraryDirectories>`标签添加Python安装目录下libs文件夹. 后执行MSBuild命令指定buildmode和Platform生成项目.

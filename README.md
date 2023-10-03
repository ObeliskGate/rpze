# rpze

一个远程Python的pvz iz(e)键控框架.

还在做 可能永远做不好

## 编译
VS 2022，Python依赖pybind11 pywin32 keystone-engine
执行`python -m pybind11 --includes` 将结果中不带去掉-I的两个路径粘贴到rp_extend属性-c/c++常规-附加包含目录中，并在rp_extend属性-链接器常规中加上自己安装的Python目录中./libs文件夹。
# rpze

一个远程Python的pvz iz(e)键控框架, 通过注入DLL和remote Python进程通信来实现高精度控制游戏.

还在做 可能永远做不好

## 编译

### MSBuild

> 100% certified works on my machine

Python依赖`pip install pybind11 pywin32 keystone-engine`
执行`python -m pybind11 --includes` 将结果中不带`-I`的两个路径替换到./rp_extend/rp_extend.vcxproj文件中目标buildmode和Platform的`<AdditionalIncludeDirectories>`标签中, 并向该文件对应编译方式中`<AdditionalLibraryDirectories>`标签添加Python安装目录下libs文件夹. 后执行MSBuild命令指定buildmode和Platform生成项目.

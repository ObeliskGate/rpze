# rpze

Remote Python, Zombie Endless(or endless rp?)

一个远程Python的Plants vs. Zombies TAS及ize测试框架.

[主库](https://github.com/ObeliskGate/rpze.git)位于GitHub.

## 使用
`pip install rpze`下载, 下载后通过`python -m rpze --path "your\path\to\pvz.exe"`验证安装, 详情见主库readme.

一个简单的完整rpze脚本示例如下:
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
- `rp_extend`: 对控制pvz游戏本地运作的基本操作的封装
- `basic`: DLL注入, 游戏启动, 汇编代码等基础功能
- `structs`: PvZ内数据结构以及部分method的的封装
- `flow`: coroutine-like测试编写相关的函数
- `iztest`: IzTest测试功能以及工具函数
- `examples`: 上述的测试功能的编写例子

其中, 若仅对Python的pvz框架感兴趣则只需关注前三个包, 对ize测试感兴趣则着重模仿`examples`并大致了解`structs`的成员(`Plants`和`Zombies`).

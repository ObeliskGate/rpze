# rpze

Remote Python, Zombie Endless(or endless rp?)

一个远程Python的Plants vs. Zombies TAS及ize测试框架.

[主库](https://github.com/ObeliskGate/rpze.git)位于GitHub.

## 结构
总体分成五个包:
- `rp_extend`: 对控制pvz游戏本地运作的基本操作的封装
- `basic`: DLL注入, 游戏启动, 汇编代码等基础功能
- `structs`: PvZ内数据结构以及部分method的的封装
- `flow`: coroutine-like测试编写相关的函数, 和以此实现的IzTest测试功能
- `examples`: 上述的测试功能的编写例子

其中, 若仅对Python的pvz框架感兴趣则只需关注前三个包, 对ize测试感兴趣则着重模仿`examples`并大致了解`structs`的成员(`Plants`和`Zombies`).

# 例子
## [生物钟](https://www.bilibili.com/video/BV1gK4y1n7V5?p=2)
一个生物钟一二路卡相位的例子.
```python
from rpze.basic import InjectedGame
from rpze.flow import *

with InjectedGame(r"your\game\path") as game:
    game.enter_level(70)  # 打开编号为70的关卡, 即ize关卡
    iz_test = IzTest(game.controller).init_by_str('''
        1000 -1
        1-2
        zs_j5
        cptoh
        .....
        .....
        .....
        lz 
        0 
        2-6''')  # 大家熟悉的izt测试

    @iz_test.flow_factory.add_flow()
    async def place_zombie(_):
        plist = iz_test.game_board.plant_list
        flower = plist["2-5"]
        await until(lambda _: flower.hp <= 4)
        place("cg 2-6")  # 2-5花死前一瞬放撑杆
        star = plist["1-5"]  # 1-5杨桃
        await until_plant_last_shoot(star).after(151 - 96)
        await repeat("xg 1-6")  # 星星最后一发攻击发出后1双鬼

    iz_test.start_test(jump_frame=False, speed_rate=5)
```
从有@的那句话开始一句一句看下去:
- `@iz_test.flow_factory.add_flow()`: 一句格式代码, 作用是让测试时执行你下面定义的place_zombie. 抄下来就行.
- `async def place_zombie(_)`: 同样是格式代码.  
    此处, 可以认为`async def`定义一个非常类似于函数的`place_zombie`,
    这个类似函数的东西接受一个`FlowManager`类型的参数(在大部分场合用不到, 这里用`_`表示我用不到)  
    **不能不写async! `place_zombie`一定要是有且仅有一个参数的函数!**
- `plist = iz_test.game_board.plant_list`: 
    - `game_board`是游戏中当前运行的关卡界面的代名词, 关卡上的所有植物, 僵尸, 你的大多操作都通过透过它进行.
    - `plant_list`是游戏中存放植物对象的数组, 其中有当前对象数量, 最大数量等等信息.  
      `plant_list`类型为`PlantList`, 继承于`ObjList[Plant]`, 提供了使用`[int | slice]`索引, `~plist`遍历等功能.  
- `flower = plist["2-5"]`: `[f"{row}-{col}"]`是`PlantList`特有的方法, 获取在1-1的植物.
- `await until(lambda _: flower.hp <= 4)`: 意为等待2-5花的血量 $\leq$ 4时往下执行.  
    简单的说, 只需要写`await until(lambda _: 你希望满足xx条件时再往下执行)`即可.    
    具体格式为`await until(FlowManager -> bool)`. 和上面的`place_zombie`一样, 这里忽略`FlowManager`参数.
- `place("cg 2-6")`: 在2-6放撑杆, 非常简单.  这个函数会返回你刚放下来的僵尸, 有需要的话可以用
- `await until_plant_last_shoot(star).after(151 - 96)`: 在星星最后一次攻击结束后再过(151 - 96)帧往下执行
    - `until_plant_last_shoot(plant)`: 卡相位函数. 相当于`until(lambda _: plant攻击后第一次打不出子弹)`
    - `until(...).after(time)` 指等到前面的条件后再过time帧再往下执行.
- `await repeat("xg 1-6")` 1-6双小鬼.
    - `repeat`代表连放僵尸, 默认delay20放两个(大家都是这么做的!), 如想delay30放三个则是`repeat("xg 1-6", 2, 30)`
    - `await`必须有. 直观理解, 这里前面有`await`的理由是`repeat`函数要等放完了才能往后执行.
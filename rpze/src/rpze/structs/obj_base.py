# -*- coding: utf_8 -*-
"""
描述pvz中数据结构的基类和基本函数.
"""
import abc
import collections.abc as c_abc
import typing
from enum import IntEnum

from ..basic import asm
from ..rp_extend import Controller


class ObjBase(abc.ABC):
    """
    pvz中的一个对象

    Attributes:
        base_ptr: 对应pvz中对象的指针
        _controller: 对应pvz的Controller对象
    """

    def __init__(self, base_ptr: int, ctler: Controller):
        """
        一个ObjBase对象由一个指向pvz中的对象的指针, 和对应游戏的Controller构造
        
        Args:
            base_ptr: 游戏中对象的基址
            ctler: 游戏对应的Controller对象
        Raises:
            ValueError: base_ptr为空时抛出
        """
        if base_ptr == 0:
            raise ValueError(f"base_ptr of an {type(self).__name__} object cannot be 0")
        super().__init__()
        self.base_ptr = base_ptr
        self._controller = ctler

    OBJ_SIZE: int = NotImplemented
    """对应pvz类在pvz中的大小, 必须在所有非抽象子类中赋值"""

    def __eq__(self, other: typing.Self) -> bool:
        """
        判断二个ObjBase对象是否指向同一游戏的同一位置

        功能更接近于Python中的is.

        Args:
            other : 另一个ObjBase对象
        """
        return self.base_ptr == other.base_ptr and (self._controller == other._controller)

    def __ne__(self, other: typing.Self) -> bool:
        return not (self.base_ptr == other.base_ptr and (self._controller == other._controller))

    def __str__(self) -> str:
        return (f"<{type(self).__name__} object at [0x{self.base_ptr:x}] "
                f"of process id {self._controller.pid}>")

    def __repr__(self) -> str:
        return (f"{type(self).__name__}(base_ptr=0x{self.base_ptr:x}, "
                f"ctler=Controller({self._controller.pid}))")


class OffsetProperty(property):
    """
    ObjBase对象在pvz内的属性

    Attributes:
        offset: 属性在游戏中的偏移
    """

    def __init__(self, fget, fset, fdel, doc, offset):
        super().__init__(fget, fset, fdel, None)
        self.__doc__ = doc
        self.offset = offset


# property factories 用于生成ObjBase对象在pvz内的属性
def property_bool(offset: int, doc: str):
    def _get(self: ObjBase) -> bool:
        return self._controller.read_bool([self.base_ptr + offset])

    def _set(self: ObjBase, value: bool):
        self._controller.write_bool(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "bool: " + doc, offset)


def property_i8(offset: int, doc: str):
    def _get(self: ObjBase) -> int:
        return self._controller.read_i8([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self._controller.write_i8(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_i16(offset: int, doc: str):
    def _get(self: ObjBase) -> int:
        return self._controller.read_i16([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self._controller.write_i16(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_i32(offset: int, doc: str):
    def _get(self: ObjBase) -> int:
        return self._controller.read_i32([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self._controller.write_i32(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_i64(offset: int, doc: str):
    def _get(self: ObjBase) -> int:
        return self._controller.read_i64([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self._controller.write_i64(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_u8(offset: int, doc: str):
    def _get(self: ObjBase) -> int:
        return self._controller.read_u8([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self._controller.write_u8(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_u16(offset: int, doc: str):
    def _get(self: ObjBase) -> int:
        return self._controller.read_u16([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self._controller.write_u16(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_u32(offset: int, doc: str):
    def _get(self: ObjBase) -> int:
        return self._controller.read_u32([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self._controller.write_u32(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_u64(offset: int, doc: str):
    def _get(self: ObjBase) -> int:
        return self._controller.read_u64([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self._controller.write_u64(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_f32(offset: int, doc: str):
    def _get(self: ObjBase) -> float:
        return self._controller.read_f32([self.base_ptr + offset])

    def _set(self: ObjBase, value: float):
        self._controller.write_f32(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "float: " + doc, offset)


def property_f64(offset: int, doc: str):
    def _get(self: ObjBase) -> float:
        return self._controller.read_f64([self.base_ptr + offset])

    def _set(self: ObjBase, value: float):
        self._controller.write_f64(value, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, "float: " + doc, offset)


def property_int_enum(offset: int, cls: type[IntEnum], doc: str):
    def _get(self: ObjBase) -> cls:
        return cls(self._controller.read_i32([self.base_ptr + offset]))

    def _set(self: ObjBase, value: cls):
        self._controller.write_i32(int(value), [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, f"{cls.__name__}: {doc}", offset)


def property_obj(offset: int, cls: type[ObjBase], doc: str):
    def _get(self: ObjBase) -> cls:
        return cls(self._controller.read_i32([self.base_ptr + offset]), self._controller)

    def _set(self: ObjBase, value: cls):
        if self._controller != value._controller:
            raise ValueError("cannot assign an object from another controller")
        self._controller.write_i32(value.base_ptr, [self.base_ptr + offset])

    return OffsetProperty(_get, _set, None, f"{cls.__name__}: {doc}", offset)


class ObjId(ObjBase):
    """
    ObjNode对象末尾的(index, rank)对象

    游戏内用于ObjNode的识别和储存.
    """

    OBJ_SIZE = 4

    index = property_u16(0, "对象索引")

    rank = property_u16(2, "对象序列号")

    def __eq__(self, val: typing.Self | tuple[int, int]) -> bool:
        """
        ObjId比较相等 与其他ObjId比较或与(index, rank)比较

        Args:
            val: 另一个ObjId对象或(index, rank)一样的可解包对象
        Returns:
            "表示相同对象"返回True
        Raises:
            TypeError: val不是ObjId对象或可解包对象
            ValueError: 可解包不是两个元素
        """
        if isinstance(val, ObjId):
            return ((self._controller.read_u32([self.base_ptr]) ==
                     val._controller.read_u32([val.base_ptr]))
                    and self._controller == val._controller)
        try:
            index, rank = val
        except TypeError as te:
            raise TypeError("ObjId can only compare with another ObjId or"
                            "an unpack-able object like (index, rank), "
                            f"not {type(val).__name__} instance") from te
        except ValueError as ve:
            raise ValueError("unpack-able val should have 2 elements (index, rank)") from ve
        return self._controller.read_u32([self.base_ptr]) == ((rank << 16) | index)

    def __ne__(self, val: typing.Self | tuple[int, int]) -> bool:
        return not (self.__eq__(val))

    def __str__(self) -> str:
        return f"(index={self.index}, rank={self.rank})"


class ObjNode(ObjBase, abc.ABC):
    """
    Plant Zombie等等, 在pvz中由ObjList数组进行内存管理的对象

    Attributes:
        id: ObjNode对象末尾的ObjId对象
    """

    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)
        self.id = ObjId(base_ptr + self.OBJ_SIZE - 4, ctler)

    ITERATOR_FUNC_ADDRESS: int = NotImplemented
    """返回pvz中迭代对象的函数地址, 必须在所有非抽象子类中赋值"""

    ITERATOR_P_BOARD_REG: str = "edx"
    """迭代对象函数用于存储Board指针的寄存器, reanimation和粒子系统为eax, 其他为edx"""


_T = typing.TypeVar("_T", bound=ObjNode)


class ObjList(ObjBase, c_abc.Sequence[_T], abc.ABC):
    """
    游戏中管理各类对象内存的数组, 即函数表中DataArray对象

    仅帮助type hint用, 请勿直接使用, 而是使用obj_list函数构造.
    """

    OBJ_SIZE = 28

    max_length = property_i32(4, "最大时对象数")

    next_index = property_i32(12, "下一个对象的索引")

    obj_num = property_i32(16, "当前对象数量")

    next_rank = property_i32(20, "下一个对象的序列号")

    def __len__(self) -> int:
        """
        返回最大时对象数, 与max_length相同

        Returns:
            最大时对象数
        """
        return self._controller.read_i32([self.base_ptr + 4])

    def at(self, index: int) -> _T:
        """
        返回index对应下标的元素

        Args:
            index: 非负索引, 不做任何检查
        Returns:
            对应下标的元素, 不确保存活
        """

    @typing.overload
    def __getitem__(self, index: int) -> _T:
        """
        返回index对应下标的元素

        Args:
            index: 整数索引, 即支持负数索引
        Returns:
            对应下标的元素, 不确保存活
        Raises:
            IndexError: 若index超出范围抛出
        """

    @typing.overload
    def __getitem__(self, index: slice) -> list[_T]:
        """
        返回slice切片对应的列表

        若在遍历返回值的时候有新对象生成或死亡, 该方法没法动态调整.

        Args:
            index: 切片索引
        Returns:
            对应切片的列表, 不保证其中任何成员存活
        """

    def __getitem__(self, index): ...

    def __invert__(self) -> c_abc.Iterator[_T]:
        """
        迭代所有未回收对象的迭代器, 利用原版函数在迭代过程中动态寻找下一个对象
        
        Returns:
            迭代器, 仅迭代存活对象
        Examples:
            >>> l: ObjList = ...
            >>> for objects in ~l:
            ...     ...  # do something
            迭代l中所有未回收的对象
        """

    @property
    def alive_iterator(self) -> c_abc.Iterator[_T]:
        """与__invert__()相同"""
        return self.__invert__()

    @typing.overload
    def find(self, index: int | ObjId) -> _T | None:
        """
        通过index查找对象

        用int查找时, 未回收对象返回T.
        用ObjId查找时, 在对应index位置对象rank相同时返回T.

        Args:
            index: 整数索引, ObjId对象或(index, rank)可解包对象
        Returns:
            存在未回收的对应对象返回, 否则返回None.
        Raises:
            TypeError: index不是int和ObjId
        Example:
            >>> self.find(-1)
            当前最后一个对象(len(self) - 1)未回收时返回, 否则返回None
        """

    @typing.overload
    def find(self, idx: int, rank: int) -> _T | None:
        """
        通过(index, rank)组查找对象

        Args:
            idx: 整数索引
            rank: 序列号
        Returns:
            存在未回收的对应对象返回, 否则返回None.
        Example:
            >>> self.find(1, 1)
            若idx == 1的对象的rank==1, 返回该对象, 否则返回None
        """

    def find(self, *args): ...

    def reset_stack(self) -> typing.Self:
        """
        清栈

        在所有对象都被回收时调用. 让本对象之后申请对象从0开始申请

        Returns:
            返回自己
        Raises:
            RuntimeError: 不是所有对象都被回收时候抛出
        """

    @abc.abstractmethod
    def free_all(self) -> typing.Self:  # DataArrayFreeAll会泄露动画对象.
        """
        删除存活的所有对象.

        Returns:
            返回自己
        """


def obj_list(node_cls: type[_T]) -> type[ObjList[_T]]:
    """
    根据node_cls构造对应的NodeClsObject的父类
    
    Args:
        node_cls: ObjNode的子类
    Returns:
        管理node_cls对象的数组的父类
    """

    class _ObjIterator(c_abc.Iterator[_T]):
        def __init__(self, ctler: Controller, _iterate_func_asm):
            self._current_ptr = 0
            self._controller = ctler
            self._iterate_func_asm = _iterate_func_asm

        def __next__(self) -> _T:
            self._controller.result_u64 = self._current_ptr
            self._controller.run_code(self._iterate_func_asm)
            if (self._controller.result_u64 >> 32) == 0:
                raise StopIteration
            self._current_ptr = self._controller.result_u32
            return node_cls(self._current_ptr, self._controller)

        def __iter__(self):
            return self

    class _ObjListImplement(ObjList[_T], abc.ABC):
        def __init__(self, base_ptr: int, ctler: Controller):
            super().__init__(base_ptr, ctler)
            self._array_base_ptr = ctler.read_u32([base_ptr])
            p_board = ctler.get_p_board()[1]
            self._code = f"""
                push esi;
                mov esi, {self._controller.result_address};
                mov {node_cls.ITERATOR_P_BOARD_REG}, {p_board};
                call {node_cls.ITERATOR_FUNC_ADDRESS};
                mov [esi + 4], al;
                pop esi;
                ret;"""  # 可恶的reg优化
            self._iterate_func_asm = None

        def at(self, index: int) -> _T:
            return node_cls(self._array_base_ptr + node_cls.OBJ_SIZE * index, self._controller)

        def find(self, *args) -> _T | None:
            match len(args):
                case 1:
                    index = args[0]
                    if isinstance(index, int):
                        try:
                            target = self[index]
                        except IndexError:
                            return None
                        return target if target.id.rank != 0 else None
                    if isinstance(index, ObjId):
                        target = self.at(index.index)
                        return target if target.id == index else None
                    raise TypeError("index must be int or ObjId instance")
                case 2:
                    idx, rank = args
                    try:
                        target = self[idx]
                    except IndexError:
                        return None
                    return target if target.id.rank == rank else None
                case other:
                    raise ValueError("the function should have 1 or 2 parameters, "
                                     f"not {other} parameters")

        def __getitem__(self, index: int | slice):
            if isinstance(index, int):
                i = index if index >= 0 else index + len(self)
                if i >= len(self) or i < 0:
                    raise IndexError("sequence index out of range")
                return self.at(i)
            if isinstance(index, slice):
                start, stop, step = index.indices(len(self))
                return [self[i] for i in range(start, stop, step)]
            raise TypeError(f"index must be int or slice, not {type(index).__name__} instance")

        def __invert__(self):
            if self._iterate_func_asm is None:
                self._iterate_func_asm = asm.decode(self._code, self._controller.result_address)
            return _ObjIterator(self._controller, self._iterate_func_asm)

        def reset_stack(self):
            if self.obj_num:
                raise RuntimeError(f"cannot reset stack when there are still {self.obj_num} objects alive")
            next_idx = self.next_index
            self.next_index = 0
            length = self.max_length
            self.max_length = 0
            while next_idx != length:
                next_idx = (t := self.at(next_idx).id).index
                t.index = 0
            return self

    return _ObjListImplement

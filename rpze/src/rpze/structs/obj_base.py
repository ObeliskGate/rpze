# -*- coding: utf_8 -*-
"""
描述pvz中数据结构的基类和基本函数.
"""
import abc
from collections.abc import Sequence, Iterator, Callable
from enum import IntEnum
from typing import ClassVar, Self, TypeVar, overload, SupportsIndex, Generic, Any, TypeAlias, Final

from ..basic import asm
from ..basic.exception import PvzStatusError
from ..rp_extend import Controller


class ObjBase(abc.ABC):
    """
    pvz中的一个对象

    Attributes:
        base_ptr: 对应pvz中对象的指针
        controller: 对应pvz的Controller对象
    """
    __slots__ = ("base_ptr", "controller")

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
        self.controller = ctler

    OBJ_SIZE: ClassVar[int] = NotImplemented
    """对应pvz类在pvz中的大小, 必须在所有非抽象子类中赋值"""

    def __eq__(self, other: Self) -> bool:
        """
        判断二个ObjBase对象是否指向同一游戏的同一位置

        功能更接近于Python中的is.

        Args:
            other : 另一个ObjBase对象
        """
        return self.base_ptr == other.base_ptr and (self.controller == other.controller)

    def __ne__(self, other: Self) -> bool:
        return not (self.base_ptr == other.base_ptr and (self.controller == other.controller))

    def __str__(self) -> str:
        return (f"<{type(self).__name__} object at [0x{self.base_ptr:x}] "
                f"of process id {self.controller.pid}>")

    def __repr__(self) -> str:
        return (f"{type(self).__name__}(base_ptr=0x{self.base_ptr:x}, "
                f"ctler=Controller({self.controller.pid}))")


_T = TypeVar("_T")
_T_co = TypeVar("_T_co", covariant=True)
_T_con = TypeVar("_T_con", contravariant=True)


class OffsetProperty(property, Generic[_T_co, _T_con]):
    """
    ObjBase对象在pvz内的属性

    两个泛型参数分别表示: 通过对象调用的__get__返回值, __set__入参.

    Attributes:
        offset: 属性在游戏中的偏移
    """
    def __init__(self,
                 fget: Callable[[ObjBase], _T_co] | None,
                 fset: Callable[[ObjBase, _T_con], None] | None,
                 fdel: Callable[[ObjBase], None] | None,
                 doc: str | None,
                 offset: int):
        super().__init__(fget, fset, fdel, doc)
        self.__doc__ = doc
        self.__objclass__ = ObjBase
        self.offset: Final[int] = offset

    @overload
    def __get__(self, obj: None, owner: type | None = ..., /) -> Self: ...

    @overload
    def __get__(self, obj: Any, owner: type | None = ..., /) -> _T_co: ...

    def __get__(self, *args):
        return super().__get__(*args)

    def __set__(self, obj: ObjBase, value: _T_con) -> None:
        return super().__set__(obj, value)

    def __delete__(self, obj: ObjBase) -> None:
        return super().__delete__(obj)


_OffsetProp: TypeAlias = OffsetProperty[_T, _T]


# property factories 用于生成ObjBase对象在pvz内的属性
def property_bool(offset: int, doc: str) -> _OffsetProp[bool]:
    def _get(self: ObjBase) -> bool:
        return self.controller.read_bool(self.base_ptr + offset)

    def _set(self: ObjBase, value: bool):
        self.controller.write_bool(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "bool: " + doc, offset)


def property_i8(offset: int, doc: str) -> _OffsetProp[int]:
    def _get(self: ObjBase) -> int:
        return self.controller.read_i8(self.base_ptr + offset)

    def _set(self: ObjBase, value: int):
        self.controller.write_i8(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_i16(offset: int, doc: str) -> _OffsetProp[int]:
    def _get(self: ObjBase) -> int:
        return self.controller.read_i16(self.base_ptr + offset)

    def _set(self: ObjBase, value: int):
        self.controller.write_i16(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_i32(offset: int, doc: str) -> _OffsetProp[int]:
    def _get(self: ObjBase) -> int:
        return self.controller.read_i32(self.base_ptr + offset)

    def _set(self: ObjBase, value: int):
        self.controller.write_i32(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_i64(offset: int, doc: str) -> _OffsetProp[int]:
    def _get(self: ObjBase) -> int:
        return self.controller.read_i64(self.base_ptr + offset)

    def _set(self: ObjBase, value: int):
        self.controller.write_i64(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_u8(offset: int, doc: str) -> _OffsetProp[int]:
    def _get(self: ObjBase) -> int:
        return self.controller.read_u8(self.base_ptr + offset)

    def _set(self: ObjBase, value: int):
        self.controller.write_u8(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_u16(offset: int, doc: str) -> _OffsetProp[int]:
    def _get(self: ObjBase) -> int:
        return self.controller.read_u16(self.base_ptr + offset)

    def _set(self: ObjBase, value: int):
        self.controller.write_u16(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_u32(offset: int, doc: str) -> _OffsetProp[int]:
    def _get(self: ObjBase) -> int:
        return self.controller.read_u32(self.base_ptr + offset)

    def _set(self: ObjBase, value: int):
        self.controller.write_u32(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_u64(offset: int, doc: str) -> _OffsetProp[int]:
    def _get(self: ObjBase) -> int:
        return self.controller.read_u64(self.base_ptr + offset)

    def _set(self: ObjBase, value: int):
        self.controller.write_u64(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "int: " + doc, offset)


def property_f32(offset: int, doc: str) -> _OffsetProp[float]:
    def _get(self: ObjBase) -> float:
        return self.controller.read_f32(self.base_ptr + offset)

    def _set(self: ObjBase, value: float):
        self.controller.write_f32(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "float: " + doc, offset)


def property_f64(offset: int, doc: str) -> _OffsetProp[float]:
    def _get(self: ObjBase) -> float:
        return self.controller.read_f64(self.base_ptr + offset)

    def _set(self: ObjBase, value: float):
        self.controller.write_f64(value, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, "float: " + doc, offset)


_T_int_enum = TypeVar("_T_int_enum", bound=IntEnum)


def property_int_enum(offset: int, cls: type[_T_int_enum], doc: str) \
        -> OffsetProperty[_T_int_enum, int]:
    def _get(self: ObjBase) -> _T_int_enum:
        return cls(self.controller.read_i32(self.base_ptr + offset))

    def _set(self: ObjBase, value: _T_int_enum) -> None:
        self.controller.write_i32(int(value), self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, f"{cls.__name__}: {doc}", offset)


_T_obj = TypeVar("_T_obj", bound=ObjBase)


def property_obj(offset: int, cls: type[_T_obj], doc: str) -> _OffsetProp[_T_obj]:
    def _get(self: ObjBase):
        return cls(self.controller.read_i32(self.base_ptr + offset), self.controller)

    def _set(self: ObjBase, value: _T_obj) -> None:
        if self.controller != value.controller:
            raise ValueError("cannot assign an object from another controller")
        self.controller.write_i32(value.base_ptr, self.base_ptr + offset)

    return OffsetProperty(_get, _set, None, f"{cls.__name__}: {doc}", offset)


class ObjId(ObjBase):
    """
    ObjNode对象末尾的(index, rank)对象

    游戏内用于ObjNode的识别和储存.
    """

    OBJ_SIZE = 4

    index = property_u16(0, "对象索引")

    rank = property_u16(2, "对象序列号")

    def __eq__(self, val: Self | tuple[int, int]) -> bool:
        """
        ObjId比较相等 与其他ObjId比较或与(index, rank)比较

        Args:
            val: 另一个ObjId对象或(index, rank)一样的可解包对象
        Returns:
            "表示相同对象"返回True
        """
        if isinstance(val, ObjId):
            return ((self.controller.read_u32(self.base_ptr) ==
                     val.controller.read_u32(val.base_ptr))
                    and self.controller == val.controller)
        index, rank = val
        return self.controller.read_u32(self.base_ptr) == ((rank << 16) | index)

    def __ne__(self, val: Self | tuple[int, int]) -> bool:
        return not self.__eq__(val)

    def __str__(self) -> str:
        return f"(index={self.index}, rank={self.rank})"

    def tpl(self) -> tuple[int, int]:
        """
        Returns:
            (index, rank)元组
        """
        return self.index, self.rank


class ObjNode(ObjBase, abc.ABC):
    """
    Plant Zombie等等, 在pvz中由ObjList数组进行内存管理的对象

    Attributes:
        id: ObjNode对象末尾的ObjId对象
    """
    __slots__ = ("id",)

    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)
        self.id = ObjId(base_ptr + self.OBJ_SIZE - 4, ctler)

    ITERATOR_FUNC_ADDRESS: ClassVar[int] = NotImplemented
    """返回pvz中迭代对象的函数地址, 必须在所有非抽象子类中赋值"""

    ITERATOR_P_BOARD_REG: ClassVar[str] = "edx"
    """迭代对象函数用于存储Board指针的寄存器, reanimation和粒子系统为eax, 其他为edx"""

    is_dead: OffsetProperty = NotImplemented
    """对象是否存活, 必须在所有非抽象子类中赋值"""


_T_node = TypeVar("_T_node", bound=ObjNode)


class ObjList(ObjBase, Sequence[_T_node], abc.ABC):
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
        return self.controller.read_i32(self.base_ptr + 4)

    def at(self, index: int) -> _T_node:
        """
        返回index对应下标的元素

        Args:
            index: 非负索引, 不做任何检查
        Returns:
            对应下标的元素, 不确保存活
        """

    @overload
    def __getitem__(self, index: SupportsIndex, /) -> _T_node:
        """
        返回index对应下标的元素

        Args:
            index: 整数索引, 即支持负数索引
        Returns:
            对应下标的元素, 不确保存活
        Raises:
            IndexError: 若index超出范围抛出
        """

    @overload
    def __getitem__(self, index: slice, /) -> list[_T_node]:
        """
        返回slice切片对应的列表

        若在遍历返回值的时候有新对象生成或死亡, 该方法没法动态调整.

        Args:
            index: 切片索引
        Returns:
            对应切片的列表, 不保证其中任何成员存活
        """

    def __getitem__(self, index): ...

    def __invert__(self) -> Iterator[_T_node]:
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
    def alive_iterator(self) -> Iterator[_T_node]:
        """与__invert__()相同"""
        return ~self

    @overload
    def find(self, index: SupportsIndex | ObjId, /) -> _T_node | None:
        """
        通过index查找对象

        用SupportsIndex查找时, 未回收对象返回T.
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

    @overload
    def find(self, idx: int, rank: int, /) -> _T_node | None:
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

    def reset_stack(self) -> Self:
        """
        清栈

        在所有对象都被回收时调用. 让本对象之后申请对象从0开始申请

        Returns:
            self
        Raises:
            PvzStatusError: 当有对象未回收时抛出
        """

    @abc.abstractmethod
    def free_all(self) -> Self:  # DataArrayFreeAll会泄露动画对象.
        """
        删除存活的所有对象.

        Returns:
            self
        """

    def set_next_idx(self, idx: int) -> Self:
        """
        设置下一个对象的编号, 若idx大于当前最大长度, 会调整最大长度至和idx相同.

        当前实现: 为将idx和next_idx在"栈位"对应位置中交换.
        "调整长度"当前实现: 从所需最高到当前长度倒序添加; 与ize一开始类似且调整长度后无需再次交换.

        Args:
            idx: 下一个对象的编号
        Returns:
            self
        Raises:
            ValueError: idx不合法或idx所在对象未回收时抛出.
        """


def obj_list(node_cls: type[_T_node]) -> type[ObjList[_T_node]]:
    """
    根据node_cls构造对应的NodeClsObject的父类
    
    Args:
        node_cls: ObjNode的子类
    Returns:
        管理node_cls对象的数组的父类
    """

    class _ObjIterator(Iterator[_T_node]):
        def __init__(self, ctler: Controller, _iterate_func_asm):
            self._current_ptr = 0
            self._controller = ctler
            self._iterate_func_asm = _iterate_func_asm

        def __next__(self) -> _T_node:
            self._controller.result_u64 = self._current_ptr
            self._controller.run_code(self._iterate_func_asm)
            if (self._controller.result_u64 >> 32) == 0:
                raise StopIteration
            self._current_ptr = self._controller.result_u32
            return node_cls(self._current_ptr, self._controller)

        def __iter__(self) -> Self:
            return self

    class _ObjListImplement(ObjList[_T_node], abc.ABC):
        def __init__(self, base_ptr: int, ctler: Controller):
            super().__init__(base_ptr, ctler)
            self._array_base_ptr = ctler.read_u32(base_ptr)
            self._code = f"""
                push esi
                mov esi, [0x6a9ec0]
                mov {node_cls.ITERATOR_P_BOARD_REG}, [esi + 0x768]
                mov esi, {self.controller.result_address}
                call {node_cls.ITERATOR_FUNC_ADDRESS}
                mov [esi + 4], al
                pop esi
                ret"""  # 可恶的reg优化
            self._iterate_func_asm = None

        def at(self, index: int) -> _T_node:
            return node_cls(self._array_base_ptr + node_cls.OBJ_SIZE * index, self.controller)

        def find(self, *args) -> _T_node | None:
            match args:
                case (idx,):
                    if isinstance(idx, SupportsIndex):
                        try:
                            target = self[idx]
                        except IndexError:
                            return None
                        return target if target.id.rank != 0 else None
                    if isinstance(idx, ObjId):
                        try:
                            target = self[idx.index]
                        except IndexError:
                            return None
                        return target if target.id == idx else None
                    raise TypeError("index must be int or ObjId instance")
                case (index, rank):
                    try:
                        target = self[index]
                    except IndexError:
                        return None
                    return target if target.id.rank == rank else None
                case _:
                    raise ValueError("the function should have 1 or 2 parameters, "
                                     f"not {len(args)} parameters")

        def __getitem__(self, index: SupportsIndex | slice):
            if isinstance(index, SupportsIndex):
                index = index.__index__()
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
                self._iterate_func_asm = asm.decode(self._code, self.controller.asm_address)
            return _ObjIterator(self.controller, self._iterate_func_asm)

        def reset_stack(self) -> Self:
            if self.obj_num:
                raise PvzStatusError(
                    f"cannot reset stack when there are still {self.obj_num} objects alive")
            next_idx = self.next_index
            self.next_index = 0
            length = self.max_length
            self.max_length = 0
            while next_idx != length:
                t = self.at(next_idx).id
                next_idx = t.index
                t.index = 0
            return self

        def _assert_size(self, size: int) -> Self:
            if size <= (current_len := self.max_length):
                return self
            if self.next_index == current_len:
                self.next_index = size
            else:
                for it in self:
                    if it.id.index == current_len:
                        it.id.index = size
                        break
            self.max_length = size
            node = self.at(current_len)
            node.id.index = self.next_index
            node.is_dead = True
            for i in range(current_len + 1, size):
                node = self.at(i)
                node.id.index = i - 1
                node.is_dead = True
            self.next_index = size - 1
            return self

        def set_next_idx(self, idx: int) -> Self:
            if idx < 0:
                raise ValueError(f"next index should be non-negative, not {idx}")
            if self.at(idx).id.rank != 0:
                raise ValueError(f"object at index {idx} is still unavailable")
            self._assert_size(idx + 1)
            if idx == self.next_index:
                return self
            target_node = self.at(idx)
            first_node = self.at(self.next_index)
            before_node = first_node
            while before_node.id.index != idx:
                before_node = self.at(before_node.id.index)
            before_node.id.index, self.next_index = self.next_index, idx
            target_node.id.index, first_node.id.index = first_node.id.index, target_node.id.index
            return self

    return _ObjListImplement

# -*- coding: utf_8 -*-
"""
描述pvz中数据结构的基类和基本函数.
"""
import abc
import collections.abc as c_abc
import typing
from enum import IntEnum

from basic import asm
from rp_extend import Controller


class ObjBase(abc.ABC):
    """
    pvz中的一个对象

    Attributes:
        base_ptr: 对应pvz中对象的指针
        controller: 对应pvz的Controller对象
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
        super().__init__()
        if base_ptr == 0:
            raise ValueError(f"base_ptr of an {type(self).__name__} object cannot be 0")
        
        self.base_ptr = base_ptr
        self.controller = ctler

    OBJ_SIZE: int = NotImplemented
    """对应pvz类在pvz中的大小, 必须在所有非抽象子类中赋值"""

    def __eq__(self, other: typing.Self) -> bool:
        """
        判断二个ObjBase对象是否指向同一游戏的同一位置

        功能更接近于Python中的is.

        Args:
            other : 另一个ObjBase对象
        """
        return self.base_ptr == other.base_ptr and (self.controller == other.controller)
    
    def __ne__(self, other: typing.Self) -> bool:
        return not (self.base_ptr == other.base_ptr and (self.controller == other.controller))

    def __str__(self) -> str:
        return (f"<{type(self).__name__} object at [0x{self.base_ptr:x}] "
                f"of pid {self.controller.pid}>")

    def __repr__(self) -> str:
        return (f"{type(self).__name__}(base_ptr=0x{self.base_ptr:x}, "
                f"ctler=Controller({self.controller.pid}))")


# property factories 用于生成ObjBase对象在pvz内的属性
def property_bool(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> bool:
        return self.controller.read_bool([self.base_ptr + offset])

    def _set(self: ObjBase, value: bool):
        self.controller.write_bool(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_i8(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> int:
        return self.controller.read_i8([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self.controller.write_i8(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_i16(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> int:
        return self.controller.read_i16([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self.controller.write_i16(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_i32(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> int:
        return self.controller.read_i32([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self.controller.write_i32(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_i64(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> int:
        return self.controller.read_i64([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self.controller.write_i64(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_u8(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> int:
        return self.controller.read_u8([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self.controller.write_u8(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_u16(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> int:
        return self.controller.read_u16([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self.controller.write_u16(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_u32(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> int:
        return self.controller.read_u32([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self.controller.write_u32(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_u64(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> int:
        return self.controller.read_u64([self.base_ptr + offset])

    def _set(self: ObjBase, value: int):
        self.controller.write_u64(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_f32(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> float:
        return self.controller.read_f32([self.base_ptr + offset])

    def _set(self: ObjBase, value: float):
        self.controller.write_f32(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_f64(offset: int, doc: str | None = None):
    def _get(self: ObjBase) -> float:
        return self.controller.read_f64([self.base_ptr + offset])

    def _set(self: ObjBase, value: float):
        self.controller.write_f64(value, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_int_enum(offset: int, cls: type[IntEnum], doc: str | None = None):
    def _get(self: ObjBase) -> cls:
        return cls(self.controller.read_i32([self.base_ptr + offset]))

    def _set(self: ObjBase, value: cls):
        self.controller.write_i32(int(value), [self.base_ptr + offset])

    return property(_get, _set, None, doc)


def property_obj(offset: int, cls: type[ObjBase], doc: str | None = None):
    def _get(self: ObjBase) -> cls:
        return cls(self.controller.read_i32([self.base_ptr + offset]), self.controller)

    def _set(self: ObjBase, value: cls):
        if self.controller != value.controller:
            raise ValueError("cannot assign an object from another controller")
        self.controller.write_i32(value.base_ptr, [self.base_ptr + offset])

    return property(_get, _set, None, doc)


class ObjId(ObjBase):
    """
    ObjNode对象末尾的(index, rank)对象

    游戏内用于ObjNode的识别和储存.
    """

    OBJ_SIZE = 4

    index: int = property_u16(0, "对象索引")

    rank: int = property_u16(2, "对象序列号")

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
            return ((self.controller.read_i32([self.base_ptr]) ==
                    val.controller.read_i32([val.base_ptr]))
                    and self.controller == val.controller)
        try:
            index, rank = val
        except TypeError as te:
            raise TypeError("ObjId can only compare with another ObjId "
                            "or an unpack-able object like (index, rank), "
                            f"not {type(val).__name__} instance") from te
        except ValueError as ve:
            raise ValueError("unpack-able val should have 2 elements (index, rank)") from ve
        return self.controller.read_i32([self.base_ptr]) == ((rank << 16) | index)
    
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


T = typing.TypeVar("T", bound=ObjNode)


class _ObjList(ObjBase, c_abc.Sequence[T], abc.ABC):
    """
    游戏中管理各类对象内存的数组, 即函数表中DataArray对象

    仅帮助type hint用, 请勿直接使用, 而是使用obj_list函数构造.
    """

    OBJ_SIZE = 28

    obj_num: int = property_i32(16, "当前对象数量")

    next_index: int = property_i32(12, "下一个对象的索引")

    next_rank: int = property_i32(20, "下一个对象的序列号")

    def __len__(self):
        return self.controller.read_i32([self.base_ptr + 4])

    def at(self, index: int) -> T:
        """
        返回index对应下标的元素

        Args:
            index: 非负索引, 不做任何检查
        Returns:
            T: 对应下标的元素, 不确保存活
        """

    @typing.overload
    def __getitem__(self, index: int) -> T:
        """
        返回index对应下标的元素

        Args:
            index: 整数索引, 即支持负数索引
        Returns:
            T: 对应下标的元素, 不确保存活
        Raises:
            IndexError: 若index超出范围抛出
        """

    @typing.overload
    def __getitem__(self, index: slice) -> list[T]:
        """
        返回slice切片对应的列表

        若在遍历返回值的时候有新对象生成或死亡, 该方法没法动态调整.

        Args:
            index: 切片索引
        Returns:
            对应切片的列表, 不保证其中任何成员存活
        """

    def __getitem__(self, index):
        ...
    
    def __invert__(self) -> c_abc.Iterator[T]:
        """
        迭代所有未回收对象的迭代器, 利用原版函数在迭代过程中动态寻找下一个对象
        
        Returns:
            迭代器, 仅迭代存活对象
        Examples:
            >>> for objects in ~self:
            迭代所有未回收的对象
        """
    
    @property
    def alive_iterator(self) -> c_abc.Iterator[T]:
        """与__invert__()相同"""
        return self.__invert__()

    def find(self, index: int | ObjId | tuple[int, int]) -> T | None:
        """
        通过index查找对象

        用int查找时, 未回收对象返回T.
        用ObjId或者(index, rank)查找时, 在对应index位置对象rank相同时返回T.

        Args:
            index: 整数索引, ObjId对象或(index, rank)可解包对象
        Returns:
            存在未回收的对应对象返回, 否则返回None.
        Raises:
            TypeError: index不是int, ObjId或可解包对象
            ValueError: 可解包对象不是两个元素
        Example:
            >>> self.find(-1)
            当前最后一个对象(len(self) - 1)未回收时返回, 否则返回None
            >>> self.find((1, 1))
            若idx == 1的对象的rank==1, 返回该对象, 否则返回None
        """


def obj_list(node_cls: type[T]) -> type[_ObjList[T]]:
    """
    根据node_cls构造对应的NodeClsObject的父类
    
    Args:
        node_cls: ObjNode的子类
    Returns:
        管理node_cls对象的数组的父类
    """

    class _ObjIterator(c_abc.Iterator[T]):
        def __init__(self, ctler: Controller, _iterate_func_asm):
            self._current_ptr = 0
            self._controller = ctler
            self._iterate_func_asm = _iterate_func_asm

        def __next__(self) -> T:
            self._controller.result_u64 = self._current_ptr
            self._controller.run_code(self._iterate_func_asm, len(self._iterate_func_asm))
            if (self._controller.result_u64 >> 32) == 0:
                raise StopIteration
            self._current_ptr = self._controller.result_u32
            return node_cls(self._current_ptr, self._controller)

        def __iter__(self):
            return self

    class _ObjListImplement(_ObjList[T], abc.ABC):
        def __init__(self, base_ptr: int, ctler: Controller):
            super().__init__(base_ptr, ctler)
            self._array_base_ptr = ctler.read_i32([base_ptr])
            p_board = ctler.read_u32([0x6a9ec0, 0x768])
            self._code = f"""
                push esi
                push edx
                mov esi, {self.controller.result_address};
                mov edx, {p_board};
                mov ecx, {node_cls.ITERATOR_FUNC_ADDRESS};
                call ecx;
                mov [{self.controller.result_address + 4}], al;
                pop edx
                pop esi
                ret;"""
            
            self._iterate_func_asm = None

        def at(self, index: int) -> T:
            return node_cls(self._array_base_ptr + node_cls.OBJ_SIZE * index, self.controller)

        def find(self, index) -> T | None:
            if isinstance(index, int):
                try:
                    target = self[index]
                except IndexError:
                    return None
                return target if target.id.rank != 0 else None
            if isinstance(index, ObjId):
                target = self.at(index.index)
                return target if target.id == index else None
            try: 
                idx, rank = index
            except TypeError as te:
                raise TypeError("object can only be found by int, ObjId instance "
                                "or an unpack-able object like (index, rank), "
                                f"not {type(index).__name__} instance") from te
            except ValueError as ve:
                raise ValueError("unpack-able index should have two elements (index, rank)") from ve
            target = self.at(idx)
            return target if target.id.rank == rank else None

        def __getitem__(self, index: int | slice):
            if isinstance(index, int):
                i = index if index >= 0 else index + len(self)
                if i >= len(self) or i < 0:
                    raise IndexError("sequence index out of range")
                return self.at(i)
            if isinstance(index, slice):
                start, stop, step = index.indices(len(self))
                return [self.at(i) for i in range(start, stop, step)]
            raise TypeError("index must be int or slice")

        def __invert__(self):
            if self._iterate_func_asm is None:
                self._iterate_func_asm = asm.decode(self._code)
            return _ObjIterator(self.controller, self._iterate_func_asm)

    return _ObjListImplement

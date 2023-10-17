import abc
import collections.abc as c_abc
import typing
from enum import IntEnum

from basic import asm
from rp_extend import Controller


class ObjBase(abc.ABC):
    """
    每一个ObjBase子类代表一个pvz中的类, 
    每一个ObjBase对象代表pvz中的一个对象
    """

    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__()
        self.base_ptr = base_ptr
        self.controller = ctler

    @classmethod
    @abc.abstractmethod
    def obj_size(cls) -> int:
        """
        对应pvz类 在pvz中的大小
        """
        pass

    def __eq__(self, other):
        """
        判断二者是否指向同一位置
        """
        return (self.controller is not other.controller) and self.base_ptr == other.base_ptr

    def __str__(self) -> str:
        return f"<{self.__class__.__name__} object at [0x{self.base_ptr:7x}] of pid {self.controller.pid}>"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(base_ptr=0x{self.base_ptr:7x}, ctler=Controller({self.controller.pid}))"


# property factories 用于生成ObjBase对象在pvz内的属性
def property_bool(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> bool:
        return self.controller.read_bool([self.base_ptr + offset])

    def __fset(self: ObjBase, value: bool):
        self.controller.write_bool(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_i8(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_i8([self.base_ptr + offset])

    def __fset(self: ObjBase, value: int):
        self.controller.write_i8(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_i16(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_i16([self.base_ptr + offset])

    def __fset(self: ObjBase, value: int):
        self.controller.write_i16(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_i32(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_i32([self.base_ptr + offset])

    def __fset(self: ObjBase, value: int):
        self.controller.write_i32(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_i64(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_i64([self.base_ptr + offset])

    def __fset(self: ObjBase, value: int):
        self.controller.write_i64(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_u8(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_u8([self.base_ptr + offset])

    def __fset(self: ObjBase, value: int):
        self.controller.write_u8(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_u16(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_u16([self.base_ptr + offset])

    def __fset(self: ObjBase, value: int):
        self.controller.write_u16(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_u32(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_u32([self.base_ptr + offset])

    def __fset(self: ObjBase, value: int):
        self.controller.write_u32(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_u64(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_u64([self.base_ptr + offset])

    def __fset(self: ObjBase, value: int):
        self.controller.write_u64(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_f32(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> float:
        return self.controller.read_f32([self.base_ptr + offset])

    def __fset(self: ObjBase, value: float):
        self.controller.write_f32(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_f64(offset: int, doc: str | None = None):
    def __fget(self: ObjBase) -> float:
        return self.controller.read_f64([self.base_ptr + offset])

    def __fset(self: ObjBase, value: float):
        self.controller.write_f64(value, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_int_enum(offset: int, cls: typing.Type[IntEnum], doc: str | None = None):
    def __fget(self: ObjBase) -> cls:
        return cls(self.controller.read_i32([self.base_ptr + offset]))

    def __fset(self: ObjBase, value: cls):
        self.controller.write_i32(int(value), [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


def property_obj(offset: int, cls: typing.Type[ObjBase], doc: str | None = None):
    def __fget(self: ObjBase) -> cls:
        return cls(self.controller.read_i32([self.base_ptr + offset]), self.controller)

    def __fset(self: ObjBase, value: cls):
        if self.controller is not value.controller:
            raise ValueError("Cannot assign an object from another controller")
        self.controller.write_i32(value.base_ptr, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


class ObjId(ObjBase):
    """
    ObjNode对象末尾的(index, rank)对象, 游戏内用于ObjNode的识别
    """

    @classmethod
    def obj_size(cls) -> int:
        return 4

    index: int = property_u16(0, "index")

    rank: int = property_u16(2, "rank")

    def __eq__(self, __value: typing.Self | typing.Sequence[int]) -> bool:
        """
        ObjId比较相等 与其他ObjId比较或与(index, rank)比较, "表示相同对象"返回True
        """
        if isinstance(__value, ObjId):
            return self.controller is __value.controller and \
                (self.controller.read_i32([self.base_ptr]) ==
                 __value.controller.read_i32([__value.base_ptr]))
        try:
            return self.controller.read_i32([self.base_ptr]) \
                == ((__value[1] << 16) | __value[0])
        except AttributeError as e:
            raise AttributeError("ObjId can only compare with another ObjId"
                                 "or an index-able object like (index, rank)") from e

    def __str__(self) -> str:
        return f"(index={self.index}, rank={self.rank})"


class ObjNode(ObjBase, abc.ABC):
    """
    Plant Zombie等等, 在pvz中由ObjList数组进行内存管理的对象的父类
    """

    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)
        self.id = ObjId(base_ptr + self.obj_size() - 4, ctler)

    @classmethod
    @abc.abstractmethod
    def iterator_function_address(cls) -> int:
        """
        返回pvz中迭代所有对象的函数地址
        """
        return NotImplemented


T = typing.TypeVar("T", bound=ObjNode)


class _ObjList(ObjBase, c_abc.Sequence[T], abc.ABC):
    """
    游戏中管理各类对象内存的数组类
    """

    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)
        self._array_base_ptr = ctler.read_i32([base_ptr])

    @classmethod
    def obj_size(cls) -> int:
        return 28

    obj_num: int = property_i32(16, "obj_num")

    next_index: int = property_i32(12, "next_index")

    next_rank: int = property_i32(20, "next_rank")

    def __len__(self):
        return self.controller.read_i32([self.base_ptr + 4])

    def at(self, index: int) -> T:
        """
        返回index对应下标的元素, 不做范围检查
        """
        return NotImplemented

    def get_id(self, id_: ObjId | c_abc.Sequence[int]) -> T | None:
        """
        通过ObjId查找对象, 若不存在相等对象则返回None
        """
        return NotImplemented

    @typing.overload
    def __getitem__(self, index: int) -> T:
        pass

    @typing.overload
    def __getitem__(self, index: slice) -> list[T]:
        pass

    def __getitem__(self, index):
        return NotImplemented

    @property
    def alive_iterator(self) -> c_abc.Iterator[T]:
        """
        返回迭代所有活着对象的迭代器
        """
        return NotImplemented


def obj_list(node_cls: typing.Type[T]) -> type[_ObjList[T]]:
    """
    根据ObjNode构造对应的_ObjList作为各个List的父类
    """

    class _ObjIterator(c_abc.Iterator[T]):
        def __init__(self, ctler: Controller):
            self._current_ptr = 0
            self._controller = ctler

        def __next__(self) -> T:
            p_board = self._controller.read_i32([0x6a9ec0, 0x768])
            code = f"""
                        push esi
                        push edx
                        push ebx
                        mov esi, {self._controller.result_address};
                        mov edx, {p_board};
                        mov ebx, {node_cls.iterator_function_address()};
                        call ebx;
                        mov [{self._controller.result_address + 4}], al;
                        pop ebx
                        pop edx
                        pop esi
                        ret;"""
            self._controller.result_u64 = self._current_ptr
            asm.run(code, self._controller)
            if (self._controller.result_u64 >> 32) == 0:
                raise StopIteration
            self._current_ptr = self._controller.result_u32
            return node_cls(self._current_ptr, self._controller)

        def __iter__(self):
            return self

    class __ObjList(_ObjList[T], abc.ABC):

        def at(self, index: int) -> T:
            return node_cls(self._array_base_ptr + node_cls.obj_size() * index, self.controller)

        def get_id(self, id_: ObjId | c_abc.Sequence[int]) -> T | None:
            for it in self:
                if it.id == id_:
                    return it
            return None

        def __getitem__(self, index: int | slice):
            if isinstance(index, int):
                i = index if index >= 0 else index + len(self)
                if i >= len(self) or i < 0:
                    raise IndexError("sequence index out of range")
                return self.at(i)
            if isinstance(index, slice):
                start, stop, step = index.indices(len(self))
                return [self.at(i) for i in range(start, stop, step)]

            raise TypeError("list indices must be integers or slices"
                            f", not {self.__class__.__name__}")

        @property
        def alive_iterator(self):
            return _ObjIterator(self.controller)

    return __ObjList[node_cls]

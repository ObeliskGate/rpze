import abc
import typing
from enum import IntEnum
import collections.abc as c_abc

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
    def SIZE(cls) -> int:
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
    (index, rank)对象, 用于ObjNode的识别
    """
    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)

    @classmethod
    def SIZE(cls) -> int:
        return 4

    index: int = property_u16(0, "index")

    rank: int = property_u16(2, "rank")

    def __eq__(self, __value) -> bool:
        """
        ObjId比较相等 与其他ObjId比较或与[index, rank]比较, "表示相同对象"返回True
        """
        if isinstance(__value, ObjId):
            return self.controller is __value.controller and \
                (self.controller.read_i32([self.base_ptr]) ==
                __value.controller.read_i32([__value.base_ptr]))
        try:
            return self.controller.read_i32([self.base_ptr]) \
                == ((__value[1] << 16) | __value[0])
        except Exception as e:
            print("ObjId can only compare with another ObjId"
                  f"or an index-able object like [index, rank], detail: {e}")
            raise AttributeError("ObjId can only compare with another ObjId"
                                 "or an index-able object like [index, rank]")

    def __str__(self) -> str:
        return f"(index={self.index}, rank={self.rank})"


class ObjNode(ObjBase, abc.ABC):
    """
    Plant Zombie等等, 在pvz中由数组进行内存管理的对象的父类
    """
    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)
        self.id = ObjId(base_ptr + self.SIZE() - 4, ctler)


T = typing.TypeVar("T", bound=ObjNode)


class _ObjList(ObjBase, c_abc.Sequence[T], abc.ABC):

    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)
        self.array_base_ptr = ctler.read_i32([base_ptr])

    @classmethod
    def SIZE(cls) -> int:
        return 28

    max_obj_num: int = property_i32(4, "max_obj_num")

    next_index: int = property_i32(12, "next_index")

    next_rank: int = property_i32(20, "next_rank")

    def __len__(self):
        return self.controller.read_i32([self.base_ptr + 16])

    def at(self, index: int) -> T:
        """
        返回index对应下标的元素, 不做范围检查
        """
        pass

    def get_id(self, id_: ObjId | tuple[int, int]) -> T | None:
        """
        通过ObjId查找对象, 若不存在相等对象则返回None
        """
        pass


def obj_list(node_cls: typing.Type[T]) -> type[_ObjList[T]]:

    class __ObjList(_ObjList[T], abc.ABC):

        def __init__(self, base_ptr: int, ctler: Controller) -> None:
            super().__init__(base_ptr, ctler)

        def at(self, index: int) -> T:
            """
            返回index对应下标的元素, 不做范围检查
            """
            return node_cls(self.array_base_ptr + node_cls.SIZE() * index, self.controller)

        def get_id(self, id_: ObjId | tuple[int, int]) -> T | None:
            for it in self:
                if it.id == id_:
                    return it
            return None

        def __getitem__(self, index: int | slice):
            if isinstance(index, int):
                if index >= len(self):
                    raise IndexError
                return self.at(index)
            if isinstance(index, slice):
                start, stop, step = index.indices(len(self))
                return [self[i] for i in range(start, stop, step)]

            raise TypeError("TypeError: list indices must be integers or slices"
                            f", not {self.__class__.__name__}")

    return __ObjList[node_cls]

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
        if base_ptr == 0:
            raise ValueError(f"base_ptr of an {self.__class__.__name__} object cannot be 0")
        
        self.base_ptr = base_ptr
        self.controller = ctler

    obj_size: int = NotImplemented
    """对应pvz类在pvz中的大小, 必须在所有非抽象子类中赋值"""

    def __eq__(self, other: typing.Self) -> bool:
        """
        判断二个ObjBase对象是否是同一游戏指向同一位置的指针
        功能更接近于Python中的is

        Args:
            other (ObjBase): 另一个ObjBase对象
        """
        return self.base_ptr == other.base_ptr and (self.controller is not other.controller)

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
            raise ValueError("cannot assign an object from another controller")
        self.controller.write_i32(value.base_ptr, [self.base_ptr + offset])

    return property(__fget, __fset, None, doc)


class ObjId(ObjBase):
    """
    ObjNode对象末尾的(index, rank)对象
    游戏内用于ObjNode的识别和储存
    """

    obj_size = 4

    index: int = property_u16(0, "index")

    rank: int = property_u16(2, "rank")

    def __eq__(self, val: typing.Self | tuple[int]) -> bool:
        """
        ObjId比较相等 与其他ObjId比较或与(index, rank)比较
        "表示相同对象"返回True

        Args:
            val (ObjId | tuple[int]): 另一个ObjId对象或(index, rank)元组
        """
        if isinstance(val, ObjId):
            return (self.controller.read_i32([self.base_ptr]) ==
                    val.controller.read_i32([val.base_ptr])) \
                    and self.controller is val.controller
        try:
            index, rank = val
        except TypeError as te:
            raise TypeError("ObjId can only compare with another ObjId"
                            "or an unpackable object like (index, rank), "
                            f"not {self.__class__.__name__} instance") from te
        except ValueError as ve:
            raise ValueError("unpackable val should have two elements (index, rank)") from ve
        return self.controller.read_i32([self.base_ptr]) \
            == ((rank << 16) | index)

    def __str__(self) -> str:
        return f"(index={self.index}, rank={self.rank})"


class ObjNode(ObjBase, abc.ABC):
    """
    Plant Zombie等等, 在pvz中由ObjList数组进行内存管理的对象的父类
    """

    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)
        self.id = ObjId(base_ptr + self.obj_size - 4, ctler)
    
    iterator_function_address: int = NotImplemented
    """返回pvz中迭代对象的函数地址, , 必须在所有非抽象子类中赋值"""


T = typing.TypeVar("T", bound=ObjNode)


class _ObjList(ObjBase, c_abc.Sequence[T], abc.ABC):
    """
    游戏中管理各类对象内存的数组类
    """

    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)
        self._array_base_ptr = ctler.read_i32([base_ptr])

    obj_size = 28

    obj_num: int = property_i32(16, "obj_num")

    next_index: int = property_i32(12, "next_index")

    next_rank: int = property_i32(20, "next_rank")

    def __len__(self):
        return self.controller.read_i32([self.base_ptr + 4])

    def at(self, index: int) -> T:
        """
        返回index对应下标的元素

        Args:
            index (int): 非负索引, 不做任何检查

        Returns
            T: 对应下标的元素, 不确保存活
        """
        return NotImplemented

    @typing.overload
    def __getitem__(self, index: int) -> T:
        """
        返回index对应下标的元素

        Args:
            index (int): 整数索引, 支持

        Returns:
            T: 对应下标的元素, 不确保存活
        """
        ...

    @typing.overload
    def __getitem__(self, index: slice) -> list[T]:
        """
        返回slice切片对应的列表
        若在遍历返回值的时候有新对象生成或死亡, 该方法没法动态调整

        Args:
            index (slice): 整数索引, 支持负数索引, 若超出范围则IndexError
        Returns:
            list[T]: 对应切片的列表, 不保证其中任何成员存活
        """
        ...

    def __getitem__(self, index):
        return NotImplemented

    @property
    def alive_iterator(self) -> c_abc.Iterator[T]:
        """
        返回迭代所有活着对象的迭代器

        Returns:
            c_abc.Iterator[T]: 迭代所有存活对象的"动态"迭代器, 即, 在迭代过程中动态寻找下一个对象
        """
        return NotImplemented

    def find(self, index: int | ObjId | tuple[int]) -> T | None:
        """
        通过index查找对象, 不支持负数索引
        用int查找时, 活对象返回T
        用ObjId或者(index, rank)查找时, 在对应index位置对象rank相同时返回T
        Args:
            index (ObjId | tuple[int] | int): 索引, ObjId对象或(index, rank)元组
        Returns:
            T | None: , 存在活着的对应对象返回, 否则返回None.
        """
        return NotImplemented


def obj_list(node_cls: typing.Type[T]) -> type[_ObjList[T]]:
    """
    根据node_cls构造对应的_ObjList作为各个NodeClsList的父类
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
        def __init__(self, base_ptr: int, ctler: Controller) -> None:
            super().__init__(base_ptr, ctler)
            p_board = ctler.read_u32([0x6a9ec0, 0x768])
            code = f"""
                        push esi
                        push edx
                        push ebx
                        mov esi, {self.controller.result_address};
                        mov edx, {p_board};
                        mov ebx, {node_cls.iterator_function_address};
                        call ebx;
                        mov [{self.controller.result_address + 4}], al;
                        pop ebx
                        pop edx
                        pop esi
                        ret;"""
            
            self._iterate_func_asm = asm.decode(code)

        def at(self, index: int) -> T:
            return node_cls(self._array_base_ptr + node_cls.obj_size * index, self.controller)

        def find(self, index) -> T | None:
            if isinstance(index, int):
                target = self.at(index)
                return target if target.id.rank != 0 else None
            if isinstance(index, ObjId):
                target = self.at(index.index)
                return target if target.id == index else None
            try: 
                idx, rank = index
            except TypeError as te:
                raise TypeError("object can only be found by ObjId, index"
                                "or an unpackable object like (index, rank), "
                                f"not {self.__class__.__name__} instance") from te
            except ValueError as ve:
                raise ValueError("unpackable index should have two elements (index, rank)") from ve
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

        @property
        def alive_iterator(self):
            return _ObjIterator(self.controller, self._iterate_func_asm)

    return _ObjListImplement[node_cls]

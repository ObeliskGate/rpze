import typing
from rp_extend import Controller
import abc
from enum import IntEnum

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
        类代表对象 在pvz中的大小
        """
        pass
    
    def __eq__(self, other):
        """
        判断二者是否指向同一位置
        """
        if not isinstance(other, ObjBase):
            raise TypeError("The right value must be an ObjBase instance")
        return (self.controller is not other.controller) and self.base_ptr == other.base_ptr
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} object at [0x{self.base_ptr:7x}] of pid {self.controller.pid}>"

def property_bool(offset: bool, doc: str | None=None):
    def __fget(self: ObjBase) -> bool:
        return self.controller.read_bool([self.base_ptr + offset])
    def __fset(self: ObjBase, value: bool):
        self.controller.write_bool(value, [self.base_ptr + offset])
    return property(__fget, __fset, None, doc)

def property_i8(offset: int, doc: str | None=None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_i8([self.base_ptr + offset])
    def __fset(self: ObjBase, value: int):
        self.controller.write_i8(value, [self.base_ptr + offset])
    return property(__fget, __fset, None, doc)


def property_i16(offset: int, doc: str | None=None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_i16([self.base_ptr + offset])
    def __fset(self: ObjBase, value: int):
        self.controller.write_i16(value, [self.base_ptr + offset])    
    return property(__fget, __fset, None, doc)

def property_i32(offset: int, doc: str | None=None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_i32([self.base_ptr + offset])
    def __fset(self: ObjBase, value: int):
        self.controller.write_i32(value, [self.base_ptr + offset])    
    return property(__fget, __fset, None, doc)    

def property_i64(offset: int, doc: str | None=None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_i64([self.base_ptr + offset])
    def __fset(self: ObjBase, value: int):
        self.controller.write_i64(value, [self.base_ptr + offset])    
    return property(__fget, __fset, None, doc)

def property_u8(offset: int, doc: str | None=None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_u8([self.base_ptr + offset])
    def __fset(self: ObjBase, value: int):
        self.controller.write_u8(value, [self.base_ptr + offset])
    return property(__fget, __fset, None, doc)

def property_u16(offset: int, doc: str | None=None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_u16([self.base_ptr + offset])
    def __fset(self: ObjBase, value: int):
        self.controller.write_u16(value, [self.base_ptr + offset])    
    return property(__fget, __fset, None, doc)

def property_u32(offset: int, doc: str | None=None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_u32([self.base_ptr + offset])
    def __fset(self: ObjBase, value: int):
        self.controller.write_u32(value, [self.base_ptr + offset])    
    return property(__fget, __fset, None, doc)

def property_u64(offset: int, doc: str | None=None):
    def __fget(self: ObjBase) -> int:
        return self.controller.read_u64([self.base_ptr + offset])
    def __fset(self: ObjBase, value: int):
        self.controller.write_u64(value, [self.base_ptr + offset])    
    return property(__fget, __fset, None, doc)

def property_f32(offset: int, doc: str | None=None):
    def __fget(self: ObjBase) -> float:
        return self.controller.read_f32([self.base_ptr + offset])
    def __fset(self: ObjBase, value: float):
        self.controller.write_f32(value, [self.base_ptr + offset])    
    return property(__fget, __fset, None, doc)

def property_f64(offset: int, doc: str | None=None):
    def __fget(self: ObjBase) -> float:
        return self.controller.read_f64([self.base_ptr + offset])
    def __fset(self: ObjBase, value: float):
        self.controller.write_f64(value, [self.base_ptr + offset])    
    return property(__fget, __fset, None, doc)

def property_int_enum(offset: int, cls: typing.Type[IntEnum], doc: str | None=None):
    def __fget(self: ObjBase) -> cls:
        return cls(self.controller.read_i32([self.base_ptr + offset]))
    def __fset(self: ObjBase, value: cls):
        self.controller.write_i32(int(value), [self.base_ptr + offset])    
    return property(__fget, __fset, None, doc)

def property_obj(offset: int, cls: typing.Type[ObjBase], doc: str|None=None):
    def __fget(self: ObjBase) -> cls:
        return cls(self.controller.read_i32([self.base_ptr + offset]), self.controller)
    def __fset(self: ObjBase, value: cls):
        if (self.controller is not value.controller):
            raise ValueError("Cannot assign an object from another controller")
        self.controller.write_i32(value.base_ptr, [self.base_ptr + offset])    
    return property(__fget, __fset, None, doc)

class ObjId(ObjBase):
    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)

    @property
    @classmethod
    def SIZE(cls) -> int:
        return 4
    
    index: int = property_u16(0, "index")
    rank: int = property_u16(2, "rank")

    def __eq__(self, __value) -> bool:
        """
            ObjId比较相等 与其他ObjId比较或与(index, rank)比较, "表示相同对象"返回True
        """
        if (isinstance(__value, ObjId)):
            return  self.controller is __value.controller and \
                (self.controller.read_i32([self.base_ptr + 0]) ==
                __value.controller.read_i32([__value.base_ptr + 0]))
        if (isinstance(__value, tuple) and len(__value) == 2):
            return  self.controller.read_i32([self.base_ptr + 0]) \
                == ((__value[1] << 16) | __value[0]) 
        raise TypeError("The right value must be either an ObjId instance or an (index, rank) tuple")
    
    def __str__(self) -> str:
        return f"(index={self.index}, rank={self.rank})"
    
class ObjNode(ObjBase, abc.ABC):
    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)
        self.id = ObjId(base_ptr + self.SIZE() - 4, ctler)

    def __repr__(self) -> str:
        return f"#{self.id.index}" + super().__repr__()
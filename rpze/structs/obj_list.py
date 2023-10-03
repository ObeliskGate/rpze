
class ObjNode:
    def __init__(self, obj) -> None:
        self.obj = obj
        self.base_ptr = obj.base_ptr
        self.size = obj.SIZE 
        self.ctler = obj.ctler
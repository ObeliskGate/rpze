# -*- coding: utf_8 -*- 
from functools import lru_cache
from rp_extend import Controller
import keystone as ks


def run(code: str, controller: Controller) -> bool:
    """
    执行code汇编码
    
    Args:
        code: x86 intel格式汇编字符串, 应该是一个(void) -> void函数, 即以"ret"结尾并且保持栈平衡
        controller: Controller对象, 用于执行汇编码
    Returns:
        执行成功返回True
    """
    r = decode(code)
    return controller.run_code(r, len(r))
    

__keystone_assembler = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)


@lru_cache()
def decode(code: str) -> bytes:
    """
    解码code汇编码
    
    Args:
        code: x86 intel格式汇编字符串
    Returns:
        解码后的字节码
    Raises:
        RuntimeError: 汇编码错误
    """
    try:
        asm, _ = __keystone_assembler.asm(code, as_bytes=True)
        return asm
    except ks.KsError as e:
        raise RuntimeError(f"asm error, {e}") from e

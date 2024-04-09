# -*- coding: utf_8 -*-
"""
异常类.
"""
from ..rp_extend import RpBaseException


class PvzStateError(RpBaseException):
    """
    pvz状态异常

    当pvz游戏状态不满足要求时抛出.
    """
    pass


class AsmError(RpBaseException):  # 作为keystone error包装使用, 万一哪天换汇编器了
    """
    汇编码编译异常

    当汇编码执行出现问题时抛出.
    """
    pass

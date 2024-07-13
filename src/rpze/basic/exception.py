# -*- coding: utf_8 -*-
"""
异常类.
"""
from ..rp_extend import RpBaseException


class PvzStatusError(RpBaseException):
    """
    pvz 状态异常

    当 pvz 游戏状态不满足要求时抛出.
    """


class AsmError(RpBaseException):  # 作为 keystone error 包装使用, 万一哪天换汇编器了
    """
    汇编码编译异常

    当汇编码执行出现问题时抛出.
    """

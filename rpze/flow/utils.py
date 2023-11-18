# -*- coding: utf_8 -*-
"""
简化flow编写的工具函数
"""
from flow import FlowRunner, CondFunc


# flow utils
def until(time: int) -> CondFunc:
    return lambda fr: fr.time == time


def delay(time: int, fr: FlowRunner) -> CondFunc:
    return until(fr.time + time)

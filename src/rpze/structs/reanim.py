# -*- coding: utf_8 -*-
"""
描述 pvz 中动画文件 Reanimation 的相关结构
"""
from typing import Self

from .obj_base import ObjNode, property_bool, obj_list
from ..basic import asm


class Reanim(ObjNode):
    OBJ_SIZE = 0xa0

    is_dead = property_bool(0x14, "is dead")

    ITERATOR_FUNC_ADDRESS = 0x41CB90

    ITERATOR_P_BOARD_REG = "eax"

    def get_track_velocity(self) -> float:
        ctler = self.controller
        code = f"""
            mov eax, {self.base_ptr}
            mov edx, {0x4738D0} // Reanimation::GetTrackVelocity(eax = Reanimation* this)
            call edx
            fstp qword ptr[{ctler.result_address}]
            ret"""
        asm.run(code, ctler)
        return ctler.result_f64


class ReanimList(obj_list(Reanim)):
    def free_all(self) -> Self:
        code = f"""
            push ebx
            push edi
            push esi
            mov eax, [0x6a9ec0]
            mov edi, [eax + 0x768]
            mov esi, {self.controller.result_address}
            xor edx, edx
            mov [esi], edx  // esi for ra, edi for board
            LIterate:
                mov {Reanim.ITERATOR_P_BOARD_REG}, edi
                call {Reanim.ITERATOR_FUNC_ADDRESS}  // Board::IterateReanim
                test al, al
                jz LFreeAll
                mov ecx, [esi]
                call {0x4733F0}  // Reanimation::ReanimationDie(ecx)
                jmp LIterate
                
            LFreeAll:
                mov ebx, {self.base_ptr}
                call {0x446a80}  // DataArray<Zombie>::DataArrayFreeAll(ebx)
                pop esi
                pop edi
                pop ebx
                ret"""

        asm.run(code, self.controller)
        return self

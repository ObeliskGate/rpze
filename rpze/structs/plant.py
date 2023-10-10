from structs.obj_base import ObjNode
import structs.obj_base as ob
from rp_extend import Controller
import basic.asm as asm
from enum import IntEnum

class PlantType(IntEnum):
    none = -1,
    pea_shooter = 0x0,
    sunflower = 0x1,
    cherry_bomb = 0x2,
    wallnut = 0x3,
    potato_mine = 0x4,
    snow_pea = 0x5,
    chomper = 0x6,
    repeater = 0x7,
    puffshroom = 0x8,
    sunshroom = 0x9,
    fumeshroom = 0xA,
    grave_buster = 0xB,
    hypnoshroom = 0xC,
    scaredyshroom = 0xD,
    iceshroom = 0xE,
    doomshroom = 0xF,
    lily_pad = 0x10,
    squash = 0x11,
    threepeater = 0x12,
    tangle_kelp = 0x13,
    jalapeno = 0x14,
    spikeweed = 0x15,
    torchwood = 0x16,
    tallnut = 0x17,
    seashroom = 0x18,
    plantern = 0x19,
    cactus = 0x1a,
    blover = 0x1b,
    split_pea = 0x1c,
    starfruit = 0x1d,
    pumpkin = 0x1e,
    magnetshroom = 0x1f,
    cabbagepult = 0x20,
    flower_pot = 0x21,
    kernelpult = 0x22,
    coffee_bean = 0x23,
    garlic = 0x24,
    umbrella_leaf = 0x25,
    marigold = 0x26,
    melonpult = 0x27,
    gatling_pea = 0x28,
    twin_sunflower = 0x29,
    gloomshroom = 0x2A,
    cattail = 0x2B,
    winter_melon = 0x2C,
    gold_magnet = 0x2D,
    spikerock = 0x2E,
    cob_cannon = 0x2F,
    imitater = 0x30

class PlantStatus(IntEnum):
    idle = 0x0,
    wait = 0x1,
    work = 0x2,
    squash_look = 0x3,
    squash_jump_up = 0x4,
    squash_stop_in_the_air = 0x5,
    squash_jump_down = 0x6,
    squash_crushed = 0x7,
    grave_buster_land = 0x8,
    grave_buster_idle = 0x9,
    chomper_bite_begin = 0xA,
    chomper_bite_success = 0xB,
    chomper_bite_fail = 0xC,
    chomper_chew = 0xD,
    chomper_swallow = 0xE,
    potato_sprout_out = 0xF,
    potato_armed = 0x10,
    spike_attack = 0x12,
    scaredyshroom_scared = 0x14,
    scaredyshroom_scared_idle = 0x15,
    scaredyshroom_grow = 0x16,
    sunshroom_small = 0x17,
    sunshroom_grow = 0x18,
    sunshroom_big = 0x19,
    magnetshroom_working = 0x1A,
    magnetshroom_inactive_idle = 0x1B,
    cactus_short_idle = 0x1E,
    cactus_grow_tall = 0x1F,
    cactus_tall_idle = 0x20,
    cactus_get_short = 0x21,
    tangle_kelp_grab = 0x22,
    cob_cannon_unaramed_idle = 0x23,
    cob_cannon_charge = 0x24,
    cob_cannon_launch = 0x25,
    cob_cannon_aramed_idle = 0x26,
    kernelpult_launch_butter = 0x27,
    umbrella_leaf_block = 0x28,
    umbrella_leaf_shrink = 0x29,
    imitater_explode = 0x2A,
    flower_pot_placed = 0x2F,
    lily_pad_placed = 0x30

class AttactFlags(IntEnum):
    ground = 0x1,
    flying_balloon = 0x2,
    lurking_snorkel = 0x4,
    animating_zombies = 0x10,
    dying_zombies = 0x20,
    digging_digger = 0x40,
    hypno_zombies = 0x80,

class Plant(ObjNode):
    def __init__(self, base_ptr: int, ctler: Controller) -> None:
        super().__init__(base_ptr, ctler)

    @classmethod
    def SIZE(cls) -> int:
        return 0x14c

    x: int = ob.property_i32(0x8, "x")

    y: int = ob.property_i32(0xc, "y")

    attact_box_width: int = ob.property_i32(0x10, "attact_box_width")

    attaxt_box_height: int = ob.property_i32(0x14, "attact_box_height")

    visible: bool = ob.property_bool(0x18, "visible")

    row: int = ob.property_i32(0x1c, "row")

    _type: PlantType = ob.property_int_enum(0x24, PlantType, "plant_type")

    col: int = ob.property_i32(0x28, "col")

    status: PlantStatus = ob.property_int_enum(0x3c, PlantStatus, "status")
    # 属性倒计时, 如磁铁, 大嘴
    status_countdown: int = ob.property_i32(0x54, "status_countdown")
    # 子弹生成 / 物品生产倒计时
    generate_countdown: int = ob.property_i32(0x58, "generate_countdown")
    # 发射子弹间隔 **这里有坑, 平常常见的大喷49等数据是做减法减出来的而不是存在这里的直接数据**
    launch_countdown: int = ob.property_i32(0x5c, "launch_countdown")

    can_attack: bool = ob.property_bool(0x48, "can_attack")

    is_dead: bool = ob.property_bool(0x141, "is_dead")



    def __str__(self) -> str:
        return f"#{self.id.index} {self._type.name} at {self.row + 1}-{self.col + 1}"


def plain_new_plant(row: int, col: int, _type: PlantType, ctler: Controller) -> Plant:
    p_board = ctler.read_i32([0x6a9ec0, 0x768])
    code = f'''
        push edx;
        push -1;
        push {int(_type)};
        push {row};
        push {col};
        mov eax, {p_board};
        mov edx, 0x40CE20;  // Board::NewPlant
        call edx;
        mov [{ctler.result_address}], eax;
        pop edx;
        ret;'''
    asm.run(code, ctler)
    return Plant(ctler.result_i32, ctler)
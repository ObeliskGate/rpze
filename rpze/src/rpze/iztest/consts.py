# -*- coding: utf_8 -*-
"""
ize常数, 常见表
"""
from enum import Enum, auto

from ..structs.plant import PlantType
from ..structs.zombie import ZombieType

ize_plant_types: set[PlantType] = {
    PlantType.pea_shooter,
    PlantType.sunflower,
    PlantType.wallnut,
    PlantType.potato_mine,
    PlantType.snow_pea,
    PlantType.chomper,
    PlantType.repeater,
    PlantType.puffshroom,
    PlantType.fumeshroom,
    PlantType.scaredyshroom,
    PlantType.squash,
    PlantType.threepeater,
    PlantType.spikeweed,
    PlantType.torchwood,
    PlantType.split_pea,
    PlantType.starfruit,
    PlantType.magnetshroom,
    PlantType.kernelpult,
    PlantType.umbrella_leaf
}
"""所有ize中出现的植物"""

ize_zombie_types: set[ZombieType] = {
    ZombieType.imp,
    ZombieType.conehead,
    ZombieType.pole_vaulting,
    ZombieType.buckethead,
    ZombieType.bungee,
    ZombieType.digger,
    ZombieType.ladder,
    ZombieType.football,
    ZombieType.dancing
}
"""所有ize中出现的僵尸"""

plant_abbr_to_type: dict[str, PlantType | None] = {
    ".": None,
    "1": PlantType.pea_shooter,
    "h": PlantType.sunflower,
    "o": PlantType.wallnut,
    "t": PlantType.potato_mine,
    "b": PlantType.snow_pea,
    "z": PlantType.chomper,
    "2": PlantType.repeater,
    "p": PlantType.puffshroom,
    "d": PlantType.fumeshroom,
    "x": PlantType.scaredyshroom,
    "w": PlantType.squash,
    "3": PlantType.threepeater,
    "_": PlantType.spikeweed,
    "j": PlantType.torchwood,
    "l": PlantType.split_pea,
    "5": PlantType.starfruit,
    "c": PlantType.magnetshroom,
    "y": PlantType.kernelpult,
    "s": PlantType.umbrella_leaf
}
"""植物缩写到植物类型的字典"""

zombie_abbr_to_type: dict[str, ZombieType] = {
    "xg": ZombieType.imp,
    "lz": ZombieType.conehead,
    "cg": ZombieType.pole_vaulting,
    "tt": ZombieType.buckethead,
    "bj": ZombieType.bungee, "xt": ZombieType.bungee,
    "kg": ZombieType.digger,
    "tz": ZombieType.ladder, "ft": ZombieType.ladder,
    "gl": ZombieType.football,
    "ww": ZombieType.dancing, "mj": ZombieType.dancing
}
"""僵尸缩写到僵尸类型的字典"""


class Theme(Enum):
    HOTCHPOTCH = auto()
    """综合"""
    KERNELS = auto()
    """控制"""
    INSTANTS = auto()
    """即死"""
    PEAS = auto()
    """输出"""
    POTATOES = auto()
    """爆炸"""
    STARFRUITS = auto()
    """倾斜"""
    MAGNETS = auto()
    """穿刺"""
    SCAREDIES = auto()
    """回复"""

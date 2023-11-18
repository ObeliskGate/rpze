# -*- coding: utf_8 -*-
"""
iztools 全场测试功能模拟
"""

from structs.plant import Plant, PlantType
from structs.zombie import ZombieType

plant_abbr_to_type: dict[str, PlantType] = {
    ".": PlantType.none,
    "1": PlantType.pea_shooter,
    "h": PlantType.sunflower,
    "o": PlantType.wallnut,
    "t": PlantType.potato_mine,
    "b": PlantType.snow_pea,
    "z": PlantType.chomper,
    "2": PlantType.repeater,
    "p": PlantType.puffshroom,
    "d": PlantType.doomshroom,
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


def parse_plant_type_list(plant_type_string: str) -> list[list[PlantType]]:
    return []
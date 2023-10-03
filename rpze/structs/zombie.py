from rp_extend import Controller
from enum import IntEnum
# 数据结构和pvz_emulator命名保持一致

class ZombieType(IntEnum):
    none = -1,
    zombie = 0x0,
    flag = 0x1,
    conehead = 0x2,
    pole_vaulting = 0x3,
    buckethead = 0x4,
    newspaper = 0x5,
    screendoor = 0x6,
    football = 0x7,
    dancing = 0x8,
    backup_dancer = 0x9,
    ducky_tube = 0xa,
    snorkel = 0xb,
    zomboni = 0xc,
    dolphin_rider = 0xe,
    jack_in_the_box = 0xf,
    balloon = 0x10,
    digger = 0x11,
    pogo = 0x12,
    yeti = 0x13,
    bungee = 0x14,
    ladder = 0x15,
    catapult = 0x16,
    gargantuar = 0x17,
    imp = 0x18,
    giga_gargantuar = 0x20

class ZombieStatus(IntEnum):
    walking = 0x0,
    dying = 0x1,
    dying_from_instant_kill = 0x2,
    dying_from_lawnmower = 0x3,
    bungee_target_drop = 0x4,
    bungee_body_drop = 0x5,
    bungee_idle_after_drop = 0x6,
    bungee_grab = 0x7,
    bungee_raise = 0x8,
    bungee_idle = 0xa,
    pole_valuting_running = 0xb,
    pole_valuting_jumpping = 0xc,
    pole_vaulting_walking = 0xd,
    rising_from_ground = 0xe,
    jackbox_walking = 0xf,
    jackbox_pop = 0x10,
    pogo_with_stick = 0x14,
    pogo_idle_before_target = 0x15,
    pogo_jump_across = 0x1b,
    newspaper_walking = 0x1d,
    newspaper_destoryed = 0x1e,
    newspaper_running = 0x1f,
    digger_dig = 0x20,
    digger_drill = 0x21,
    digger_lost_dig = 0x22,
    digger_landing = 0x23,
    digger_dizzy = 0x24,
    digger_walk_right = 0x25,
    digger_walk_left = 0x26,
    digger_idle = 0x27,
    dancing_moonwalk = 0x28,
    dancing_point = 0x29,
    dancing_wait_summoning = 0x2a,
    dancing_summoning = 0x2b,
    dancing_walking = 0x2c,
    dancing_armrise1 = 0x2d,
    dancing_armrise2 = 0x2e,
    dancing_armrise3 = 0x2f,
    dancing_armrise4 = 0x30,
    dancing_armrise5 = 0x31,
    backup_spawning = 0x32,
    dophin_walk_with_dophin = 0x33,
    dophin_jump_in_pool = 0x34,
    dophin_ride = 0x35,
    dophin_jump = 0x36,
    dophin_walk_in_pool = 0x37,
    dophin_walk_without_dophin = 0x38,
    snorkel_walking = 0x39,
    snorkel_jump_in_the_pool = 0x3a,
    snorkel_swim = 0x3b,
    snorkel_up_to_eat = 0x3c,
    snorkel_eat = 0x3d,
    snorkel_finied_eat = 0x3e,
    catapult_shoot = 0x43,
    catapult_idle = 0x44,
    balloon_flying = 0x49,
    balloon_falling = 0x4a,
    balloon_walking = 0x4b,
    imp_flying = 0x47,
    imp_landing = 0x48,
    gargantuar_throw = 0x45,
    gargantuar_smash = 0x46,
    ladder_walking = 0x4c,
    ladder_placing = 0x4d,
    yeti_escape = 0x5b
    
class ZombieAction(IntEnum):
    none = 0x0,
    entering_pool = 0x1,
    leaving_pool = 0x2,
    caught_by_kelp = 0x3,
    climbing_ladder = 0x6,
    falling = 0x7,
    fall_from_sky = 0x9
    
class ZombieAccessoriesType1(IntEnum):
    none = 0x0,
    roadcone = 0x1,
    bucket = 0x2,
    football_cap = 0x3,
    miner_hat = 0x4
    
class ZombieAccessoriesType2(IntEnum):
    none = 0x0,
    screen_door = 0x1,
    newspaper = 0x2,
    ladder = 0x3,

class Zombie:
    
    def __init__(self, ctler: Controller, base_ptr: int):
        self.ctler = ctler
        self.base_ptr = base_ptr
        
    SIZE = 0x158

    @property
    def int_x(self) -> int:
        return self.ctler.read_i32([self.base_ptr + 0x8])
        
    @property.setter
    def int_x(self, val: int):
        self.ctler.write_i32(val, self.base_ptr + 0x8)
        
    @property
    def int_y(self) -> int:
        return self.ctler.read_i32([self.base_ptr + 0xc])
    
    @property.setter
    def int_y(self, val: int):
        self.ctler.write_i32(val, [self.base_ptr + 0xc])
        
    @property
    def width(self) -> int:
        return self.ctler.read_i32([self.base_ptr + 0x10])
    
    @property.setter
    def width(self, val: int):
        self.ctler.write_i32(val, [self.base_ptr + 0x10])
        
    @property
    def height(self) -> int:
        return self.ctler.read_i32([self.base_ptr + 0x14])
    
    @property.setter
    def height(self, val: int):
        self.ctler.write_i32(val, [self.base_ptr + 0x14])
        
    @property
    def row(self):
        return self.ctler.read_i32([self.base_ptr + 0x1c])
    
    @property.setter
    def row(self, val: int):
        self.ctler.write_i32(val, [self.base_ptr + 0x1c])
        
    @property
    def zombie_type(self) -> ZombieType:
        return ZombieType(self.ctler.read_i32([self.base_ptr + 0x24]))
    
    @property.setter
    def zombie_type(self, val: ZombieType):
        self.ctler.write_i32(val, [self.base_ptr + 0x24])
        
    @property
    def status(self) -> ZombieStatus:
        return ZombieStatus(self.ctler.read_i32([self.base_ptr + 0x28]))
    
    @property.setter
    def status(self, val: ZombieStatus):
        self.ctler.write_i32(val, [self.base_ptr + 0x28])
        
    @property
    def x(self) -> float:
        return self.ctler.read_f32([self.base_ptr + 0x2c])
    
    @property.setter
    def x(self, val: float):
        self.ctler.write_f32(val, [self.base_ptr + 0x2c])
        
    @property
    def y(self) -> float:
        return self.ctler.read_f32([self.base_ptr + 0x30])
    
    @property.setter
    def y(self, val: float):
        self.ctler.write_f32(val, [self.base_ptr + 0x30])
        
    # x的变化率, 横向速度
    @property
    def dx(self) -> float:
        return self.ctler.read_f32([self.base_ptr + 0x34])
    
    @property.setter
    def dx(self, val: float):
        self.ctler.write_f32(val, [self.base_ptr + 0x34])
        
    @property
    def is_eating(self) -> bool:
        return self.ctler.read_i8([self.base_ptr + 0x50]) == 1
    
    @property.setter
    def is_eating(self, val: bool):
        self.ctler.write_i8(1 if val else 0, [self.base_ptr + 0x50])
        
    # 闪光倒计时
    @property
    def flash_cowntdown(self) -> int:
        return self.ctler.read_i32([self.base_ptr + 0x54])
    
    @property.setter
    def flash_cowntdown(self, val: int):
        self.ctler.write_i32(val, [self.base_ptr + 0x54])
        
    @property
    def time_since_spawn(self) -> int:
        return self.ctler.read_i32([self.base_ptr + 0x60])
    
    @property.setter
    def time_since_spawn(self, val: int):
        self.ctler.write_i32(val, [self.base_ptr + 0x60])
        
    @property
    def action(self) -> ZombieAction:
        return ZombieAction(self.ctler.read_i32([self.base_ptr + 0x64]))
    
    @property.setter
    def action(self, val: ZombieAction):
        self.ctler.write_i32(val, [self.base_ptr + 0x64])

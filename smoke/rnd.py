"""Destructive RND integration smoke: replaces the current IZombie fixture.

Set RP_GAME_PATH and run python smoke/rnd.py. --auto-enter uses the project's
real enter_ize helper instead of requiring manual entry; it destroys saved setup.
"""
from __future__ import annotations

import argparse
import math
import struct

from rpze.basic import asm
from rpze.basic.inject import InjectedGame
from rpze.rp_extend import (
    RND_EXACT_CAPACITY,
    Controller,
    ControllerError,
    ObjType,
    ObjUuid,
    RndHook,
    SyncMethod,
)
from rpze.structs import game_board as game_board_module
from rpze.structs.game_board import GameBoard, get_board
from rpze.structs.griditem import GriditemType
from rpze.structs.plant import PlantType
from rpze.structs.zombie import ZombieType


IZOMBIE_BRAIN_ROWS = tuple(range(5))


def assert_izombie_brains(board: GameBoard) -> None:
    """确认下一次引擎帧开始前,五行都有存活且有血量的脑子."""
    brains = [
        brain
        for brain in board.griditem_list.alive_iterator
        if brain.type_ == GriditemType.IZOMBIE_BRAIN
    ]
    assert len(brains) == len(IZOMBIE_BRAIN_ROWS), brains
    assert {brain.row for brain in brains} == set(IZOMBIE_BRAIN_ROWS)
    for brain in brains:
        assert brain.brain_hp > 0
        assert not brain.is_dead


def prepare_board(controller: Controller, board: GameBoard) -> None:
    """清空场景,并在第一次跳帧前恢复完整的五行 IZombie 脑子."""
    for objects in (
        board.plant_list,
        board.zombie_list,
        board.projectile_list,
        board.griditem_list,
    ):
        objects.free_all()

    # free_all 后不能立刻跑无脑帧;先一次性补齐五行,再让引擎统一处理.
    for row in IZOMBIE_BRAIN_ROWS:
        brain = board.new_iz_brain(row)
        assert brain.row == row and brain.brain_hp > 0 and not brain.is_dead
    assert_izombie_brains(board)
    controller.skip_frames(1)


def integer_birth(controller: Controller, board: GameBoard) -> None:
    """验证整数 RND 的出生即时字段,死亡回收和槽位复用契约."""
    hook = RndHook.PLANT_ATTACK_INITIAL
    # 这是根据当前计数器和空闲链的预测,不是向游戏预留 UUID 或槽位.
    predicted = ObjUuid(
        controller.get_obj_next_uuid_cnt(ObjType.PLANT),
        board.plant_list.next_index,
        ObjType.PLANT,
    )
    controller.rnd_set_default(hook, 11)
    controller.rnd_set(hook, predicted, 7)
    plant = board.new_plant(0, 0, PlantType.PEASHOOTER)

    # 出生返回后先检查 UUID 和字段;帧推进可能改变字段,不能代替这个即时契约.
    assert plant.uuid == predicted
    assert plant.generate_cd == 7, plant.generate_cd
    assert_izombie_brains(board)
    controller.skip_frames(1)

    other = board.new_plant(1, 0, PlantType.PEASHOOTER)
    other_uuid = other.uuid
    assert other.generate_cd == 11, other.generate_cd
    assert controller.rnd_get(hook, other_uuid) is None
    assert_izombie_brains(board)
    controller.skip_frames(1)

    plant.die()
    # die 只标记删除;必须先让完整游戏帧回收,再检查旧 UUID 已失效.
    assert_izombie_brains(board)
    controller.skip_frames(1)
    assert controller.get_obj_base_ptr(predicted) == 0
    assert board.find(predicted) is None

    board.plant_list.set_next_idx(predicted.index)
    replacement = board.new_plant(0, 0, PlantType.PEASHOOTER)
    replacement_uuid = replacement.uuid
    assert replacement_uuid != predicted
    assert replacement_uuid.index == predicted.index
    assert replacement.generate_cd == 11
    # 复用同一个槽位仍是新的一次分配,不能命中过期 UUID 的配置.
    assert_izombie_brains(board)
    controller.skip_frames(1)
    assert controller.rnd_get(hook, predicted) == 7
    assert controller.rnd_remove(hook, predicted)
    controller.rnd_clear(hook)
    assert not controller.rnd_enabled(hook)

    other.die()
    assert_izombie_brains(board)
    controller.skip_frames(1)
    assert controller.get_obj_base_ptr(other_uuid) == 0
    assert board.find(other_uuid) is None

    replacement.die()
    assert_izombie_brains(board)
    controller.skip_frames(1)
    assert controller.get_obj_base_ptr(replacement_uuid) == 0
    assert board.find(replacement_uuid) is None
    print(
        'PASS PLANT_ATTACK_INITIAL 0x45DEE2 birth exact=7/default=11; '
        'stale UUID misses; clear disables',
        flush=True,
    )


def plant_hooks(controller: Controller, board: GameBoard) -> None:
    """验证植物攻击间隔,生产初值/间隔和玉米投手黄油分支."""
    from rpze.structs.projectile import ProjectileType

    hooks = (
        RndHook.PLANT_ATTACK_INTERVAL,
        RndHook.PLANT_PRODUCTION_INITIAL,
        RndHook.PLANT_PRODUCTION_INTERVAL,
        RndHook.PLANT_KERNEL_BUTTER,
    )
    plants = []
    zombies = []

    def next_plant_uuid() -> ObjUuid:
        return ObjUuid(
            controller.get_obj_next_uuid_cnt(ObjType.PLANT),
            board.plant_list.next_index,
            ObjType.PLANT,
        )

    def cleanup_scene() -> None:
        for zombie in zombies:
            if not zombie.is_dead:
                zombie.die_no_loot()
        for plant in plants:
            if not plant.is_dead:
                plant.die()
        if plants or zombies:
            assert_izombie_brains(board)
            controller.skip_frames(1)
        plants.clear()
        zombies.clear()
        for projectile in list(board.projectile_list.alive_iterator):
            projectile.die()
        assert_izombie_brains(board)
        controller.skip_frames(1)
        for hook in hooks:
            controller.rnd_clear(hook)
        prepare_board(controller, board)

    def call_plant_update(plant, address: int) -> None:
        code = f"""
            push edi
            mov edi, {plant.base_ptr}
            call {address}
            pop edi
            ret
        """
        assert asm.run(code, controller)

    def configure(hook: RndHook, exact_uuid: ObjUuid, exact: int, default: int) -> None:
        controller.rnd_set_default(hook, default)
        controller.rnd_set(hook, exact_uuid, exact)

    try:
        # 攻击间隔在完整植物帧中先减到零,续值再经过 RND 后写回倒计时.
        cleanup_scene()
        exact_uuid = next_plant_uuid()
        configure(RndHook.PLANT_ATTACK_INTERVAL, exact_uuid, 11, 7)
        exact = board.new_plant(0, 0, PlantType.PEASHOOTER)
        assert exact.uuid == exact_uuid
        board.iz_setup_plant(exact)
        default = board.new_plant(1, 0, PlantType.PEASHOOTER)
        board.iz_setup_plant(default)
        zombies.extend((board.iz_place_zombie(0, 8, ZombieType.NORMAL),
                        board.iz_place_zombie(1, 8, ZombieType.NORMAL)))
        plants.extend((exact, default))
        exact.generate_cd = default.generate_cd = 1
        assert_izombie_brains(board)
        controller.skip_frames(1)
        assert exact.generate_cd == 139, exact.generate_cd
        assert default.generate_cd == 143, default.generate_cd
        cleanup_scene()

        # 生产初值只在出生例程内取一次,精确 UUID 和其他对象分别走不同结果.
        exact_uuid = next_plant_uuid()
        configure(RndHook.PLANT_PRODUCTION_INITIAL, exact_uuid, 17, 23)
        exact = board.new_plant(0, 0, PlantType.SUNFLOWER)
        default = board.new_plant(1, 0, PlantType.SUNFLOWER)
        plants.extend((exact, default))
        assert exact.uuid == exact_uuid
        assert exact.generate_cd == 317, exact.generate_cd
        assert default.generate_cd == 323, default.generate_cd
        assert exact.max_boot_delay == default.max_boot_delay == 2500
        cleanup_scene()

        # 生产间隔例程会排除 IZombie 模式;暂时切到已知的普通关卡模式,
        # 调用完整入口,再无条件恢复原模式.
        exact_uuid = next_plant_uuid()
        configure(RndHook.PLANT_PRODUCTION_INTERVAL, exact_uuid, 11, 7)
        exact = board.new_plant(0, 0, PlantType.SUNFLOWER)
        default = board.new_plant(1, 0, PlantType.SUNFLOWER)
        plants.extend((exact, default))
        assert exact.uuid == exact_uuid
        exact.generate_cd = default.generate_cd = 0
        old_mode = controller.read_i32(0x6A9EC0, 0x7F8)
        assert old_mode == 70, old_mode
        controller.write_i32(0, 0x6A9EC0, 0x7F8)
        try:
            call_plant_update(exact, 0x45F9A0)
            call_plant_update(default, 0x45F9A0)
        finally:
            controller.write_i32(old_mode, 0x6A9EC0, 0x7F8)
        assert exact.generate_cd == 2361, exact.generate_cd
        assert default.generate_cd == 2357, default.generate_cd
        cleanup_scene()

        # 玉米投手在真实攻击帧中创建子弹,精确对象出黄油,其他对象出玉米粒.
        exact_uuid = next_plant_uuid()
        configure(RndHook.PLANT_KERNEL_BUTTER, exact_uuid, 0, 1)
        exact = board.new_plant(0, 0, PlantType.KERNELPULT)
        default = board.new_plant(1, 0, PlantType.KERNELPULT)
        assert exact.uuid == exact_uuid
        board.iz_setup_plant(exact)
        board.iz_setup_plant(default)
        zombies.extend((board.iz_place_zombie(0, 8, ZombieType.NORMAL),
                        board.iz_place_zombie(1, 8, ZombieType.NORMAL)))
        plants.extend((exact, default))
        exact.generate_cd = default.generate_cd = 1
        observed = {}
        for _ in range(340):
            assert_izombie_brains(board)
            controller.skip_frames(1)
            for projectile in board.projectile_list.alive_iterator:
                if projectile.col in (0, 1) and projectile.col not in observed:
                    observed[projectile.col] = projectile.type_
            if len(observed) == 2:
                break
        assert observed == {0: ProjectileType.BUTTER, 1: ProjectileType.KERNEL}, observed
        cleanup_scene()
    finally:
        cleanup_scene()
        for hook in hooks:
            controller.rnd_clear(hook)
    print(
        "PASS plant hooks: ATTACK_INTERVAL exact=139/default=143; "
        "PRODUCTION_INITIAL exact=317/default=323; "
        "PRODUCTION_INTERVAL exact=2361/default=2357; "
        "KERNEL_BUTTER exact=butter/default=kernel",
        flush=True,
    )
def configuration(controller: Controller) -> None:
    """在暂停态原子验证配置,容量,覆盖顺序,隔离和参数校验."""
    c = controller
    a, b = RndHook.PLANT_ATTACK_INITIAL, RndHook.ZOMBIE_SPAWN_OTHER
    u = ObjUuid(1, 0, ObjType.PLANT)
    c.rnd_set(a, u, 0)
    assert c.rnd_enabled(a) and c.rnd_get(a, u) == 0
    c.rnd_set_default(a, 11)
    c.rnd_set_default(a, None)
    assert c.rnd_enabled(a) and c.rnd_get_default(a) is None
    assert c.rnd_remove(a, u) and not c.rnd_enabled(a)
    assert not c.rnd_remove(a, u)
    # 容量契约:精确填满表后,新键必须失败;已有键仍可读写和删除.
    entries = [
        (
            a if i % 2 else b,
            ObjUuid(i + 1, i % 1024,
                    ObjType.PLANT if i % 2 else ObjType.ZOMBIE),
            i,
        )
        for i in range(RND_EXACT_CAPACITY)
    ]
    for h, uuid, value in reversed(entries):
        c.rnd_set(h, uuid, value)
    c.rnd_set_default(a, 19)
    extra = ObjUuid(99999, 0, ObjType.PLANT)
    try:
        c.rnd_set(a, extra, 23)
    except ControllerError:
        pass
    else:
        raise AssertionError("full table accepted a new key")
    for h, uuid, value in entries:
        assert c.rnd_get(h, uuid) == value
    assert c.rnd_get_default(a) == 19 and c.rnd_enabled(a) and c.rnd_enabled(b)
    h, uuid, _ = entries[len(entries) // 2]
    c.rnd_set(h, uuid, 41)
    assert c.rnd_get(h, uuid) == 41
    for index in (0, len(entries) // 2, len(entries) - 1):
        h, uuid, _ = entries[index]
        assert c.rnd_remove(h, uuid)
        assert c.rnd_get(h, uuid) is None
    c.rnd_clear(a)
    assert not c.rnd_enabled(a) and c.rnd_enabled(b)
    for h, uuid, value in entries:
        if h == b and uuid != entries[0][1] and uuid != entries[len(entries) // 2][1]:
            assert c.rnd_get(h, uuid) == value
    c.rnd_set(a, extra, 7)
    c.rnd_clear()
    assert all(not c.rnd_enabled(h) for h in RndHook)
    f = RndHook.ZOMBIE_SPEED_NORMAL
    for value in (0.0, -0.0, 2.0 ** -149, 0.125):
        c.rnd_set_default(f, value)
        assert struct.pack("<f", c.rnd_get_default(f)) == struct.pack("<f", value)
    c.rnd_clear()
    failures = [(TypeError, lambda: c.rnd_set(a, u, 1.5)),
                (ValueError, lambda: c.rnd_set(a, ObjUuid(), 1)),
                (ValueError, lambda: c.rnd_set(a, ObjUuid(1, 1024, ObjType.PLANT), 1)),
                (ValueError, lambda: c.rnd_set(a, ObjUuid(1, 0, ObjType.ZOMBIE), 1)),
                (OverflowError, lambda: c.rnd_set(a, u, 2**31)),
                (OverflowError, lambda: c.rnd_set(a, u, -2**31-1)),
                (ValueError, lambda: c.rnd_set_default(f, math.nan)),
                (ValueError, lambda: c.rnd_set_default(f, math.inf)),
                (OverflowError, lambda: c.rnd_set_default(f, 1e100))]
    for error, operation in failures:
        try:
            operation()
        except error:
            pass
        else:
            raise AssertionError(f"expected {error.__name__}")
        assert all(not c.rnd_enabled(h) for h in RndHook)
    class StopsControl:
        def __index__(self):
            c.end()
            return 7
    try:
        c.rnd_set(a, u, StopsControl())
    except ControllerError:
        pass
    else:
        raise AssertionError("index protocol bypassed prepared check")
    finally:
        c.start()
    assert c.rnd_get(a, u) is None and not c.rnd_enabled(a)
    class IndexFailure(Exception):
        pass
    class BrokenIndex:
        def __index__(self):
            raise IndexFailure("index failure must propagate")
    try:
        c.rnd_set(a, u, BrokenIndex())
    except IndexFailure:
        pass
    else:
        raise AssertionError("index protocol exception was lost")
    print("PASS configuration: capacity/overwrite/order/isolation/validation/fp32 bits", flush=True)


def prepared_state(controller: Controller) -> None:
    """非 prepared 状态拒绝配置;恢复控制后原配置仍在."""
    c = controller
    h = RndHook.PLANT_ATTACK_INITIAL
    u = ObjUuid(1, 0, ObjType.PLANT)
    operations = (lambda: c.rnd_set(h, u, 1),
                  lambda: c.rnd_get(h, u),
                  lambda: c.rnd_remove(h, u),
                  lambda: c.rnd_set_default(h, 1),
                  lambda: c.rnd_get_default(h),
                  lambda: c.rnd_enabled(h),
                  lambda: c.rnd_clear(h), lambda: c.rnd_clear())
    def rejected() -> None:
        for operation in operations:
            try:
                operation()
            except ControllerError:
                pass
            else:
                raise AssertionError("unprepared operation accepted")
    c.rnd_set_default(h, 11)
    c.end()
    try:
        rejected()
    finally:
        c.start()
    assert c.rnd_get_default(h) == 11
    c.rnd_clear()
    print("PASS all API prepared gates; end/start preserves configuration", flush=True)


def control_modes(
    controller: Controller,
    board: GameBoard,
    normal: SyncMethod,
    jumping: SyncMethod,
) -> None:
    """在普通帧和跳帧同步模式下重复游戏对象出生契约."""
    controller.end()
    controller.sync_method = normal
    controller.jumping_sync_method = jumping
    controller.start()
    integer_birth(controller, board)
    assert_izombie_brains(board)
    assert controller.start_jump_frame()
    try:
        integer_birth(controller, board)
        float_birth(controller, board)
    finally:
        controller.end_jump_frame()
    print(f"PASS sync normal={normal} jumping={jumping}", flush=True)


def zombie_hooks(controller: Controller, board: GameBoard) -> None:
    """验证全部僵尸 RND 钩子的出生字段,默认值和真实引擎效果."""
    exact_int = 17
    default_int = 777
    zombies = []
    plants = []

    def next_uuid() -> ObjUuid:
        return ObjUuid(
            controller.get_obj_next_uuid_cnt(ObjType.ZOMBIE),
            board.zombie_list.next_index,
            ObjType.ZOMBIE,
        )

    def direct_zombie(expected_uuid: ObjUuid, row: int, zombie_type: ZombieType):
        """通过 Board::AddZombie 保留出生初始化,避免 IZombie 覆盖出生坐标."""
        assert expected_uuid == next_uuid()
        code = f"""
            push {row}
            push {int(zombie_type)}
            mov eax, {board.base_ptr}
            call {0x40ddc0}  // Board::AddZombie
            mov [{controller.result_address}], eax
            ret
        """
        assert asm.run(code, controller)
        zombie = board.zombie_list.find(expected_uuid)
        assert zombie is not None
        assert zombie.uuid == expected_uuid
        zombies.append(zombie)
        return zombie

    def call_engine(address: int, zombie) -> None:
        code = f"""
            mov eax, {zombie.base_ptr}
            call {address}
            ret
        """
        assert asm.run(code, controller)

    def float_bits(value: float) -> int:
        return struct.unpack("<I", struct.pack("<f", value))[0]

    def reset_scene() -> None:
        controller.rnd_clear()
        prepare_board(controller, board)

    def cleanup_scene() -> None:
        for zombie in zombies:
            if not zombie.is_dead:
                zombie.die_no_loot()
        for plant in plants:
            if not plant.is_dead:
                plant.die()
        if zombies or plants:
            controller.skip_frames(1)
        zombies.clear()
        plants.clear()
        controller.rnd_clear()
        prepare_board(controller, board)

    try:
        for hook, zombie_type, offset in (
            (RndHook.ZOMBIE_SPAWN_OTHER, ZombieType.NORMAL, 780),
            (RndHook.ZOMBIE_SPAWN_POLE, ZombieType.POLEVAULTER, 870),
            (RndHook.ZOMBIE_SPAWN_ZAMBONI, ZombieType.ZAMBONI, 800),
            (RndHook.ZOMBIE_SPAWN_CATAPULT, ZombieType.CATAPULT, 825),
            (RndHook.ZOMBIE_SPAWN_GARGANTUAR, ZombieType.GARGANTUAR, 845),
        ):
            reset_scene()
            controller.rnd_set_default(hook, default_int)
            exact_uuid = next_uuid()
            controller.rnd_set(hook, exact_uuid, exact_int)
            exact_zombie = direct_zombie(exact_uuid, 2, zombie_type)
            assert exact_zombie.x == offset + exact_int
            default_uuid = next_uuid()
            default_zombie = direct_zombie(default_uuid, 1, zombie_type)
            assert default_zombie.x == offset + default_int
            cleanup_scene()

        reset_scene()
        controller.rnd_set_default(RndHook.ZOMBIE_SPEED_JACK, 2.0)
        controller.rnd_set_default(RndHook.ZOMBIE_JACK_COUNTDOWN, default_int)
        controller.rnd_set_default(RndHook.ZOMBIE_JACK_EARLY_EXPLOSION, 1)
        exact_uuid = next_uuid()
        controller.rnd_set(RndHook.ZOMBIE_JACK_COUNTDOWN, exact_uuid, exact_int)
        exact_zombie = direct_zombie(exact_uuid, 2, ZombieType.JACK_IN_THE_BOX)
        assert exact_zombie.dx == 2.0
        assert controller.read_i32(exact_zombie.base_ptr + 0x68) == 466
        default_uuid = next_uuid()
        default_zombie = direct_zombie(default_uuid, 1, ZombieType.JACK_IN_THE_BOX)
        assert controller.read_i32(default_zombie.base_ptr + 0x68) == 1226
        cleanup_scene()

        reset_scene()
        controller.rnd_set_default(RndHook.ZOMBIE_SPEED_JACK, 2.0)
        controller.rnd_set_default(RndHook.ZOMBIE_JACK_COUNTDOWN, exact_int)
        controller.rnd_set_default(RndHook.ZOMBIE_JACK_EARLY_EXPLOSION, 1)
        exact_uuid = next_uuid()
        controller.rnd_set(RndHook.ZOMBIE_JACK_EARLY_EXPLOSION, exact_uuid, 0)
        exact_zombie = direct_zombie(exact_uuid, 2, ZombieType.JACK_IN_THE_BOX)
        assert exact_zombie.dx == 2.0
        assert controller.read_i32(exact_zombie.base_ptr + 0x68) == 154
        default_uuid = next_uuid()
        default_zombie = direct_zombie(default_uuid, 1, ZombieType.JACK_IN_THE_BOX)
        assert controller.read_i32(default_zombie.base_ptr + 0x68) == 466
        cleanup_scene()

        reset_scene()
        controller.rnd_set_default(RndHook.ZOMBIE_BUNGEE_HEIGHT, default_int)
        exact_uuid = next_uuid()
        controller.rnd_set(RndHook.ZOMBIE_BUNGEE_HEIGHT, exact_uuid, exact_int)
        exact_zombie = direct_zombie(exact_uuid, 2, ZombieType.BUNGEE)
        assert controller.read_u32(exact_zombie.base_ptr + 0x84) == float_bits(3017.0)
        default_uuid = next_uuid()
        default_zombie = direct_zombie(default_uuid, 1, ZombieType.BUNGEE)
        assert controller.read_u32(default_zombie.base_ptr + 0x84) == float_bits(3777.0)
        cleanup_scene()

        for hook, zombie_type, exact_phase, default_phase in (
            (RndHook.ZOMBIE_DANCER_SLIDE, ZombieType.DANCER, 317, 1077),
            (RndHook.ZOMBIE_YETI_ESCAPE, ZombieType.YETI, 1517, 2277),
            (RndHook.ZOMBIE_POGO_INITIAL, ZombieType.POGO, 18, 778),
        ):
            reset_scene()
            controller.rnd_set_default(hook, default_int)
            exact_uuid = next_uuid()
            controller.rnd_set(hook, exact_uuid, exact_int)
            exact_zombie = direct_zombie(exact_uuid, 2, zombie_type)
            assert controller.read_i32(exact_zombie.base_ptr + 0x68) == exact_phase
            default_uuid = next_uuid()
            default_zombie = direct_zombie(default_uuid, 1, zombie_type)
            assert controller.read_i32(default_zombie.base_ptr + 0x68) == default_phase
            cleanup_scene()

        reset_scene()
        controller.rnd_set_default(RndHook.ZOMBIE_SPEED_NORMAL, 1.0)
        controller.rnd_set_default(RndHook.ZOMBIE_JALAPENO_COUNTDOWN, default_int)
        exact_uuid = next_uuid()
        controller.rnd_set(RndHook.ZOMBIE_SPEED_NORMAL, exact_uuid, 1.0)
        controller.rnd_set(RndHook.ZOMBIE_JALAPENO_COUNTDOWN, exact_uuid, exact_int)
        exact_zombie = direct_zombie(exact_uuid, 2, ZombieType.JALAPENO_HEAD)
        assert exact_zombie.dx == 1.0
        assert controller.read_i32(exact_zombie.base_ptr + 0x68) == 584
        default_uuid = next_uuid()
        default_zombie = direct_zombie(default_uuid, 1, ZombieType.JALAPENO_HEAD)
        assert controller.read_i32(default_zombie.base_ptr + 0x68) == 2104
        cleanup_scene()

        reset_scene()
        controller.rnd_set_default(RndHook.ZOMBIE_GARLIC_DIRECTION, 1)
        controller.rnd_set_default(RndHook.ZOMBIE_SPEED_NORMAL, 2.0)
        controller.rnd_set_default(RndHook.ZOMBIE_SPAWN_OTHER, 0)
        garlic = board.new_plant(2, 8, PlantType.GARLIC)
        assert garlic is not None
        plants.append(garlic)
        exact_uuid = next_uuid()
        controller.rnd_set(RndHook.ZOMBIE_GARLIC_DIRECTION, exact_uuid, 0)
        controller.rnd_set(RndHook.ZOMBIE_SPAWN_OTHER, exact_uuid, 0)
        exact_zombie = direct_zombie(exact_uuid, 2, ZombieType.NORMAL)
        controller.skip_frames(300)
        assert exact_zombie.row == 3
        exact_zombie.die_no_loot()
        controller.skip_frames(1)
        zombies.remove(exact_zombie)
        default_uuid = next_uuid()
        default_zombie = direct_zombie(default_uuid, 2, ZombieType.NORMAL)
        controller.skip_frames(300)
        assert default_zombie.row == 1
        cleanup_scene()

        reset_scene()
        controller.rnd_set_default(RndHook.ZOMBIE_FREEZE_FIRST, default_int)
        exact_uuid = next_uuid()
        controller.rnd_set(RndHook.ZOMBIE_FREEZE_FIRST, exact_uuid, exact_int)
        exact_zombie = direct_zombie(exact_uuid, 2, ZombieType.NORMAL)
        call_engine(0x5323c0, exact_zombie)
        assert exact_zombie.freeze_cd == 417
        assert exact_zombie.slow_cd == 2000
        default_uuid = next_uuid()
        default_zombie = direct_zombie(default_uuid, 1, ZombieType.NORMAL)
        call_engine(0x5323c0, default_zombie)
        assert default_zombie.freeze_cd == 1177
        cleanup_scene()

        reset_scene()
        controller.rnd_set_default(RndHook.ZOMBIE_FREEZE_FIRST, exact_int)
        controller.rnd_set_default(RndHook.ZOMBIE_FREEZE_REPEAT, default_int)
        exact_uuid = next_uuid()
        controller.rnd_set(RndHook.ZOMBIE_FREEZE_FIRST, exact_uuid, exact_int)
        controller.rnd_set(RndHook.ZOMBIE_FREEZE_REPEAT, exact_uuid, 23)
        exact_zombie = direct_zombie(exact_uuid, 2, ZombieType.NORMAL)
        call_engine(0x5323c0, exact_zombie)
        assert exact_zombie.freeze_cd == 417
        call_engine(0x5323c0, exact_zombie)
        assert exact_zombie.freeze_cd == 323
        default_uuid = next_uuid()
        default_zombie = direct_zombie(default_uuid, 1, ZombieType.NORMAL)
        call_engine(0x5323c0, default_zombie)
        assert default_zombie.freeze_cd == 417
        call_engine(0x5323c0, default_zombie)
        assert default_zombie.freeze_cd == 1077
        cleanup_scene()

        for hook, zombie_type in (
            (RndHook.ZOMBIE_SPEED_JACK, ZombieType.JACK_IN_THE_BOX),
            (RndHook.ZOMBIE_SPEED_LADDER, ZombieType.LADDER),
            (RndHook.ZOMBIE_SPEED_DOLPHIN, ZombieType.DOLPHIN_RIDER),
            (RndHook.ZOMBIE_SPEED_NORMAL, ZombieType.NORMAL),
        ):
            reset_scene()
            controller.rnd_set_default(hook, 0.25)
            exact_uuid = next_uuid()
            controller.rnd_set(hook, exact_uuid, 0.125)
            exact_zombie = direct_zombie(exact_uuid, 2, zombie_type)
            assert controller.read_u32(exact_zombie.base_ptr + 0x34) == 0x3e000000
            default_uuid = next_uuid()
            default_zombie = direct_zombie(default_uuid, 1, zombie_type)
            assert controller.read_u32(default_zombie.base_ptr + 0x34) == 0x3e800000
            cleanup_scene()
    finally:
        cleanup_scene()

    print(
        "PASS all 19 zombie RND hooks; births used Board::AddZombie, garlic used real frames, freeze used direct engine call",
        flush=True,
    )


def float_birth(controller: Controller, board: GameBoard) -> None:
    """验证浮点 RND 的出生即时位模式,并在完整帧后验证死亡回收."""
    h = RndHook.ZOMBIE_SPEED_NORMAL
    uuid = ObjUuid(
        controller.get_obj_next_uuid_cnt(ObjType.ZOMBIE),
        board.zombie_list.next_index,
        ObjType.ZOMBIE,
    )
    controller.rnd_set_default(h, 0.25)
    controller.rnd_set(h, uuid, 0.125)
    zombie = board.iz_place_zombie(0, 8, ZombieType.NORMAL)

    # 出生字段必须在跳帧前即时读取,之后的帧只负责让引擎完成清理.
    assert zombie.uuid == uuid
    assert controller.read_u32(zombie.base_ptr + 0x34) == 0x3e000000
    assert_izombie_brains(board)
    controller.skip_frames(1)

    other = board.iz_place_zombie(1, 8, ZombieType.NORMAL)
    other_uuid = other.uuid
    assert controller.read_u32(other.base_ptr + 0x34) == 0x3e800000
    assert_izombie_brains(board)
    controller.skip_frames(1)

    zombie.die_no_loot()
    assert_izombie_brains(board)
    controller.skip_frames(1)
    assert controller.get_obj_base_ptr(uuid) == 0
    assert board.find(uuid) is None

    other.die_no_loot()
    assert_izombie_brains(board)
    controller.skip_frames(1)
    assert controller.get_obj_base_ptr(other_uuid) == 0
    assert board.find(other_uuid) is None

    controller.rnd_clear(h)
    print(
        "PASS ZOMBIE_SPEED_NORMAL 0x524B97 birth exact=0.125/default=0.25 "
        "stored bits",
        flush=True,
    )


def board_lifecycle_regression(controller: Controller, board: GameBoard) -> GameBoard:
    """Keep a newborn object's UUID/RND live across deferred Board disposal."""
    hook = RndHook.PLANT_ATTACK_INITIAL
    old_board_ptr = board.base_ptr
    old_uuid = ObjUuid(
        controller.get_obj_next_uuid_cnt(ObjType.PLANT),
        board.plant_list.next_index,
        ObjType.PLANT,
    )
    controller.rnd_set_default(hook, 137)
    controller.rnd_set(hook, old_uuid, -271)
    old_plant = board.new_plant(0, 0, PlantType.PEASHOOTER)
    assert old_plant.uuid == old_uuid
    assert old_plant.generate_cd == -271
    assert_izombie_brains(board)

    # This is only the released game's real PreNewGame lifecycle trigger; it
    # is not ProcessDeleteQueue/Effect cleanup and never writes m_board.
    code = """
        push esi
        mov esi, [0x6A9EC0]
        push 0
        push 70
        call 0x44F560
        pop esi
        ret
    """
    assert asm.run(code, controller)
    new_board_ptr = controller.read_u32(0x6A9EC0, 0x768)
    assert new_board_ptr != 0 and new_board_ptr != old_board_ptr

    # Do not consume get_p_board() and then let get_board() retain the old
    # wrapper.  Evict only this PID's cache entry, then obtain a fresh wrapper.
    cache = game_board_module.__dict__["__game_board_cache"]
    assert cache.pop(controller.pid, None) is board
    new_board = get_board(controller)
    assert new_board is not board and new_board.base_ptr == new_board_ptr
    assert controller.get_obj_base_ptr(old_uuid) == 0
    assert all(not controller.rnd_enabled(h) for h in RndHook)

    # Build the five-brain fixture without advancing a frame: the next frame
    # must be the one that disposes the old Board and exercises identity guards.
    for objects in (
        new_board.plant_list,
        new_board.zombie_list,
        new_board.projectile_list,
        new_board.griditem_list,
    ):
        objects.free_all()
    for row in IZOMBIE_BRAIN_ROWS:
        brain = new_board.new_iz_brain(row)
        assert brain.row == row and brain.brain_hp > 0 and not brain.is_dead
    assert_izombie_brains(new_board)

    new_uuid = ObjUuid(
        controller.get_obj_next_uuid_cnt(ObjType.PLANT),
        new_board.plant_list.next_index,
        ObjType.PLANT,
    )
    controller.rnd_set_default(hook, 137)
    controller.rnd_set(hook, new_uuid, -271)
    new_plant = new_board.new_plant(0, 0, PlantType.PEASHOOTER)
    assert new_plant.uuid == new_uuid
    assert new_plant.generate_cd == -271
    new_plant_ptr = new_plant.base_ptr
    assert controller.get_obj_base_ptr(new_uuid) == new_plant_ptr
    assert controller.rnd_get_default(hook) == 137
    assert controller.rnd_get(hook, new_uuid) == -271

    controller.skip_frames(1)
    assert controller.get_obj_base_ptr(old_uuid) == 0
    assert controller.get_obj_base_ptr(new_uuid) == new_plant_ptr
    assert controller.rnd_get_default(hook) == 137
    assert controller.rnd_get(hook, new_uuid) == -271
    print(
        "PASS Board replacement deferred dispose: newborn UUID/pointer and exact/default RND survive",
        flush=True,
    )

    new_plant.die()
    assert_izombie_brains(new_board)
    controller.skip_frames(1)
    assert controller.get_obj_base_ptr(new_uuid) == 0
    assert new_board.find(new_uuid) is None
    controller.rnd_clear(hook)
    return new_board
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auto-enter", action="store_true")
    parser.add_argument("--normal", choices=("SPIN", "MUTEX"), default="MUTEX")
    parser.add_argument("--jumping", choices=("SPIN", "MUTEX"), default="SPIN")
    args = parser.parse_args()
    print("Destructive RND smoke: clearing the IZombie scene.", flush=True)
    with InjectedGame() as game:
        controller = game.controller
        try:
            if args.auto_enter:
                from rpze.iztest.operations import enter_ize
                board = enter_ize(controller)
                controller.start()
            else:
                controller.end()
                input('进入 IZombie 后按 Enter: ')
                controller.start()
                board = get_board(controller)
            assert all(not controller.rnd_enabled(hook) for hook in RndHook)
            prepare_board(controller, board)
            configuration(controller)
            integer_birth(controller, board)
            float_birth(controller, board)
            plant_hooks(controller, board)
            zombie_hooks(controller, board)
            prepared_state(controller)
            control_modes(controller, board, SyncMethod[args.normal], SyncMethod[args.jumping])
            board = board_lifecycle_regression(controller, board)
        finally:
            if controller.global_connected():
                controller.start()
                controller.rnd_clear()


if __name__ == '__main__':
    main()

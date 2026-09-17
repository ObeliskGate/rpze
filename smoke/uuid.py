"""Destructive integration smoke test for the UUID object metadata hooks.

Set RP_GAME_PATH as usual, then run::

    python smoke/uuid.py

The script asks for exactly three operator transitions: enter any I,Zombie
level, leave to the main menu, and re-enter a new I,Zombie Board.  It clears
paused UUID-test arrays and restores all five IZombie brains before frames, so
empty rows are not required.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from rpze.basic import asm
from rpze.basic.inject import InjectedGame
from rpze.rp_extend import (
    OBJ_TYPE_INFO,
    OBJ_UUID_SLOT_COUNT,
    Controller,
    ObjType,
    ObjUuid,
)
from rpze.structs.game_board import GameBoard, get_board
from rpze.structs.griditem import Griditem, GriditemType
from rpze.structs.plant import Plant, PlantType
from rpze.structs.projectile import Projectile
from rpze.structs.zombie import Zombie, ZombieType


# py::enum_ is not iterable.  Keep this derived from the exported table rather
# than duplicating the type set, so adding a real type needs one table entry.
OBJ_TYPES = tuple(ObjType(i) for i in range(len(OBJ_TYPE_INFO)))
IZOMBIE_BRAIN_ROWS = tuple(range(5))

# Verify the Python-facing table immediately after constructing OBJ_TYPES.
assert isinstance(OBJ_TYPE_INFO, tuple)
assert not hasattr(ObjType, "Count") and not hasattr(ObjType, "COUNT")
assert callable(getattr(Controller, "get_obj_next_uuid_cnt", None))
for index, info in enumerate(OBJ_TYPE_INFO):
    type_ = ObjType(index)
    assert type_.ITEM_SIZE == info.ITEM_SIZE
    assert type_.BOARD_ARRAY_OFFSET == info.BOARD_ARRAY_OFFSET


Factory = Callable[[], Any]
Killer = Callable[[Any], None]


def next_counts(controller: Controller) -> dict[ObjType, int]:
    return {
        type_: controller.get_obj_next_uuid_cnt(type_)
        for type_ in OBJ_TYPES
    }


def assert_next_step(
    before: dict[ObjType, int],
    after: dict[ObjType, int],
    changed: ObjType,
    steps: int = 1,
) -> None:
    for type_ in OBJ_TYPES:
        if type_ == changed:
            assert after[type_] == before[type_] + steps, (
                type_, before[type_], after[type_], steps
            )
        else:
            assert after[type_] == before[type_], (
                type_, before[type_], after[type_]
            )


def assert_getters_stable(controller: Controller) -> dict[ObjType, int]:
    before = next_counts(controller)
    again = next_counts(controller)
    assert again == before
    return before


def live_uuids(controller: Controller, type_: ObjType) -> list[ObjUuid]:
    """Return UUIDs for all slots whose PvZ mID says they are live.

    The mID check is deliberately independent of the UUID metadata: a live mID
    without a UUID (or a UUID left on a dead slot) is a failed hook/cleanup.
    """
    array = controller.get_obj_array_ptr(type_)
    max_size = min(controller.get_obj_max_size(type_), OBJ_UUID_SLOT_COUNT)
    if not array or not max_size:
        return []

    max_used = controller.read_u32(array + 4) or 0
    count = min(max_used, max_size)
    if not count:
        return []

    block = controller.get_obj_block_ptr(type_)
    assert block, (type_, array, max_used, max_size)
    stride = type_.ITEM_SIZE + 4
    result: list[ObjUuid] = []
    for index in range(count):
        m_id = controller.read_u32(block + stride * index + type_.ITEM_SIZE) or 0
        uuid = controller.get_obj_uuid(type_, index)
        assert bool(uuid) == bool(m_id >> 16), (type_, index, m_id, uuid)
        if uuid:
            ptr = block + stride * index
            assert controller.get_obj_base_ptr(uuid) == ptr
            assert controller.get_obj_uuid_by_ptr(type_, ptr) == uuid
            assert_python_lookup(get_board(controller), type_, uuid, ptr)
            result.append(uuid)
    return result


def all_live_uuids(controller: Controller) -> dict[ObjType, list[ObjUuid]]:
    return {type_: live_uuids(controller, type_) for type_ in OBJ_TYPES}


def check_public_api(controller: Controller) -> None:
    invalid = ObjUuid()
    for type_ in OBJ_TYPES:
        max_size = min(controller.get_obj_max_size(type_), OBJ_UUID_SLOT_COUNT)
        block = controller.get_obj_block_ptr(type_)
        assert not controller.get_obj_uuid(type_, -1)
        assert not controller.get_obj_uuid(type_, max_size)
        assert not controller.get_obj_uuid_by_ptr(type_, block + 1 if block else 1)
        assert controller.get_obj_base_ptr(type_, -1) == 0
        assert controller.get_obj_base_ptr(type_, max_size) == 0
    assert controller.get_obj_base_ptr(invalid) == 0
    assert_getters_stable(controller)




def object_list(board: GameBoard, type_: ObjType) -> Any:
    if type_ == ObjType.PLANT:
        return board.plant_list
    if type_ == ObjType.ZOMBIE:
        return board.zombie_list
    if type_ == ObjType.PROJECTILE:
        return board.projectile_list
    if type_ == ObjType.GRID_ITEM:
        return board.griditem_list
    raise AssertionError(f"no smoke list for object type {type_!r}")


def assert_python_lookup(board: GameBoard, type_: ObjType, uuid: ObjUuid, ptr: int) -> None:
    """Check Python lookup without replacing the independent native mID oracle."""
    obj = board.find(uuid)
    assert obj is not None and obj.base_ptr == ptr
    assert obj.uuid == uuid and obj.OBJ_TYPE == type_
    objects = object_list(board, type_)
    found = objects.find(uuid)
    assert found is not None and found.base_ptr == ptr
    assert objects.find(ObjUuid()) is None
    assert board.find(ObjUuid()) is None
    for other_type in OBJ_TYPES:
        if other_type != type_:
            assert object_list(board, other_type).find(uuid) is None


def factory_for(board: GameBoard, type_: ObjType) -> Factory:
    if type_ == ObjType.PLANT:
        def create_plant() -> Plant:
            plant = board.new_plant(0, 0, PlantType.PEASHOOTER)
            board.iz_setup_plant(plant)
            return plant
        return create_plant
    if type_ == ObjType.ZOMBIE:
        return lambda: board.iz_place_zombie(0, 8, ZombieType.NORMAL)
    if type_ == ObjType.GRID_ITEM:
        return lambda: board.add_ladder(0, 1)
    raise AssertionError(f"the projectile factory is intentionally natural-only: {type_!r}")


def exact_allocation(
    controller: Controller,
    type_: ObjType,
    factory: Factory,
) -> tuple[Any, ObjUuid]:
    before = next_counts(controller)
    obj = factory()
    ptr = getattr(obj, "base_ptr", 0)
    assert ptr, (type_, obj)
    after = next_counts(controller)
    assert_next_step(before, after, type_)

    uuid = controller.get_obj_uuid_by_ptr(type_, ptr)
    assert uuid and uuid.uuid_cnt == before[type_]
    assert controller.get_obj_base_ptr(uuid) == ptr
    assert controller.get_obj_uuid_by_ptr(type_, ptr) == uuid
    assert obj.uuid == uuid
    assert_python_lookup(get_board(controller), type_, uuid, ptr)
    return obj, uuid


def physical_single_free_realloc(
    controller: Controller,
    board: GameBoard,
    type_: ObjType,
    obj: Any,
    old_uuid: ObjUuid,
    killer: Killer,
    factory: Factory,
) -> tuple[Any, ObjUuid]:
    before_free = next_counts(controller)
    # die()/die_no_loot() only marks an object for deletion.  Do not inspect
    # UUID invalidation until ProcessDeleteQueue has physically reclaimed it.
    killer(obj)
    assert board.find(old_uuid) is not None
    assert object_list(board, type_).find(old_uuid) is not None
    board.process_delete_queue()
    assert controller.get_obj_base_ptr(old_uuid) == 0
    assert board.find(old_uuid) is None
    assert object_list(board, type_).find(old_uuid) is None
    after_free = next_counts(controller)
    for current_type in OBJ_TYPES:
        assert after_free[current_type] == before_free[current_type], (
            current_type, before_free[current_type], after_free[current_type]
        )

    replacement, new_uuid = exact_allocation(controller, type_, factory)
    assert controller.get_obj_base_ptr(old_uuid) == 0
    assert board.find(old_uuid) is None
    assert object_list(board, type_).find(old_uuid) is None
    assert new_uuid.uuid_cnt != old_uuid.uuid_cnt
    return replacement, new_uuid


def check_plant_path(controller: Controller, board: GameBoard) -> None:
    prepare_empty_board(controller, board)
    obj, uuid = exact_allocation(controller, ObjType.PLANT, factory_for(board, ObjType.PLANT))
    physical_single_free_realloc(
        controller,
        board,
        ObjType.PLANT,
        obj,
        uuid,
        lambda plant: plant.die(),
        factory_for(board, ObjType.PLANT),
    )


def check_zombie_path(controller: Controller, board: GameBoard) -> None:
    prepare_empty_board(controller, board)
    obj, uuid = exact_allocation(controller, ObjType.ZOMBIE, factory_for(board, ObjType.ZOMBIE))
    physical_single_free_realloc(
        controller,
        board,
        ObjType.ZOMBIE,
        obj,
        uuid,
        lambda zombie: zombie.die_no_loot(),
        factory_for(board, ObjType.ZOMBIE),
    )


def check_paused_consecutive_allocations(
    controller: Controller, board: GameBoard
) -> None:
    """Create two GridItems back-to-back without a frame or helper refresh."""
    prepare_empty_board(controller, board)
    type_ = ObjType.GRID_ITEM
    factory = factory_for(board, type_)

    before = next_counts(controller)
    first = factory()
    after_first = next_counts(controller)
    assert_next_step(before, after_first, type_)
    first_uuid = controller.get_obj_uuid_by_ptr(type_, first.base_ptr)
    assert first_uuid and first_uuid.uuid_cnt == before[type_]
    assert controller.get_obj_base_ptr(first_uuid) == first.base_ptr

    second_before = after_first
    second = factory()
    after_second = next_counts(controller)
    assert_next_step(second_before, after_second, type_)
    second_uuid = controller.get_obj_uuid_by_ptr(type_, second.base_ptr)
    assert second_uuid and second_uuid.uuid_cnt == second_before[type_]
    assert second_uuid.uuid_cnt != first_uuid.uuid_cnt
    assert controller.get_obj_base_ptr(first_uuid) == first.base_ptr
    assert controller.get_obj_base_ptr(second_uuid) == second.base_ptr

    # A getter is read-only even while the game is held in the same pause.
    assert_getters_stable(controller)

    first.die()
    second.die()
    board.process_delete_queue()
    assert controller.get_obj_base_ptr(first_uuid) == 0
    assert controller.get_obj_base_ptr(second_uuid) == 0


def check_same_asm_double_creation(
    controller: Controller, board: GameBoard
) -> tuple[Griditem, ObjUuid, Griditem, ObjUuid]:
    """Issue two verified AddALadder allocations in one run_code callback."""
    prepare_empty_board(controller, board)
    type_ = ObjType.GRID_ITEM
    before = next_counts(controller)
    result = controller.result_address
    code = f"""
        push edi
        xor edi, edi
        mov eax, {board.base_ptr}
        push 1
        call {0x408F40}  // Board::AddALadder
        mov [{result}], eax
        xor edi, edi
        mov eax, {board.base_ptr}
        push 2
        call {0x408F40}  // Board::AddALadder
        mov [{result + 4}], eax
        pop edi
        ret
    """
    assert asm.run(code, controller)
    pointers = tuple(controller.result_mem[:8].cast("I"))
    first_ptr, second_ptr = pointers
    assert first_ptr and second_ptr and first_ptr != second_ptr, pointers

    after = next_counts(controller)
    assert_next_step(before, after, type_, steps=2)
    first_uuid = controller.get_obj_uuid_by_ptr(type_, first_ptr)
    second_uuid = controller.get_obj_uuid_by_ptr(type_, second_ptr)
    assert first_uuid and first_uuid.uuid_cnt == before[type_]
    assert second_uuid and second_uuid.uuid_cnt == before[type_] + 1
    assert controller.get_obj_base_ptr(first_uuid) == first_ptr
    assert controller.get_obj_base_ptr(second_uuid) == second_ptr
    assert_getters_stable(controller)
    return (
        Griditem(first_ptr, controller),
        first_uuid,
        Griditem(second_ptr, controller),
        second_uuid,
    )


def check_same_asm_free_realloc(
    controller: Controller, board: GameBoard, current: Griditem, current_uuid: ObjUuid
) -> tuple[Griditem, ObjUuid]:
    """Free one fixture physically, then allocate its replacement in one asm run."""
    ptr = controller.get_obj_base_ptr(current_uuid)
    assert ptr == current.base_ptr
    before = next_counts(controller)
    result = controller.result_address
    code = f"""
        push esi
        push edi
        mov esi, {ptr}
        call {0x44D000}  // Griditem::Die: mark for deletion
        mov esi, {board.base_ptr}
        call {0x41BAD0}  // Board::ProcessDeleteQueue: physical free
        xor edi, edi
        mov eax, {board.base_ptr}
        push 1
        call {0x408F40}  // Board::AddALadder: replacement allocation
        mov [{result}], eax
        pop edi
        pop esi
        ret
    """
    assert asm.run(code, controller)

    # The process-delete call is in this same callback, so this is the first
    # point at which the old UUID may be required to be invalid.
    assert controller.get_obj_base_ptr(current_uuid) == 0
    replacement_ptr = controller.result_u32
    assert replacement_ptr
    replacement_uuid = controller.get_obj_uuid_by_ptr(ObjType.GRID_ITEM, replacement_ptr)
    assert replacement_uuid
    after = next_counts(controller)
    assert_next_step(before, after, ObjType.GRID_ITEM)
    assert replacement_uuid.uuid_cnt == before[ObjType.GRID_ITEM]
    assert replacement_uuid.uuid_cnt != current_uuid.uuid_cnt
    assert controller.get_obj_base_ptr(replacement_uuid) == replacement_ptr
    assert_getters_stable(controller)
    return Griditem(replacement_ptr, controller), replacement_uuid


def check_griditem_reset_stack(controller: Controller, board: GameBoard) -> None:
    """Reset a genuinely empty valid array without touching UUID state."""
    prepare_empty_board(controller, board)
    type_ = ObjType.GRID_ITEM
    grid_list = board.griditem_list
    block = controller.get_obj_block_ptr(type_)
    assert block
    assert grid_list.obj_num == 0
    max_size = min(controller.get_obj_max_size(type_), OBJ_UUID_SLOT_COUNT)
    before_slots = [controller.get_obj_uuid(type_, i) for i in range(max_size)]
    before_next = next_counts(controller)

    grid_list.reset_stack()

    after_next = next_counts(controller)
    after_slots = [controller.get_obj_uuid(type_, i) for i in range(max_size)]
    assert after_next == before_next
    assert after_slots == before_slots
    assert not live_uuids(controller, type_)
    assert controller.get_obj_block_ptr(type_) == block

    # The reset is not an allocation.  The next real creation must use the
    # unchanged manager counter immediately, still without a frame.
    obj, uuid = exact_allocation(controller, type_, factory_for(board, type_))
    assert uuid.uuid_cnt == before_next[type_]
    obj.die()
    board.process_delete_queue()
    assert controller.get_obj_base_ptr(uuid) == 0


def wait_for_projectile(
    controller: Controller,
    board: GameBoard,
    shooter: Plant,
    baseline: set[ObjUuid],
) -> tuple[Projectile, ObjUuid]:
    type_ = ObjType.PROJECTILE
    ensure_izombie_brains(controller, board)
    before = next_counts(controller)
    shooter.generate_cd = 1
    observed: ObjUuid | None = None
    for _ in range(300):
        controller.skip_frames(1)
        candidates = [
            uuid
            for uuid in live_uuids(controller, type_)
            if uuid not in baseline
        ]
        if candidates:
            observed = candidates[0]
            break
    if observed is None:
        raise AssertionError("自然发射前提未满足")

    after = next_counts(controller)
    assert after[type_] > before[type_]
    assert before[type_] <= observed.uuid_cnt < after[type_]
    for other in OBJ_TYPES:
        if other != type_:
            assert after[other] == before[other], (
                other, before[other], after[other]
            )
    assert_getters_stable(controller)
    ptr = controller.get_obj_base_ptr(observed)
    assert ptr
    assert controller.get_obj_uuid_by_ptr(type_, ptr) == observed
    return Projectile(ptr, controller), observed


def check_projectile_path(controller: Controller, board: GameBoard) -> None:
    prepare_runnable_board(controller, board)
    baseline = set(live_uuids(controller, ObjType.PROJECTILE))
    plant, plant_uuid = exact_allocation(
        controller, ObjType.PLANT, factory_for(board, ObjType.PLANT)
    )
    zombie, zombie_uuid = exact_allocation(
        controller, ObjType.ZOMBIE, factory_for(board, ObjType.ZOMBIE)
    )
    before_projectile = next_counts(controller)
    projectile, projectile_uuid = wait_for_projectile(
        controller, board, plant, baseline
    )

    before_free = next_counts(controller)
    projectile.die()
    board.process_delete_queue()
    assert controller.get_obj_base_ptr(projectile_uuid) == 0
    after_free = next_counts(controller)
    assert after_free == before_free

    baseline = set(live_uuids(controller, ObjType.PROJECTILE))
    replacement, replacement_uuid = wait_for_projectile(
        controller, board, plant, baseline
    )
    assert replacement_uuid.uuid_cnt != projectile_uuid.uuid_cnt
    assert controller.get_obj_base_ptr(projectile_uuid) == 0

    # Keep the natural-fire path's own other-type invariant explicit.
    assert before_projectile[ObjType.PLANT] == next_counts(controller)[ObjType.PLANT]
    assert before_projectile[ObjType.ZOMBIE] == next_counts(controller)[ObjType.ZOMBIE]

    replacement.die()
    plant.die()
    zombie.die_no_loot()
    board.process_delete_queue()
    assert controller.get_obj_base_ptr(replacement_uuid) == 0
    assert controller.get_obj_base_ptr(plant_uuid) == 0
    assert controller.get_obj_base_ptr(zombie_uuid) == 0


def prepare_empty_board(controller: Controller, board: GameBoard) -> None:
    """Clear every object list for paused UUID checks that run no frames."""
    for list_ in (
        board.plant_list,
        board.zombie_list,
        board.projectile_list,
        board.griditem_list,
    ):
        list_.free_all()
    board.process_delete_queue()
    for type_ in OBJ_TYPES:
        assert not live_uuids(controller, type_)


def ensure_izombie_brains(controller: Controller, board: GameBoard) -> None:
    """Keep one live brain in each IZombie row before a frame can run."""
    type_ = ObjType.GRID_ITEM
    assert controller.get_obj_array_ptr(type_)
    assert controller.get_obj_block_ptr(type_)

    brain_rows: set[int] = set()
    for uuid in live_uuids(controller, type_):
        ptr = controller.get_obj_base_ptr(uuid)
        assert ptr
        brain = Griditem(ptr, controller)
        if brain.type_ != GriditemType.IZOMBIE_BRAIN:
            continue
        assert brain.row in IZOMBIE_BRAIN_ROWS, (brain.row, uuid)
        assert brain.row not in brain_rows, (brain.row, uuid)
        assert not brain.is_dead, (brain.row, uuid)
        assert brain.brain_hp > 0, (brain.row, uuid)
        assert brain.col == 0, (brain.row, brain.col, uuid)
        brain_rows.add(brain.row)

    for row in IZOMBIE_BRAIN_ROWS:
        if row in brain_rows:
            continue
        brain = board.new_iz_brain(row)
        assert brain.type_ == GriditemType.IZOMBIE_BRAIN
        assert brain.row == row
        assert brain.col == 0
        assert brain.brain_hp > 0
        assert not brain.is_dead
        brain_rows.add(row)

    assert brain_rows == set(IZOMBIE_BRAIN_ROWS), brain_rows


def prepare_runnable_board(controller: Controller, board: GameBoard) -> None:
    """Clear fixtures, then restore all five brains before running frames."""
    prepare_empty_board(controller, board)
    ensure_izombie_brains(controller, board)


def check_griditem_scenarios(controller: Controller, board: GameBoard) -> None:
    check_paused_consecutive_allocations(controller, board)

    first, first_uuid, second, second_uuid = check_same_asm_double_creation(
        controller, board
    )
    replacement, replacement_uuid = check_same_asm_free_realloc(
        controller, board, first, first_uuid
    )
    assert controller.get_obj_base_ptr(second_uuid) == second.base_ptr
    replacement.die()
    second.die()
    board.process_delete_queue()
    assert controller.get_obj_base_ptr(replacement_uuid) == 0
    assert controller.get_obj_base_ptr(second_uuid) == 0

    check_griditem_reset_stack(controller, board)


def check_jump_controlled_allocations(
    controller: Controller, board: GameBoard
) -> None:
    prepare_runnable_board(controller, board)
    type_ = ObjType.GRID_ITEM
    factory = factory_for(board, type_)
    assert not controller.is_jumping_frame()
    ensure_izombie_brains(controller, board)
    assert controller.start_jump_frame()
    try:
        # start_jump_frame can itself cross a game boundary; take every
        # comparison snapshot only after the mode switch has completed.
        before = next_counts(controller)
        first, first_uuid = exact_allocation(controller, type_, factory)
        after_first = next_counts(controller)
        assert after_first[type_] == before[type_] + 1
        assert controller.get_obj_base_ptr(first_uuid) == first.base_ptr

        second, second_uuid = exact_allocation(controller, type_, factory)
        assert second_uuid.uuid_cnt == after_first[type_]
        assert controller.get_obj_base_ptr(second_uuid) == second.base_ptr
    finally:
        ensure_izombie_brains(controller, board)
        assert controller.end_jump_frame()

    # end_jump_frame may execute another game frame.  Do not compare counters
    # across it; only validate the current live slots' UUID/pointer closure.
    all_live_uuids(controller)
    prepare_empty_board(controller, board)


def check_allocation_paths(controller: Controller, board: GameBoard) -> None:
    """Run all four real allocator paths and their single-free lifecycles."""
    check_plant_path(controller, board)
    check_zombie_path(controller, board)
    check_griditem_scenarios(controller, board)
    check_projectile_path(controller, board)
    check_jump_controlled_allocations(controller, board)
    prepare_empty_board(controller, board)


def setup_fixtures(
    controller: Controller, board: GameBoard
) -> dict[int, tuple[Any, ObjUuid]]:
    """Create one live fixture of each type for the free_all checks."""
    prepare_runnable_board(controller, board)
    baseline = set(live_uuids(controller, ObjType.PROJECTILE))
    plant, plant_uuid = exact_allocation(
        controller, ObjType.PLANT, factory_for(board, ObjType.PLANT)
    )
    zombie, zombie_uuid = exact_allocation(
        controller, ObjType.ZOMBIE, factory_for(board, ObjType.ZOMBIE)
    )
    grid, grid_uuid = exact_allocation(
        controller, ObjType.GRID_ITEM, factory_for(board, ObjType.GRID_ITEM)
    )
    projectile, projectile_uuid = wait_for_projectile(
        controller, board, plant, baseline
    )
    return {
        int(ObjType.PLANT): (plant, plant_uuid),
        int(ObjType.ZOMBIE): (zombie, zombie_uuid),
        int(ObjType.PROJECTILE): (projectile, projectile_uuid),
        int(ObjType.GRID_ITEM): (grid, grid_uuid),
    }


def check_free_all_one(
    controller: Controller,
    board: GameBoard,
    fixtures: dict[int, tuple[Any, ObjUuid]],
    type_: ObjType,
) -> None:
    target = fixtures[int(type_)]
    before_live = live_uuids(controller, type_)
    assert before_live
    target_obj, target_uuid = target
    assert target_uuid in before_live
    assert controller.get_obj_base_ptr(target_uuid) == target_obj.base_ptr
    before_block = controller.get_obj_block_ptr(type_)
    assert before_block
    before_next = next_counts(controller)

    object_list(board, type_).free_all()
    board.process_delete_queue()

    for uuid in before_live:
        assert controller.get_obj_base_ptr(uuid) == 0
    max_size = min(controller.get_obj_max_size(type_), OBJ_UUID_SLOT_COUNT)
    assert all(not controller.get_obj_uuid(type_, i) for i in range(max_size))
    assert controller.get_obj_block_ptr(type_) == before_block
    assert next_counts(controller) == before_next

    for other in OBJ_TYPES:
        if other == type_:
            continue
        other_obj, other_uuid = fixtures[int(other)]
        assert controller.get_obj_base_ptr(other_uuid) == other_obj.base_ptr

    # Rebuild the target only after its free_all assertions.  This keeps the
    # preserved non-target fixtures observable while the target is empty.
    if type_ == ObjType.PROJECTILE:
        plant, _ = fixtures[int(ObjType.PLANT)]
        baseline = set(live_uuids(controller, ObjType.PROJECTILE))
        replacement, replacement_uuid = wait_for_projectile(
            controller, board, plant, baseline
        )
    else:
        replacement, replacement_uuid = exact_allocation(
            controller, type_, factory_for(board, type_)
        )
    fixtures[int(type_)] = (replacement, replacement_uuid)


def check_free_all_lifecycles(
    controller: Controller, board: GameBoard
) -> None:
    fixtures = setup_fixtures(controller, board)
    for type_ in (
        ObjType.PLANT,
        ObjType.ZOMBIE,
        ObjType.PROJECTILE,
        ObjType.GRID_ITEM,
    ):
        check_free_all_one(controller, board, fixtures, type_)


def wait_for_operator(
    controller: Controller, prompt: str, board: GameBoard | None = None
) -> None:
    if board is not None:
        ensure_izombie_brains(controller, board)
    controller.end()
    input(prompt)
    controller.start()


def check_board_transition(
    controller: Controller,
    board: GameBoard,
    before_leave_next: dict[ObjType, int],
    old_uuids: dict[ObjType, list[ObjUuid]],
) -> GameBoard:
    """Check unpublish, then observe and validate a newly published Board."""
    wait_for_operator(
        controller,
        "请退出关卡，等待游戏主菜单显示，然后回终端按 Enter... ",
        board,
    )
    # wait_for_operator returns with the same Controller prepared on the menu.
    for type_ in OBJ_TYPES:
        assert controller.get_obj_array_ptr(type_) == 0
        assert controller.get_obj_block_ptr(type_) == 0
        assert controller.get_obj_max_size(type_) == 0

    # All old UUIDs are invalid while the Board is absent.
    for uuids in old_uuids.values():
        for uuid in uuids:
            assert controller.get_obj_base_ptr(uuid) == 0

    # Repeated reads check that next is stable without a Board.
    no_board_next = assert_getters_stable(controller)
    for type_ in OBJ_TYPES:
        # The user was allowed to leave the game running before unpublish.
        assert no_board_next[type_] >= before_leave_next[type_]
        assert no_board_next[type_] != 0

    # No extra prompt.  The same Controller is released/reacquired on the
    # already-visible menu; exact equality is safe with no Board present.
    controller.end()
    controller.start()
    for type_ in OBJ_TYPES:
        assert controller.get_obj_array_ptr(type_) == 0
        assert controller.get_obj_block_ptr(type_) == 0
        assert controller.get_obj_max_size(type_) == 0
    assert assert_getters_stable(controller) == no_board_next
    for uuids in old_uuids.values():
        for uuid in uuids:
            assert controller.get_obj_base_ptr(uuid) == 0

    wait_for_operator(
        controller,
        "请重新进入我是僵尸关卡，等待关卡画面显示，然后回终端按 Enter... ",
    )
    # Read before get_board; get_board consumes isBoardPtrValid only.
    before_get_board = assert_getters_stable(controller)
    for type_ in OBJ_TYPES:
        # Board construction/scanner may have consumed IDs while the user
        # was entering the level.
        assert before_get_board[type_] >= no_board_next[type_]
        assert before_get_board[type_] != 0

    board = get_board(controller)
    after_get_board = assert_getters_stable(controller)
    assert after_get_board == before_get_board
    for type_ in OBJ_TYPES:
        assert controller.get_obj_array_ptr(type_) == (
            board.base_ptr + type_.BOARD_ARRAY_OFFSET
        )
        for uuid in old_uuids[type_]:
            assert controller.get_obj_base_ptr(uuid) == 0
    return board


def run_checks(controller: Controller) -> None:
    wait_for_operator(
        controller,
        "请进入任意我是僵尸关卡，无需清场；等待关卡画面显示后回终端按 Enter... ",
    )

    board = get_board(controller)
    prepare_empty_board(controller, board)
    check_public_api(controller)
    check_allocation_paths(controller, board)

    check_free_all_lifecycles(controller, board)
    # Restore the complete IZombie fixture before taking transition snapshots
    # and before releasing control.  This is deliberately after the free_all
    # evidence, which leaves only its replacement GridItem alive.
    ensure_izombie_brains(controller, board)
    before_leave_next = next_counts(controller)
    old_uuids = all_live_uuids(controller)
    board = check_board_transition(controller, board, before_leave_next, old_uuids)

    # The new Board must use the same manager history.  Repeat every real path
    # (including natural Projectile firing) after the transition.
    check_allocation_paths(controller, board)

    # Normal context exit resumes the game before closing it.
    ensure_izombie_brains(controller, board)


def main() -> None:
    with InjectedGame() as game:
        run_checks(game.controller)
    print(
        "\nUUID smoke 检查完成。\n"
        "已覆盖：按类型创建、无帧即时可见、同段 asm 连续创建/释放重建、"
        "reset_stack、跳帧、单体 free、free_all、"
        "无 Board 与 NEW Board 的连续发号。\n"
        "未覆盖：主动 GridItem dispose（已从默认 smoke 删除）；"
        "LoadGame（未单独确认菜单重进是否触发读档及 scanner）；"
        "晚注入 scanner（晚注入模式已移除，未执行）。"
    )


if __name__ == "__main__":
    main()


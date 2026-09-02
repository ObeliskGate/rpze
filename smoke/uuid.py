"""Destructive integration smoke test for the UUID v1 object metadata hooks.

Set ``RP_GAME_PATH`` as usual, then run::

    python smoke/uuid.py

The harness starts and injects PvZ through :class:`InjectedGame`. It creates and
deletes GridItems, disposes the GridItem DataArray, and asks the operator to
create a new Board and perform a successful LoadGame. Use a disposable game
session/save.
"""

from __future__ import annotations

from rpze.basic import asm
from rpze.basic.inject import InjectedGame
from rpze.rp_extend import Controller, ObjType, ObjUuid, OBJ_UUID_SLOT_COUNT
from rpze.structs.game_board import GameBoard, get_board


OBJ_TYPES = (
    ObjType.PLANT,
    ObjType.ZOMBIE,
    ObjType.PROJECTILE,
    ObjType.GRID_ITEM,
)


def live_uuids(controller: Controller, type_: ObjType) -> list[ObjUuid]:
    """Return UUIDs for all slots whose PvZ mID says they are live."""
    array = controller.get_obj_array_ptr(type_)
    block = controller.get_obj_block_ptr(type_)
    max_used = 0 if not array else controller.read_u32(array + 4)
    count = min(max_used or 0, controller.get_obj_max_size(type_), OBJ_UUID_SLOT_COUNT)
    stride = type_.ITEM_SIZE + 4
    result: list[ObjUuid] = []
    for index in range(count):
        m_id = controller.read_u32(block + stride * index + type_.ITEM_SIZE)
        uuid = controller.get_obj_uuid(type_, index)
        assert bool(uuid) == bool(m_id and m_id >> 16), (type_, index, m_id, uuid)
        if uuid:
            assert controller.get_obj_base_ptr(uuid) == block + stride * index
            result.append(uuid)
    return result


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


def check_attach_scanner(controller: Controller) -> None:
    # Attaching after Board construction bypasses Alloc hooks; every live mID
    # must nevertheless have received a UUID from the one-shot scanner.
    for type_ in OBJ_TYPES:
        live_uuids(controller, type_)


def check_alloc_free_realloc(controller: Controller, board: GameBoard) -> ObjUuid:
    item = board.new_iz_brain(0)
    first = controller.get_obj_uuid_by_ptr(ObjType.GRID_ITEM, item.base_ptr)
    assert first and first.uuid_cnt != 0
    assert controller.get_obj_base_ptr(first) == item.base_ptr

    item.die()
    board.process_delete_queue()
    assert controller.get_obj_base_ptr(first) == 0

    replacement = board.new_iz_brain(0)
    second = controller.get_obj_uuid_by_ptr(ObjType.GRID_ITEM, replacement.base_ptr)
    assert second and second.index == first.index
    assert second.uuid_cnt != first.uuid_cnt
    assert controller.get_obj_base_ptr(first) == 0
    return second


def check_one_run_free_realloc(
    controller: Controller, board: GameBoard, current: ObjUuid
) -> ObjUuid:
    ptr = controller.get_obj_base_ptr(current)
    code = f"""
        push esi
        push edi
        mov esi, {ptr}
        call {0x44D000}  // GridItem::Die
        mov esi, {board.base_ptr}
        call {0x41BAD0}  // Board::ProcessDeleteQueue
        xor edi, edi
        mov eax, {board.base_ptr}
        push 1
        call {0x408F40}  // Board::AddALadder
        mov [{controller.result_address}], eax
        pop edi
        pop esi
        ret
    """
    asm.run(code, controller)
    replacement = controller.get_obj_uuid_by_ptr(
        ObjType.GRID_ITEM, controller.result_u32
    )
    assert replacement and replacement.index == current.index
    assert replacement.uuid_cnt != current.uuid_cnt
    assert controller.get_obj_base_ptr(current) == 0
    return replacement


def check_free_all(controller: Controller, board: GameBoard) -> None:
    block = controller.get_obj_block_ptr(ObjType.GRID_ITEM)
    board.griditem_list.free_all()
    assert controller.get_obj_block_ptr(ObjType.GRID_ITEM) == block
    max_size = min(controller.get_obj_max_size(ObjType.GRID_ITEM), OBJ_UUID_SLOT_COUNT)
    assert all(not controller.get_obj_uuid(ObjType.GRID_ITEM, i) for i in range(max_size))


def check_dispose(controller: Controller) -> None:
    type_ = ObjType.GRID_ITEM
    array = controller.get_obj_array_ptr(type_)
    code = f"""
        push esi
        mov esi, {array}
        call {0x41E190}  // DataArray<GridItem>::Dispose
        pop esi
        ret
    """
    asm.run(code, controller)
    assert controller.get_obj_array_ptr(type_) == array
    assert controller.get_obj_block_ptr(type_) == 0
    assert controller.get_obj_max_size(type_) == 0


def wait_for_operator(controller: Controller, prompt: str) -> None:
    controller.end()
    input(prompt)
    controller.start()


def check_new_board(controller: Controller, old_uuid: ObjUuid) -> GameBoard:
    wait_for_operator(controller, "Create/enter a NEW Board, then press Enter here... ")
    board = get_board(controller)
    assert controller.get_obj_base_ptr(old_uuid) == 0
    for type_ in OBJ_TYPES:
        assert controller.get_obj_array_ptr(type_) == board.base_ptr + type_.BOARD_ARRAY_OFFSET
    return board


def check_load_game(controller: Controller, board: GameBoard) -> None:
    before = [uuid for type_ in OBJ_TYPES for uuid in live_uuids(controller, type_)]
    board_ptr = board.base_ptr
    wait_for_operator(controller, "Perform a SUCCESSFUL LoadGame, then press Enter here... ")
    loaded = get_board(controller)
    assert loaded.base_ptr == board_ptr
    assert all(controller.get_obj_base_ptr(uuid) == 0 for uuid in before)
    for type_ in OBJ_TYPES:
        live_uuids(controller, type_)


def main() -> None:
    with InjectedGame() as game:
        controller = game.controller
        wait_for_operator(controller, "Enter any level, then press Enter here... ")
        board = get_board(controller)
        check_public_api(controller)
        check_attach_scanner(controller)
        current = check_alloc_free_realloc(controller, board)
        current = check_one_run_free_realloc(controller, board, current)
        check_free_all(controller, board)

        old = board.new_iz_brain(0)
        old_uuid = controller.get_obj_uuid_by_ptr(ObjType.GRID_ITEM, old.base_ptr)
        check_free_all(controller, board)
        check_dispose(controller)
        board = check_new_board(controller, old_uuid)
        check_load_game(controller, board)

        print("UUID v1 smoke passed")


if __name__ == "__main__":
    main()

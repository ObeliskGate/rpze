from rp_extend import Controller
import keystone as ks


def run(code: str, controller: Controller) -> bool:
    r = decode(code)
    controller.run_code(r, len(r))
    

def decode(code: str) -> bytes:
    try:
        k = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
        asm, _ = k.asm(code, as_bytes=True)
        return asm
    except ks.KsError as e:
        raise RuntimeError(f"asm error, {e}") from e
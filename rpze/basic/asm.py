from rp_extend import Controller
import keystone as ks


def run(code: str, controller: Controller) -> bool:
    try:
        k = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
        asm, _ = k.asm(code, as_bytes=True)
        return controller.run_code(asm, len(asm))
    except ks.KsError as e:
        print(f"ERROR: {e}")

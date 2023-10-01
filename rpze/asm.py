from rp_extend import Controller
import keystone.x86_const as x86
import keystone as ks

def encode(code):
    try:
       # Initialize engine in X86-32bit mode
        k = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
        return k.asm(code, as_bytes=True)
    except ks.KsError as e:
        print("ERROR: %s" % e)
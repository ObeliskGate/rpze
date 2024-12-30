add_requires("minhook 1.3.3", { arch = "x86", 
    configs = { lto = true, cxflags = { "-FI intrin.h" } }})
add_requires("boost", { arch = "x86", 
    configs = { lto = true, container = true}})

target("rp_dll")
    set_languages("cxx23")
    add_packages("minhook", "boost")
    add_syslinks("User32")
    set_encodings("utf-8")
    set_kind("shared")
    add_includedirs("../sharedinc")
    add_includedirs("inc")
    add_files("src/*.cpp")
    add_defines("RP_DLL")
    set_pcxxheader("inc/stdafx.h")
    if is_mode("release") or is_mode("releasedbg") then
        set_policy("build.optimization.lto", true)
        set_warnings("allextra")
    end

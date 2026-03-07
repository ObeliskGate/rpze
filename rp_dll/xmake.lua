add_requires("minhook >= 1.3.4", { arch = "i386", plat="mingw", configs = { 
        runtimes  = "MT", 
        -- lto = true,  -- LTO 会导致链接失败，应该是 xmake/minhook 上游 bug
        shflags = { "-static" },
        ldflags = { "-static" },
    } })


target("rp_dll")
    set_plat("mingw")
    set_arch("i386")
    set_languages("cxx23")
    set_filename("rp_dll.dll")
    add_packages("minhook")
    add_links("stdc++exp")
    add_syslinks("User32")
    set_encodings("utf-8")

    add_ldflags("-static", {force = true})
    add_shflags("-static", {force = true})

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

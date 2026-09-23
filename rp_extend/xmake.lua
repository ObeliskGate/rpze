add_requires("pybind11 >= 3.0.1") -- for Python 3.14 support

target("rp_extend")
    add_packages("pybind11")
    set_languages("cxx23")
    set_encodings("utf-8")
    add_rules("python.module", { soabi = true })
    add_includedirs("../sharedinc")
    add_includedirs("inc")
    add_files("src/*.cpp")
    set_pcxxheader("inc/stdafx.h")

    add_defines("NOMINMAX")

    if is_mode("release") or is_mode("releasedbg") then
        set_policy("build.optimization.lto", true)
        if is_plat("windows") then
            add_shflags("/LTCG", {force = true})
        end
        set_warnings("allextra")
    end

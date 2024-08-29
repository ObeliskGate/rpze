add_requires("pybind11 >= 2.13.5")

target("rp_extend")
    add_packages("pybind11")
    set_languages("cxx23")
    set_encodings("utf-8")
    add_rules("python.library", { soabi = true })
    add_includedirs("../sharedinc")
    add_includedirs("inc")
    add_files("src/*.cpp")
    set_pcxxheader("inc/stdafx.h")
    if is_mode("release") or is_mode("releasedbg") then
        set_policy("build.optimization.lto", true)
        set_warnings("allextra")
    end
    -- add_shflags("/PDBALTPATH:%_PDB%")
    -- add_ldflags("/PDBALTPATH:%_PDB%")
    
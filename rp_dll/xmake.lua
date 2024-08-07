add_requires("minhook", { arch = "x86", configs = { lto = true }})

target("rp_dll")
    set_languages("cxx23")
    add_packages("minhook")
    add_syslinks("User32")
    set_encodings("utf-8")
    set_kind("shared")
    add_includedirs("../sharedinc")
    add_includedirs("inc")
    add_files("src/*.cpp")
    add_defines("RP_DLL")
    if is_mode("release") or is_mode("releasedbg") then
        set_policy("build.optimization.lto", true)
    end
    -- add_ldflags("/PDBALTPATH:%_PDB%")
    -- add_shflags("/PDBALTPATH:%_PDB%")

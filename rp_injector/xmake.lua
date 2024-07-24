target("rp_injector")
    set_kind("binary")
    add_files("*.cpp")
    set_languages("cxx23")
    add_includedirs("../sharedinc")
    set_warnings("allextra")
    
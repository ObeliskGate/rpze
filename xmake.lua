set_xmakever("2.7.1")
add_requires("python 3.x", {system = true})

includes("**/xmake.lua")


add_rules("mode.debug", "mode.releasedbg", "mode.release")
add_rules("plugin.compile_commands.autoupdate", {outputdir = ".vscode", lsp = "clangd"})


target("prebuild")
    set_kind("phony")
    on_config(function(target)
        if not os.isdir("./src/rpze/bin") then
            os.mkdir("./src/rpze/bin")
        end
    end)
    before_build(function(target)
        os.rm("./src/rpze/bin/*")
        os.rm("./src/rpze/*.pyd")
        os.rm("./src/rpze/*.pdb")
    end)
    before_clean(function(target)
        os.rm("./src/rpze/bin/*")
        os.rm("./src/rpze/*.pyd")
        os.rm("./src/rpze/*.pdb")
    end)


target("rp_dll")
    set_arch("x86")
    add_deps("prebuild")
    after_build(function (target)
        os.cp(target:targetfile(), "./src/rpze/bin/")
    end)

target("rp_injector")
    set_arch("x86")
    add_deps("prebuild")
    after_build(function (target)
        os.cp(target:targetfile(), "./src/rpze/bin/")
    end)

target("rp_extend")
    add_deps("prebuild")
    after_build(function (target)
        os.cp(target:targetfile(), "./src/rpze/")
    end)
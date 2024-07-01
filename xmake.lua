includes("**/xmake.lua")
if is_mode("release") or is_mode("releasedbg") then
    set_runtimes("MT")
else 
    set_runtimes("MTd")
end


add_rules("mode.debug", "mode.releasedbg")
add_rules("plugin.compile_commands.autoupdate", {outputdir = ".vscode", lsp = "clangd"})


target("prebuild")
    set_kind("phony")
    on_config(function(target)
        import("lib.detect.find_tool")
        assert(is_plat("windows"), "Only support windows")

        local python = assert(find_tool("python3"), "Python3 not found")
        local arch = try { function() return os.iorunv(python.program, {"-c", 
            "import sys; print('x86' if sys.maxsize < 2**32 else 'x64')"}) end}
        local version = os.iorunv(python.program, {"--version"})
        if arch and version then
            local arch = arch:trim()
            print(version:trim() .. ": " .. arch)  -- arch由Python版本决定而不是操作系统
            assert(is_arch(arch), "Python arch must be same with the project arch")
        end

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
        if os.isfile(target:targetdir().."/rp_dll.pdb") then
            os.cp(target:targetdir().."/rp_dll.pdb", "./src/rpze/bin/")
        end
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
        if os.isfile(target:targetdir().."/rp_extend.pdb") then
            os.mv(target:targetdir().."/rp_extend.pdb", "./src/rpze/")
        end
    end)
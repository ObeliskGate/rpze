includes("**/xmake.lua")

add_rules("mode.debug", "mode.release", "mode.releasedbg")
add_rules("plugin.compile_commands.autoupdate", {outputdir = ".vscode", lsp = "clangd"})

target("prebuild")
    set_kind("phony")
    before_build(function(target)
        import("lib.detect.find_tool")
        assert(is_plat("windows"), "Only support windows")
        local python = find_tool("python3")
        arch = os.arch()
        if python then
            arch = try { function() return os.iorunv(python.program, {"-c", 
                "import sys; print('x86' if sys.maxsize < 2**32 else 'x64')"}) end}
            if arch then
                print("Python arch: " .. arch)  -- arch由Python版本决定而不是操作系统
            else
                arch = os.arch()
            end
        end

        os.rm("./src/rpze/bin/*")
        os.rm("./src/rpze/*.pyd")
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
    set_arch(arch)
    add_deps("prebuild")
    after_build(function (target)
        os.cp(target:targetfile(), "./src/rpze/")
    end)
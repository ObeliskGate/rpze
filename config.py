import subprocess
import sysconfig
import sys
import re
import os
import argparse

def config(lib_dir=None):
    """配置rp_extend的msbuild工程, lib_dir为Python静态库目录"""
    from pybind11 import get_include
    
    os.chdir(os.path.dirname(__file__))
    target = "./rp_extend/rp_extend.vcxproj"

    path_set = set()
    path_set.add(get_include())
    path_set.add(sysconfig.get_path("platinclude"))
    path_set.add(sysconfig.get_path("include"))

    if lib_dir is None:
        lib_dir = sys.base_prefix + "\\libs"

    with open(target, "r") as f:
        content = f.read()

    include_str = ("<AdditionalIncludeDirectories>" + 
        ';'.join(path_set) + ';%(AdditionalIncludeDirectories)' +
        "</AdditionalIncludeDirectories>").replace("\\", "\\\\")

    
    lib_str = ("<AdditionalLibraryDirectories>" + 
        lib_dir + ';%(AdditionalLibraryDirectories)' +
        "</AdditionalLibraryDirectories>").replace("\\", "\\\\")

    content = re.sub(
        r"<AdditionalIncludeDirectories>(.*?)</AdditionalIncludeDirectories>", 
        include_str, 
        content)
    
    content = re.sub(
        r"<AdditionalLibraryDirectories>(.*?)</AdditionalLibraryDirectories>", 
        lib_str,
        content)

    with open(target, "w") as f:
        f.write(content)

    if not os.path.exists("./rpze/src/rpze/bin"):
        os.mkdir("./rpze/src/rpze/bin")

    print("Configure done!")


def _get_latest_whl(directory):
    """找到最新的whl文件"""
    # 初始化变量来追踪最新的文件和时间戳
    latest_time = 0
    latest_file = None

    # 遍历目录中的所有文件
    for entry in os.scandir(directory):
        if entry.is_file() and entry.name.endswith('.whl'):
            # 获取文件的修改时间
            file_time = os.path.getmtime(entry.path)
            # 如果这个文件是更晚修改的，更新追踪变量
            if file_time > latest_time:
                latest_time = file_time
                latest_file = entry.name

    # 检查是否找到了.whl文件并输出结果
    if latest_file is not None:
        return latest_file
    raise RuntimeError("No .whl file found in the directory")

def build(compile=False):
    """构建.whl包"""
    os.chdir(os.path.dirname(__file__))
    platform = "x64" if sys.maxsize > 2**32 else "x86"
    if compile:
        subprocess.run(["msbuild", 
                        "/p:Configuration=Release", 
                        f"/p:Platform={platform}"])
    subprocess.run("python -m build", cwd="./rpze")
    latest_file_name = _get_latest_whl(os.path.abspath("./rpze/dist"))
    platfrom = "win_amd64" if platform == "x64" else "win32"
    pyver = "cp" + str(sys.version_info.major) + str(sys.version_info.minor)
    name, ver, *_ = latest_file_name.split("-")
    new_file_name = (name + "-" + 
                     ver + "-" + 
                     pyver + "-" + 
                     pyver + "-" +
                     platfrom + ".whl")
    try:
        os.chdir("./rpze/dist")
        os.rename(latest_file_name, new_file_name)
    finally:
        os.chdir(os.path.dirname(__file__))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="rpze build script")

    # 添加 --config 参数，带一个可选的值
    parser.add_argument('--config', nargs='?', const=None, default=NotImplemented, 
                        help="""Configure rpze project (optional)
                        
                        Usage: --config [lib_dir]
                        lib_dir: directory of Python .lib files (optional)""")
    # 添加 --build 参数
    parser.add_argument('--build', nargs='?', const=False, default=NotImplemented, 
                        help="""Build rpze.whl (optional)
                        
                        Usage: --build [val]
                        when val is not empty, compile the project. (need msbuild)""")

    # 解析命令行参数
    args = parser.parse_args()

    # 打印参数值
    if args.config is not NotImplemented:
        config(args.config)
    else:
        print("do not configure.")

    if args.build is not NotImplemented:
        build(bool(args.build))
    else:
        print("do not build.")

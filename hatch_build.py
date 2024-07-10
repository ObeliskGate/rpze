import os
import subprocess
import sys
from typing import Any
from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = 'xmake'

    def clean(self, versions: list[str]):
        subprocess.run("xmake c")

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        subprocess.run(f"xmake f -c -m release -a {'x86' if sys.maxsize < 2**32 else 'x64'}")
        subprocess.run("xmake")
        return

    def dependencies(self):
        try:
            subprocess.run("xmake --version", stdout=subprocess.DEVNULL, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("xmake is not installed")
        return []
    
    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        dist_path, file_name = os.path.split(artifact_path)
        arch = 'x86' if sys.maxsize < 2**32 else 'x64'
        platfrom = "win_amd64" if arch == "x64" else "win32"
        pyver = "cp" + str(sys.version_info.major) + str(sys.version_info.minor)
        name, ver, *_ = file_name.split("-")
        new_file_name = (name + "-" + 
                         ver + "-" + 
                         pyver + "-" + 
                         pyver + "-" +
                         platfrom + ".whl")
        cwd = os.getcwd()
        try:
            os.chdir(dist_path)
            fp = os.path.join(dist_path, new_file_name)
            if os.path.isfile(fp):
                os.remove(fp)
            os.rename(file_name, new_file_name)
        finally:
            os.chdir(cwd)
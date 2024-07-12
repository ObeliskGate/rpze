import subprocess
import sys
from typing import Any
from hatchling.builders.hooks.plugin.interface import BuildHookInterface

def config_xmake(arglist):
    subprocess.run(["xmake", "f",  
                    "-a",  'x86' if sys.maxsize < 2**32 else 'x64'] 
                    + arglist)


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = 'custom'

    def clean(self, versions: list[str]):
        subprocess.run("xmake c")

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        platfrom = "win32" if sys.maxsize < 2**32  else "win_amd64"
        pyver = "cp" + str(sys.version_info.major) + str(sys.version_info.minor)
        build_data["tag"] = f"{pyver}-{pyver}-{platfrom}"
        build_data["pure_python"] = False
        config_xmake(["-m", "release", "-c", "-y"])
        subprocess.run("xmake -r")

    def dependencies(self):
        try:
            subprocess.run("xmake --version", stdout=subprocess.DEVNULL, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("xmake is not installed")
        return []
    
if __name__ == "__main__":
    config_xmake(sys.argv[1:])

import subprocess
import sys
from typing import Any


def config_xmake(args):
    subprocess.run(["xmake", "f",
                    "-a", 'x86' if sys.maxsize < 2 ** 32 else 'x64']
                   + args)


if __name__ == "__main__":
    config_xmake(sys.argv[1:])

try:
    from hatchling.builders.hooks.plugin.interface import BuildHookInterface  # noqa
except ImportError:
    sys.exit()


class CustomBuildHook(BuildHookInterface):
    def clean(self, versions: list[str]):  # noqa
        subprocess.run("xmake c")

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:  # noqa
        platform = "win32" if sys.maxsize < 2 ** 32 else "win_amd64"
        pyver = "cp" + str(sys.version_info.major) + str(sys.version_info.minor)
        build_data["tag"] = f"{pyver}-{pyver}-{platform}"
        build_data["pure_python"] = False
        config_xmake(["-m", "release", "-c", "-y"])
        subprocess.run("xmake -r")

    def dependencies(self):  # noqa
        try:
            subprocess.run("xmake --version", stdout=subprocess.DEVNULL, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise RuntimeError("xmake is not installed") from e
        return []

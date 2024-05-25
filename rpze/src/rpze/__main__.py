# -*- coding: utf_8 -*-
"""
验证安装用
"""
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="rpze command line utility")
    parser.add_argument("--path", help="specify a path for running the example")
    args = parser.parse_args()
    if p := args.path:
        print(f"your game path is {p}, "
              f"remember that only 1.0.0.1051_EN on pvz.tools is officially supported")
        try:
            from .basic.inject import InjectedGame
            from .examples.botanical_clock import botanical_clock
        except ImportError as ie:
            raise ImportError("maybe the package is not fully installed?") from ie

        from pathlib import Path
        dir_ = Path(__file__).parent / "bin"
        if not dir_.is_dir():
            raise IOError("/bin is not a directory, "
                          "please turn off the antivirus program and add exclusions.")
        file_names = set()
        for entry in dir_.iterdir():
            if entry.is_file():
                file_names.add(entry.name)
        if file_names != {"rp_dll.dll", "rp_injector.exe"}:
            raise IOError("miss binary dependencies! "
                          "please turn off the antivirus program and add exclusions.")
        try:
            game = InjectedGame(p)
        except (PermissionError, IOError, FileNotFoundError) as e:
            raise IOError("maybe the path is wrong?") from e
        with game:
            botanical_clock(game.controller, False)

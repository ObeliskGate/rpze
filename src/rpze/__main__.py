# -*- coding: utf_8 -*-
"""
验证安装用
"""
import argparse
import os

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="rpze command line utility")
    parser.add_argument("--path", help="pvz game path; defaults to RP_GAME_PATH environment variable")
    args = parser.parse_args()
    p = args.path
    if p is None:
        from dotenv import load_dotenv
        load_dotenv()
        p = os.environ.get("RP_GAME_PATH")
        if p is None:
            parser.error("--path is required if RP_GAME_PATH environment variable is not set")
    if p:
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
        if not {"rp_dll.dll", "rp_injector.exe"} <= file_names:
            raise IOError("miss binary dependencies! "
                          "please turn off the antivirus program and add exclusions.")
        try:
            game = InjectedGame(p)
        except (PermissionError, IOError, FileNotFoundError) as e:
            raise IOError("maybe the path is wrong?") from e
        with game:
            botanical_clock(game.controller, False)

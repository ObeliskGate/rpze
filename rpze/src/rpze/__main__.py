import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="rpze command line utility")
    parser.add_argument("--path", help="specify a path for running the example")
    args = parser.parse_args()
    if p := args.path:
        print(f"your game path is {p}, "
              f"remember that only 1.0.0.1051_EN on pvz.tools is officially supported")
        try:
            from .basic import InjectedGame, enter_ize
            from .examples.botanical_clock import botanical_clock
        except ImportError as ie:
            raise ImportError("maybe the package is not fully installed?") from ie
        try:
            game = InjectedGame(p)
        except (PermissionError, IOError, FileNotFoundError) as e:
            raise IOError("maybe the path is wrong?") from e
        with game:
            enter_ize(game)
            botanical_clock(game.controller, False)

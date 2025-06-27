import hashlib
from pathlib import Path

def generate_hash(file: Path, method: str) -> str:
    hash_func = hashlib.new(method)

    with file.open('rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def get_hash(file: Path, method: str, hash_: Path) -> None:
    hash_str = generate_hash(file, method)

    with hash_.open('w') as f:
        f.write(hash_str)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Generate hash for a file')

    parser.add_argument('file_path')
    parser.add_argument('--method', '-m',
                        choices=hashlib.algorithms_available, 
                        default='sha256')
    parser.add_argument('--path', '-p', default=None)

    args = parser.parse_args()
    if args.path is None:
        hash_path = Path(f"{args.file_path}.{args.method}")
    else:
        hash_path = Path(args.path)

    file_path = Path(args.file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File {file_path} does not exist")
    if not file_path.is_file():
        raise FileNotFoundError(f"Path {file_path} is not a file")
    if hash_path.exists():
        raise FileExistsError(f"File {hash_path} already exists")
    
    get_hash(file_path, args.method, hash_path)
    print(f"Hash for {file_path} using {args.method} saved to {hash_path}")

import hashlib

def get_file_hash(file_path, algo='sha256'):
    hasher = hashlib.new(algo)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def check_known_hashes(file_hash, hash_db='data/known_hashes.txt'):
    with open(hash_db, 'r') as f:
        known_hashes = set(line.strip() for line in f)
    return file_hash in known_hashes

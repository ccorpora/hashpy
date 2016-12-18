import hashlib
import pathlib
import base64
import argparse
import sys
import os

KB = 2**10
MB = KB*KB
GB = KB*MB
TB = KB*GB

algorithms = {'md5', 'sha1', 'sha256', 'sha512'}
ALG_DEFAULTS = {'md5', 'sha1'}
# If the file size is <= MAX_READ_SZ, it will be read all at once,
# otherwise the file will be read in READ_SZ chunks
MAX_READ_SZ = 100 * MB
READ_SZ = 32 * KB

def normalize(algname):
    """Normalize the given algorithm name to match list of algorithms"""
    norm = algname.lower().replace('-', '')
    if norm in algorithms:
        return norm
    else:
        raise ValueError('{} is not known and/or available'.format(algname))

class HashRecord:
    
    def __init__(self, algorithms, data=b''):
        self._hashes = dict()
        for algname in algorithms:
            self._hashes[algname] = hashlib.new(algname, data=data)

    def update(self, data):
        """Updates hash object in self.hashes with data"""
        for ho in self._hashes.values():
            ho.update(data)
        
    def _hashobj(self, algname):
        try:
            return self._hashes[algname]
        except KeyError:
            raise ValueError("No hashes for {} algorithm".format(algname))
    
    @property
    def algorithms(self):
        return set([n for n in self._hashes.keys()])
    
    @property
    def hashes(self):
        return [ho for ho in self._hashes.values()]
            
    def hexdigest(self, algname):
        """Returns a hexdigest of the current state of the algorithm's hash object"""
        return self._hashobj(algname).hexdigest()
    
    def digest(self, algname):
        """Returns a digest of the current state of the algorithm's hash object"""
        return self._hashobj(algname).digest()
    
    def base64digest(self, algname):
        """Returns a digest in base64 of the current state of the algorithm's hash object"""
        return base64.b64encode(self.digest(algname)).decode('ascii')
    
    def __eq__(self, other):
        common_algs = self.algorithms.intersection(other.algorithms)
        if len(common_algs) > 0:
            for algname in common_algs:
                h = self.hexdigest(algname)
                oh = other.hexdigest(algname)
                if (h or oh) and (oh != h):
                    return False
            return True
        else:
            return False      
        

class Hasher:
    """Object to hash files using multiple hash algorithms"""
    
    def __init__(self, *algnames, **kwargs):
        if not algnames:
            self._algorithms = ALG_DEFAULTS
        else:
            self._algorithms = set()
            for i in algnames:
                self.add_algorithm(i)
        self.hashed = 0
        self.errors = 0
        self.files = 0
        self.read_bytes = 0
        
    @property
    def algorithms(self):
        return self._algorithms
    
    def add_algorithm(self, algname):
        """Updates self.algorithms with algorithm"""
        self._algorithms.add(normalize(algname))
        
    def remove_algorithm(self, algname):
        """Removes algorithm from self.algorithms, if it is the only algorithm raises a ValueError"""
        name = normalize(algname)
        if name in self.algorithms:
            if len(self.algorithms) > 1:
                try:
                    self._algorithms.remove(name)
                except KeyError:
                    raise ValueError("{} is not in algorithms".format(name))
            else:
                raise ValueError("Hasher object needs at least one algorithm")
    
    def _hash(self, fpath):
        """Return a HashRecord for hash_file"""
        with fpath.open('rb') as fin:
            if fpath.stat().st_size >= MAX_READ_SZ:
                hr = self._hash_large(fin)
            else:
                data = fin.read()
                hr = HashRecord(self.algorithms, data=data)
                self.read_bytes += len(data)
        return hr
    
    def _hash_large(self, fin):
        """Returns HashRecord of files with sizes larger than max read size"""
        data = fin.read(READ_SZ)
        hr = HashRecord(self.algorithms)
        while data:
            self.read_bytes += len(data)
            hr.update(data)
            data = fin.read(READ_SZ)
        return hr
        
    def hash_file(self, fpath):
        """Hashes a file and returns a HashRecord"""
        self.files += 1
        try:
            hr = self._hash(fpath)
            self.hashed += 1
        except FileNotFoundError:
            self.files -= 1
            raise
        except (IOError, OSError):
            self.errors += 1
            raise
        return hr
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('filepath')
    parser.add_argument('-a', '--algorithms', nargs='+', choices=algorithms, default=ALG_DEFAULTS)
    parser.add_argument('--all', action='store_true')
    parser.add_argument('-r', '--recursive', action='store_true')
    args = parser.parse_args()
    if args.all:
        args.algorithms = sorted(algorithms)
    h = Hasher(*args.algorithms)
    try:
        fpath = pathlib.Path(args.filepath).resolve()
    except FileNotFoundError:
        print("No File found at {}".format(args.filepath))
        sys.exit()
    if fpath.is_file():
        hr = h.hash_file(fpath)
        print(fpath)
        for algname in args.algorithms:
            print('{}: {}'.format(algname.upper(), hr.hexdigest(algname).upper()))
    elif fpath.is_dir() and not args.recursive:
        for fp in fpath.iterdir():
            if fp.is_file():
                try:
                    print(fp)
                except UnicodeEncodeError:
                    print(str(fp).encode(sys.stdout.encoding, errors='replace').decode(sys.stdout.encoding))
                try:
                    hr = h.hash_file(fp)
                except (OSError, IOError) as e:
                    print("ERROR: {}".format(e))
                else:
                    for algname in args.algorithms:
                        print('{}: {}'.format(algname.upper(), hr.hexdigest(algname).upper()))
                print("="* 79)
    elif fpath.is_dir() and args.recursive:
        for root, dirs, fnames in os.walk(str(fpath)):
            for fn in fnames:
                fp = pathlib.Path(root) / fn
                if fp.is_file():
                    try:
                        print(fp)
                    except UnicodeEncodeError:
                        print(str(fp).encode(sys.stdout.encoding, errors='replace').decode(sys.stdout.encoding))
                    try:
                        hr = h.hash_file(fp)
                    except (OSError, IOError) as e:
                        print("ERROR: {}".format(e))
                    else:
                        for algname in args.algorithms:
                            print('{}: {}'.format(algname.upper(), hr.hexdigest(algname).upper()))
                    print("="* 79)        
    else:
        print("Need to supply a file path or directory path")
        
#__all__ = ["Hasher", "Verifier", "algorithms"]
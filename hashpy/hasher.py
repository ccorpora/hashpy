import hashlib
import pathlib
import base64
import argparse
import sys

KB = 2**10
MB = KB*KB
GB = KB*MB
TB = KB*GB

algorithms = ('md5', 'sha1', 'sha256', 'sha512')
ALG_DEFAULTS = ('md5', 'sha1')
# if file size is <= MAX_READ_SZ bytes, if will be read at once,
# otherwise the file will be read with multiple read calls
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
    
    def __init__(self, *algnames, data=b''):
        tmp = []
        for name in algnames:
            name = normalize(name)
            if name in tmp:
                pass
            else:
                tmp.append(hashlib.new(name, data))
        if not tmp:
            for name in ALG_DEFAULTS:
                tmp.append(hashlib.new(normalize(name), data))
        self._hashes = tuple(tmp)

    def update(self, data):
        """Updates hash object in self.hashes with data"""
        for ho in self.hashes:
            ho.update(data)
            
    @property
    def hashes(self):
        return self._hashes
        
    def _get_hashobj(self, algname):
        algname = normalize(algname)
        for ho in self.hashes:
            if ho.name == algname:
                return ho
        raise ValueError('No {} hash objects'.format(algname))
            
    def to_hex(self, algname):
        """Returns a hexdigest of the current state of the algorithm's hash object"""
        return self._get_hashobj(algname).hexdigest()
    
    def to_bytes(self, algname):
        """Returns a digest of the current state of the algorithm's hash object"""
        return self._get_hashobj(algname).digest()
    
    def to_base64(self, algname):
        """Returns a digest in base64 of the current state of the algorithm's hash object"""
        return base64.b64encode(self._get_hashobj(algname).to_bytes())
    
    @property    
    def algorithms(self):
        tmp = [h.name for h in self.hashes]
        tmp.sort()
        return tuple(tmp)
    
    def __eq__(self, other):
        common_algs = set(self.algorithms).intersection(set(other.algorithms))
        if len(common_algs) > 1:
            for algname in common_algs:
                h = self.to_hex(alg)
                oh = other.to_hex(alg)
                if (h or oh) and (oh != h):
                    return False
            return True
        else:
            raise ValueError("No common algorithms were used for hashing")
                
class Hasher:
    """Object to hash files using multiple hash algorithms"""
    
    def __init__(self, *algorithms, read_sz=READ_SZ, max_read_sz=MAX_READ_SZ):
        if not algorithms:
            self.algorithms = ALG_DEFAULTS
        else:
            self.algorithms = None
            for alg in algorithms:
                self.add(alg)
        if read_sz < GB and read_sz > 0:
            self.read_sz = read_sz
        else:
            self.read_sz = MAX_READ_SZ
        if max_read_sz < GB and max_read_sz > 0:
            self.max_read_sz = max_read_sz
        else:
            self.max_read_sz = MAX_READ_SZ
        self.hashed = 0
        self.errors = 0
        self.files = 0
        self.read_bytes = 0
        
    def add(self, algname):
        """Updates self.algorithms with algorithm"""
        if self.algorithms:
            new = set(self.algorithms)
        else:
            new = set()
        algname = normalize(algname)
        new.add(algname)
        self.algorithms = tuple(new)
        
    def remove(self, algname):
        """Removes algorithm from self.algorithms, if it is the only algorithm raises a ValueError"""
        algname = normalize(algname)
        if algname in self.algorithms:
            if len(self.algorithms) > 1:
                new = list(self.algorithms)
                new.remove(algname)
                self.algorithms = tuple(new)
            else:
                raise ValueError("Hasher object needs at least one algorithm")
    
    def _hash(self, fpath):
        """Return a HashRecord for hash_file"""
        with fpath.open('rb') as fin:
            if fpath.stat().st_size >= self.max_read_sz:
                hr = self._hash_large(fin)
            else:
                data = fin.read()
                hr = HashRecord(*self.algorithms, data=data)
                self.read_bytes += len(data)
        return hr
    
    def _hash_large(self, fin):
        """Returns HashRecord of files with sizes larger than max read size"""
        data = fin.read(self.read_sz)
        hr = HashRecord(*self.algorithms)
        while data:
            self.read_bytes += len(data)
            hr.update(data)
            data = fin.read(self.read_sz)
        return hr
        
    def hash_file(self, fpath):
        """Hashes a file and returns a HashRecord"""
        self.files += 1
        try:
            hr = self._hash(fpath)
            self.hashed += 1
        except (IOError, OSError) as e:
            self.errors += 1
            raise
        return hr
    
class Verifier(Hasher):
    """Verifies hashes from previously produced hashes"""     
    
    # results of verifications
    HASH_MATCH = 1
    HASH_NO_MATCH = 0
    HASH_FILE_NOT_FOUND = -1
    HASH_READ_ERROR = -2

    def __init__(self, *algorithms):
        super().__init__(*algorithms)
        self.matching = 0
        self.non_matching = 0
        self.not_found = 0

    def verify_hash(self, fpath, hr):
        """Returns results of verification"""
        try:
            fpath = fpath.resolve()
            new_hr = self.hash_file(fpath)
        except FileNotFoundError:
            # count separately from other OSError exceptions
            self.not_found += 1
            res = self.HASH_FILE_NOT_FOUND
        # all other errors when reading
        except (IOError, OSError):
            self.files += 1
            self.errors += 1
            res = self.HASH_READ_ERROR
        else:
            self.files += 1
            self.hashed += 1
            # in case old hash is uppercase
            if new_hr == old_hr:
                res = self.HASH_MATCH
                self.matching += 1
            else:
                res = self.HASH_NO_MATCH
                self.non_matching += 1
        return res
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('filepath')
    parser.add_argument('-a', '--algorithm', nargs='+', choices=algorithms, default=ALG_DEFAULTS)
    args = parser.parse_args()
    h = Hasher(*args.algorithm)
    try:
        fpath = pathlib.Path(args.filepath).resolve()
    except FileNotFoundError:
        print("No File found at {}".format(args.filepath))
        sys.exit()
    if fpath.is_file():
        hr = h.hash_file(fpath)
        print(fpath)
        for algname in args.algorithm:
            print('{}: {}'.format(algname.upper(), hr.to_hex(algname).upper()))
    elif fpath.is_dir():
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
                    for algname in args.algorithm:
                        print('{}: {}'.format(algname.upper(), hr.to_hex(algname).upper()))
                print("="* 79)
    else:
        print("Need to supply a file path or directory path")
import hashlib
import pathlib

KB = 2**10
MB = KB*KB
GB = KB*MB
TB = KB*GB

ALG_NAMES = tuple(sorted(hashlib.algorithms_guaranteed))
ALG_DEFAULTS = ('md5',)
# if file size is <= MAX_READ_SZ bytes, if will be read at once,
# otherwise the file will be read with multiple read calls
MAX_READ_SZ = 100 * MB
READ_SZ = 32 * KB

class HashRecord:
    
    def __init__(self, hashes=None, error=None):
        self.hashes = dict()
        if hashes:
            self.update_hashes(hashes)
        self.error = error
        
    def update_hashes(self, hashes):
        """hashes are either a dict or a iterable of tuples"""
        if not isinstance(hashes, dict):
            hashes = dict(hashes)
        for algname in hashes:
            if algname not in ALG_NAMES:
                raise ValueError('Unknown algorithm: {}'.format(algname))
        self.hashes.update(hashes)
        
    def get_hash(self, name):
        return self.hashes.get(name)
    
    @property    
    def algorithms(self):
        tmp = [k for k in self.hashes]
        tmp.sort()
        return tuple(tmp)
    
    def __eq__(self, other):
        common_algs = set(self.algorithms).intersection(set(other.algorithms))
        if len(common_algs) > 1:
            for alg in common_algs:
                h = self.get_hash(alg)
                oh = self.get_hash(alg)
                if (h or oh) and (oh != h):
                    return False
            return True
        else:
            raise ValueError("No common algorithms were used for hashing")
                
class Hasher:
    """Object to hash files using multiple hash algorithms"""
    
    def __init__(self, *algorithms):
        if not algorithms:
            self.algorithms = ALG_DEFAULTS
        else:
            self.algorithms = None
            for alg in algorithms:
                self.add_algorithm(alg)
        self.hashed = 0
        self.errors = 0
        self.files = 0
        self.read_bytes = 0
        
    def _normalize(self, algorithm):
        """Normalize the given algorithm name to match list of algorithms"""
        new = algorithm.lower().replace('-', '')
        if new in ALG_NAMES:
            return new
        else:
            raise ValueError('{} is not in algorithms used'.format(algorithm))
        
    def add_algorithm(self, algorithm):
        """Updates self.algorithms with algorithm"""
        if self.algorithms:
            new = set(self.algorithms)
        else:
            new = set()
        algorithm = self._normalize(algorithm)
        new.add(algorithm)
        self.algorithms = tuple(new)
        
    def remove_algorithm(self, algorithm):
        """Removes algorithm from self.algorithms, if it is the only algorithm raises a ValueError"""
        algorithm = self._normalize(algorithm)
        if algorithm in self.algorithms:
            if len(self.algorithms > 1):
                new = list(algorithms)
                new.remove(algorithm)
            else:
                raise ValueError("Hasher object needs at least one algorithm")
    
    def _hash(self, fpath):
        """Return hashes of a file as a dict, keys are the algorithm"""
        with fpath.open('rb') as fin:
            if fpath.stat().st_size >= MAX_READ_SZ:
                hashes = self._hash_large(fin)
            else:
                hashes = []
                b = fin.read()
                self.read_bytes += len(b)
                for alg in self.algorithms:
                    hashes.append((alg, hashlib.new(alg, b).hexdigest()))
        return hashes
    
    def _hash_large(self, fin):
        """Return hash of files with sizes larger than max read size"""
        hashes = {}
        for alg in self.algorithms:
            hashes[alg] = hashlib.new(alg)
        b = fin.read(READ_SZ)
        while b:
            self.read_bytes += len(b)
            for hashobj in hashes.values():
                hashobj.update(b)
            b = fin.read(READ_SZ)
        return [(name,hashobj.hexdigest()) for name,hashobj in hashes.items()]
        
    def hash_file(self, fpath):
        """Hashes a file and returns the hashes in a dict"""
        self.files += 1
        hashes = []
        error = None
        try:
            hashes = self._hash(fpath)
            self.hashed += 1
        except (IOError, OSError) as e:
            error = str(e)
            self.errors += 1
        return HashRecord(hashes, error)
    
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
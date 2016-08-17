import hashlib
import pathlib

KB = 2**10
MB = KB*KB
GB = KB*MB
TB = KB*GB

ALG_NAMES = tuple(sorted(hashlib.algorithms_available, key=lambda x: x.lower()))
ALG_DEFAULTS = ('md5',)
# if file size is <= MAX_READ_SZ bytes, if will be read at once,
# otherwise the file will be read with multiple read calls
MAX_READ_SZ = 100 * MB
READ_SZ = 32 * KB

class HashRecord:
    
    def __init__(self, hashes, error=None):
        self.hashes = dict(hashes)
        self.error = error
        
    def add(self, hashes):
        self.hashes.update(hashes)
        
    def get_hash(self, name):
        return self.hashes.get(name)
    
    @property    
    def algorithms(self):
        tmp = [k for k in self.hashes]
        tmp.sort()
        return tuple(tmp)
                
class Hasher:
    """Object to hash files using multiple hash algorithms"""
    
    def __init__(self, *algorithms):
        if not algorithms:
            self.algorithms = ALG_DEFAULTS
        else:
            tmp1 = []
            for alg in algorithms:
                if alg in ALG_NAMES:
                    tmp1.append(alg)
            # if none of the algorithms are available, raise a ValueError
            if not tmp1:
                s = ','.join(algorithms)
                raise ValueError("{} hashes are unknown".format(alg))
            tmp2 = []
            for alg in tmp1:
                if alg.lower() != alg and alg.lower() in tmp2:
                    pass
                else:
                    tmp2.append(alg)
            tmp2.sort()
            self.algorithms = tuple(tmp2)
        self.hashed = 0
        self.errors = 0
        self.files = 0
        self.read_bytes = 0        
            
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
            
        
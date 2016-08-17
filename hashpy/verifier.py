from hasher import Hasher, HashRecord

class Verifier(Hasher):
    """Verifies hashes from previously produced hashes"""     
    
    # results of verifications
    HASH_MATCH = 1
    HASH_NO_MATCH = 0
    HASH_FILE_NOT_FOUND = -1
    HASH_READ_ERROR = -2

    def __init__(self, *algorithms):
        super().__init__(*algorithm)
        self.matching = 0
        self.non_matching = 0
        self.not_found = 0

    def verify_hash(self, fpath, hr):
        """Returns results of verification"""
        try:
            fpath = fpath.resolve()
            new_hash = self.get_hash(fpath)
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
            if new_hash == old_hash.lower():
                res = self.HASH_MATCH
                self.matching += 1
            else:
                res = self.HASH_NO_MATCH
                self.non_matching += 1
        return res
import unittest
import tempfile
import os
import hashpy
from hashpy import Hasher
import hashlib
import random
from pathlib import Path
import sys
import shutil
import os

TEMP_DIRPATH = Path(tempfile.mkdtemp()).resolve()

class TestHasher(unittest.TestCase):
    def setUp(self):
        self.hasher = Hasher('md5')
        self.test_fpath = TEMP_DIRPATH / 'testfile'
        self.test_fpath.touch()
        
    def testFileHashSmall(self):
        b = os.urandom(2**10)
        h = hashlib.md5(b).hexdigest()
        with self.test_fpath.open('wb') as fout:
            fout.write(b)
        testh = self.hasher.hash_file(self.test_fpath)
        self.assertEqual(h, testh)
        self.test_fpath.unlink()
        
    def testFileHashSmall(self):
        b = os.urandom(Hasher.MAX_READ_SZ*2 + 9)
        h = hashlib.md5(b).hexdigest()
        with self.test_fpath.open('wb') as fout:
            fout.write(b)
        testh = self.hasher.hash_file(self.test_fpath)
        self.assertEqual(h, testh)
        self.test_fpath.unlink()

class TestVerifier(unittest.TestCase):
    def setUp(self):
        pass
        
if __name__ == "__main__":
    unittest.main()

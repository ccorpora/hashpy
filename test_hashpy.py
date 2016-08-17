import unittest
import tempfile
import os
import hashpy
from hashpy.hasher import Hasher, KB, MB, MAX_READ_SZ
import hashlib
import random
from pathlib import Path
import sys
import shutil
import os

TEMP_DIRPATH = Path(tempfile.mkdtemp()).resolve()
        
class TestMultiHasher(unittest.TestCase):
    def setUp(self):
        self.mhasher = Hasher('md5', 'sha1')
        self.shasher = Hasher()
        self.test_fpath = TEMP_DIRPATH / 'testfile'
        self.test_fpath.touch()
        
    def testHasherSetup(self):
        self.assertTrue('md5' in self.mhasher.algorithms)
        self.assertTrue('sha1' in self.mhasher.algorithms)
        self.assertTrue('sha1' not in self.shasher.algorithms)
        
    def testFileHashSmall(self):
        b = os.urandom(KB)
        h1 = hashlib.md5(b).hexdigest()
        h2 = hashlib.sha1(b).hexdigest()
        with self.test_fpath.open('wb') as fout:
            fout.write(b)
        mhr = self.mhasher.hash_file(self.test_fpath)
        shr = self.shasher.hash_file(self.test_fpath)
        self.assertEqual(h1, mhr.get_hash('md5'))
        self.assertEqual(h1, shr.get_hash('md5'))
        self.assertEqual(h2, mhr.get_hash('sha1'))
        self.assertIsNone(shr.get_hash('sha1'))
        self.assertEqual(self.mhasher.files, 1)
        self.assertEqual(self.shasher.files, 1)
        self.assertEqual(self.test_fpath.stat().st_size, self.shasher.read_bytes)
        self.assertEqual(self.test_fpath.stat().st_size, self.mhasher.read_bytes)
        self.test_fpath.unlink
        
    def testFileHashLarge(self):
        b = os.urandom(MAX_READ_SZ*3 + 112)
        h1 = hashlib.md5(b).hexdigest()
        h2 = hashlib.sha1(b).hexdigest()
        with self.test_fpath.open('wb') as fout:
            fout.write(b)
        mhr = self.mhasher.hash_file(self.test_fpath)
        shr = self.shasher.hash_file(self.test_fpath)
        self.assertEqual(h1, mhr.get_hash('md5'))
        self.assertEqual(h1, shr.get_hash('md5'))
        self.assertEqual(h2, mhr.get_hash('sha1'))
        self.assertIsNone(shr.get_hash('sha1'))
        self.assertEqual(self.mhasher.files, 1)
        self.assertEqual(self.shasher.files, 1)
        self.assertEqual(self.test_fpath.stat().st_size, self.shasher.read_bytes)
        self.assertEqual(self.test_fpath.stat().st_size, self.mhasher.read_bytes)
        self.test_fpath.unlink()
        
    def testUnknownMultiHash(self):
        h1 = 'unknown-algorithm'
        h2 = 'other-unknown-algorithm'
        with self.assertRaises(ValueError):
            Hasher(h1, h2)

class TestVerifier(unittest.TestCase):
    def setUp(self):
        pass
        
if __name__ == "__main__":
    unittest.main()

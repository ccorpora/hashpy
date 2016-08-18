import unittest
import tempfile
import os
import hashpy
from hashpy import Hasher, HashRecord, Verifier, KB, MB, MAX_READ_SZ
import hashlib
import random
from pathlib import Path
import sys
import shutil
import os

TEMP_DIRPATH = Path(tempfile.mkdtemp()).resolve()

class TestHasher(unittest.TestCase):
    def setUp(self):
        # setup hasher that uses multiple algorithms
        self.mhasher = Hasher('md5', 'sha1')
        # setup hasher that uses a single algorithm, default is MD5
        self.shasher = Hasher()
        self.test_fpath = TEMP_DIRPATH / 'testfile'
        self.test_fpath.touch()
        
    def testHasherSetup(self):
        """Test that the hashers were setup correctly"""
        self.assertTrue('md5' in self.mhasher.algorithms)
        self.assertTrue('sha1' in self.mhasher.algorithms)
        self.assertTrue('sha512' not in self.mhasher.algorithms)
        for alg in hashpy.ALG_NAMES:
            if alg == 'md5':
                self.assertTrue('md5' in self.shasher.algorithms)
            else:
                self.assertTrue(alg not in self.shasher.algorithms)
        
    def testFileHashSmall(self):
        """Test reading a small file"""
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
        """Test reading a large file"""
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
        
    def testFileHashSmallKnown(self):
        """Test reading a small file with a known value"""
        b = b'abc'
        known_md5 = '900150983cd24fb0d6963f7d28e17f72'
        with self.test_fpath.open('wb') as fout:
            fout.write(b)
        hr = self.shasher.hash_file(self.test_fpath)
        self.assertEqual(known_md5, hr.get_hash('md5'))
        self.assertEqual(self.shasher.files, 1)
        self.assertEqual(3, self.shasher.read_bytes)
        self.test_fpath.unlink()     
        
    def testFileHashLargeKnown(self):
        """Test reading a large file"""
        b = b'a' * (2**30)
        known_md5 = 'adb5a28fda6ec2a01075b9945887a083'
        known_sha256 = 'c4d3e5935f50de4f0ad36ae131a72fb84a53595f81f92678b42b91fc78992d84'
        with self.test_fpath.open('wb') as fout:
            fout.write(b)
        self.mhasher = Hasher('md5', 'sha256')
        hr = self.mhasher.hash_file(self.test_fpath)
        self.assertEqual(known_md5, hr.get_hash('md5'))
        self.assertEqual(known_sha256, hr.get_hash('sha256'))
        self.assertEqual(self.mhasher.files, 1)
        self.assertEqual(2**30, self.mhasher.read_bytes)
        self.test_fpath.unlink()    
        
    def testUnknownMultiHash(self):
        h1 = 'unknown-algorithm'
        h2 = 'other-unknown-algorithm'
        with self.assertRaises(ValueError):
            Hasher(h1, h2)
            
class TestHashRecord(unittest.TestCase):
    
    def testHashRecordCreation(self):
        """Test HashRecord creation with a single hash value"""
        name, hash_value = 'md5', hashlib.md5().hexdigest()
        # create with a dictionary
        hr1 = HashRecord(dict([(name, hash_value)]))
        self.assertEqual(hr1.get_hash('md5'), hash_value)
        # create with a list of tuples
        hr2 = HashRecord([(name, hash_value)])
        self.assertEqual(hr2.get_hash('md5'), hash_value) 
        
    def testHashRecordCreationEmpty(self):
        hr = HashRecord()
        for alg in hashpy.ALG_NAMES:
            self.assertEqual(hr.get_hash(alg), None)
        
    def testHashRecordUpdate(self):
        name, hash_value = 'md5', hashlib.md5().hexdigest()
        other, other_value = 'sha1', hashlib.sha1().hexdigest()
        hr = HashRecord(dict([(name, hash_value)]))
        hr.update_hashes([(other, other_value)])
        self.assertEqual(hr.get_hash('sha1'), other_value)
        
    def testHashRecordUpdateUnknown(self):
        name, hash_value = 'md5', hashlib.md5().hexdigest()
        other, other_value = 'unknownalg', hashlib.sha1().hexdigest()
        hr = HashRecord(dict([(name, hash_value)]))
        with self.assertRaises(ValueError):
            hr.update_hashes({other:other_value})
            
    def testHashRecordUpdateNewHash(self):
        name, hash_value = 'md5', hashlib.md5().hexdigest()
        hr = HashRecord(dict([(name, hash_value)]))
        self.assertEqual(hr.get_hash(name), hash_value)
        new_value = hashlib.md5(b'New').hexdigest()
        hr.update_hashes([(name, new_value)])
        self.assertEqual(hr.get_hash(name), new_value)
       

class TestVerifier(unittest.TestCase):
    def setUp(self):
        pass
    
if __name__ == '__main__':
    unittest.main()
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
        # setup hasher that uses a single algorithm
        self.shasher = Hasher('md5')
        self.test_fpath = TEMP_DIRPATH / 'testfile'
        self.test_fpath.touch()
        
    def testHasherSetup(self):
        """Test that the hashers were setup correctly"""
        self.assertTrue('md5' in self.mhasher.algorithms)
        self.assertTrue('sha1' in self.mhasher.algorithms)
        self.assertTrue('sha512' not in self.mhasher.algorithms)
        for alg in hashpy.algorithms:
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
        self.assertEqual(h1, mhr.to_hex('md5'))
        self.assertEqual(h1, shr.to_hex('md5'))
        self.assertEqual(h2, mhr.to_hex('sha1'))
        with self.assertRaises(ValueError):
            shr.to_hex('sha1')
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
        self.assertEqual(h1, mhr.to_hex('md5'))
        self.assertEqual(h1, shr.to_hex('md5'))
        self.assertEqual(h2, mhr.to_hex('sha1'))
        with self.assertRaises(ValueError):
            shr.to_hex('sha1')
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
        self.assertEqual(known_md5, hr.to_hex('md5'))
        self.assertEqual(self.shasher.files, 1)
        self.assertEqual(3, self.shasher.read_bytes)
        self.test_fpath.unlink()
        
    def testFileHashLargeKnown(self):
        """Test reading a large file with a known value"""
        b = b'a' * (2**30)
        known_md5 = 'adb5a28fda6ec2a01075b9945887a083'
        known_sha256 = 'c4d3e5935f50de4f0ad36ae131a72fb84a53595f81f92678b42b91fc78992d84'
        with self.test_fpath.open('wb') as fout:
            fout.write(b)
        self.mhasher = Hasher('md5', 'sha256')
        hr = self.mhasher.hash_file(self.test_fpath)
        self.assertEqual(known_md5, hr.to_hex('md5'))
        self.assertEqual(known_sha256, hr.to_hex('sha256'))
        self.assertEqual(self.mhasher.files, 1)
        self.assertEqual(2**30, self.mhasher.read_bytes)
        self.test_fpath.unlink()    
        
    def testUnknownMultiHash(self):
        h1 = 'md5'
        h2 = 'unknown-algorithm'
        with self.assertRaises(ValueError):
            Hasher(h1, h2)
            
    def testRemoveAlgorithm(self):
        self.mhasher.remove('md5')
        self.assertEqual(self.mhasher.algorithms, ('sha1',))
        
    def testRemoveAlgorithmError(self):
        with self.assertRaises(ValueError):
            self.shasher.remove('md5')
            
    def testAddAlgorithm(self):
        self.shasher.add('sha1')
        self.assertTrue(self.shasher.algorithms, ('md5', 'sha1'))
        
    def testAddAlgorithmError(self):
        with self.assertRaises(ValueError):
            self.shasher.add('unknown')
            
class TestHashRecord(unittest.TestCase):
    
    def testHashRecordCreation(self):
        """Test HashRecord creation with a single hash value"""
        data = b'data'
        name, hash_value = 'md5', hashlib.md5(data).hexdigest()
        hr1 = HashRecord(name, data=data)
        self.assertEqual(hr1.to_hex(name), hash_value)
        
    def testHashRecordCreationEmpty(self):
        hr = HashRecord()
        for algname in hashpy.algorithms:
            if algname in hashpy.ALG_DEFAULTS:
                pass
            else:
                with self.assertRaises(ValueError):
                    hr.to_hex(algname)          

    def testHashRecordUpdate(self):
        data = b'\x00\x01'
        name, hash_value = 'md5', hashlib.md5(data).hexdigest()
        other, other_value = 'sha1', hashlib.sha1(data).hexdigest()
        hr = HashRecord(name, other)
        hr.update(data)
        self.assertEqual(hr.to_hex(name), hash_value)
        self.assertEqual(hr.to_hex(other), other_value)
        
    def testMultipleSame(self):
        n1 = 'md5'
        n2 = 'sha1'
        n3 = 'MD5'
        n4 = 'SHA-1'
        hr = HashRecord(n1, n2, n3, n4)
        self.assertIs(hr._get_hashobj(n1), hr._get_hashobj(n3))
        self.assertIs(hr._get_hashobj(n2), hr._get_hashobj(n4))

class TestVerifier(unittest.TestCase):
    def setUp(self):
        pass
    
if __name__ == '__main__':
    unittest.main()
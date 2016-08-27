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
        self.test_fpath = TEMP_DIRPATH / 'testfile'
        self.test_fpath.touch()
        
    def testHasherSetupMulti(self):
        """Test that the hashers were setup correctly"""
        hasher_ = Hasher('md5', 'sha1', 'sha256')
        for algname in hashpy.algorithms:
            if algname in ('md5', 'sha1', 'sha256'):
                self.assertTrue(algname in hasher_.algorithms)
            else:
                self.assertFalse(algname in hasher_.algorithms)
                
    def testHasherSetupSingle(self):
        """Test that the hashers were setup correctly"""
        hasher_ = Hasher('md5')
        for algname in hashpy.algorithms:
            if algname == 'md5':
                self.assertTrue(algname in hasher_.algorithms)
            else:
                self.assertFalse(algname in hasher_.algorithms)
        
    def hashFileHelper(self, data, algnames, hash_values=None):
        hasher_ = Hasher(*algnames)
        if not hash_values:
            hash_values = {}
            for algname in algnames:
                hash_values[algname] = hashlib.new(algname, data=data).hexdigest()
        with self.test_fpath.open('wb') as fout:
            fout.write(data)
        hr = hasher_.hash_file(self.test_fpath)
        for alg in hashpy.algorithms:
            if alg in algnames:
                self.assertEqual(hash_values[alg], hr.to_hex(alg))
            else:
                with self.assertRaises(ValueError):
                    hr.to_hex(alg)
        self.assertEqual(hasher_.files, 1)
        self.assertEqual(self.test_fpath.stat().st_size, hasher_.read_bytes)
        self.test_fpath.unlink()
        
    def testFileHashSmallMulti(self):
        """Test reading a small file with a Hasher with multiple hash algorithms"""
        b = os.urandom(KB)
        self.hashFileHelper(b, hashpy.algorithms)
        
    def testFileHashSmallSingle(self):
        """Test reading a small file with a Hasher with a single hash algorithm"""
        b = os.urandom(KB)
        self.hashFileHelper(b, ['md5'])
        
    def testFileHashLargeSingle(self):
        """Test reading a large file"""
        b = os.urandom(MAX_READ_SZ*3 + 112)
        self.hashFileHelper(b, ['md5'])
        
    def testFileHashLargeMulti(self):
        """Test reading a large file"""
        b = os.urandom(MAX_READ_SZ*3 + 112)
        self.hashFileHelper(b, ['md5', 'sha1'])
        
    def testFileHashSmallKnownSingle(self):
        """Test reading a small file with a known value"""
        b = b'abc'
        hv = dict()
        hv['md5'] = '900150983cd24fb0d6963f7d28e17f72'
        self.hashFileHelper(b, ['md5'], hash_values=hv)
        
    def testFileHashLargeKnownMulti(self):
        """Test reading a large file with a known value"""
        b = b'a' * (2**30)
        hv = dict()
        hv['md5'] = 'adb5a28fda6ec2a01075b9945887a083'
        hv['sha256'] = 'c4d3e5935f50de4f0ad36ae131a72fb84a53595f81f92678b42b91fc78992d84'
        self.hashFileHelper(b, ['md5', 'sha256'], hash_values=hv)
        
    def testUnknownHashMulti(self):
        h1 = 'md5'
        h2 = 'unknown-algorithm'
        with self.assertRaises(ValueError):
            Hasher(h1, h2)
            
    def testRemoveAlgorithm(self):
        hasher_ = Hasher('md5', 'sha1', 'sha512')
        hasher_.remove('md5')
        self.assertEqual(sorted(hasher_.algorithms), sorted(('sha1', 'sha512')))
    
    def testRemoveAlgorithmError(self):
        hasher_ = Hasher('md5')      
        with self.assertRaises(ValueError):
            hasher_.remove('md5')
            
    def testAddAlgorithm(self):
        hasher_ = Hasher('md5')
        self.assertEqual(hasher_.algorithms, ('md5',))
        hasher_.add('sha1')
        self.assertEqual(sorted(hasher_.algorithms), sorted(('md5', 'sha1')))
        
    def testAddAlgorithmError(self):
        hasher_ = Hasher()
        with self.assertRaises(ValueError):
            hasher_.add('unknown')
            
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
        
    def testFileHashRecordKnown(self):
        """Test reading a small file with a known value"""
        hr = HashRecord('md5', data=b'abc')
        known_md5 = '900150983cd24fb0d6963f7d28e17f72'
        known_md5_bytes = b'\x90\x01P\x98<\xd2O\xb0\xd6\x96?}(\xe1\x7fr'
        known_md5_base64 = 'kAFQmDzST7DWlj99KOF/cg=='
        self.assertEqual(known_md5, hr.to_hex('md5'))
        self.assertEqual(known_md5_bytes, hr.to_bytes('md5'))
        self.assertEqual(known_md5_base64, hr.to_base64('md5'))

class TestVerifier(unittest.TestCase):
    def setUp(self):
        pass
    
if __name__ == '__main__':
    unittest.main()
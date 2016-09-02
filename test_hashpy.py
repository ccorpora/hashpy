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
            hash_values = dict()
            for algname in algnames:
                hash_values[algname] = hashlib.new(algname, data=data).hexdigest()
        with self.test_fpath.open('wb') as fout:
            fout.write(data)
        hr = hasher_.hash_file(self.test_fpath)
        for alg in hashpy.algorithms:
            if alg in algnames:
                self.assertEqual(hash_values[alg], hr.hexdigest(alg))
            else:
                with self.assertRaises(ValueError):
                    hr.hexdigest(alg)
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
        hasher_.remove_algorithm('md5')
        self.assertEqual(sorted(hasher_.algorithms), sorted(('sha1', 'sha512')))
    
    def testRemoveAlgorithmError(self):
        hasher_ = Hasher('md5')      
        with self.assertRaises(ValueError):
            hasher_.remove_algorithm('md5')
            
    def testAddAlgorithm(self):
        hasher_ = Hasher('md5')
        hasher_.add_algorithm('sha1')
        self.assertEqual(sorted(hasher_.algorithms), sorted(('md5', 'sha1')))
        
    def testAddAlgorithmError(self):
        hasher_ = Hasher()
        with self.assertRaises(ValueError):
            hasher_.add_algorithm('unknown')
            
class TestHashRecord(unittest.TestCase):
    
    def testHashRecordCreation(self):
        """Test HashRecord creation with a single hash value"""
        data = b'abc'
        name, hash_value = 'md5', hashlib.md5(data).hexdigest()
        hr = HashRecord([name], data=data)
        self.assertEqual(hr.hexdigest(name), hash_value)
        
    def testHashRecordAlgorithms(self):
        hr = HashRecord(hashpy.algorithms)
        for a in hr.algorithms:
            self.assertIn(a, hashpy.algorithms)
        
    def testHashRecordHashes(self):
        algnames = ['md5', 'sha1']
        hr = HashRecord(algnames)
        self.assertTrue(hr._hashobj('sha1') in hr.hashes)
        self.assertTrue(hr._hashobj('md5') in hr.hashes)

    def testHashRecordUpdate(self):
        data = b'\x00\x01'
        name, hash_value = 'md5', hashlib.md5(data).hexdigest()
        other, other_value = 'sha1', hashlib.sha1(data).hexdigest()
        hr = HashRecord([name, other])
        hr.update(data)
        self.assertEqual(hr.hexdigest(name), hash_value)
        self.assertEqual(hr.hexdigest(other), other_value)
        
    def testHashRecordKnown(self):
        """Test reading a small file with a known value"""
        hr = HashRecord(['md5'], data=b'abc')
        known_md5 = '900150983cd24fb0d6963f7d28e17f72'
        known_md5_bytes = b'\x90\x01P\x98<\xd2O\xb0\xd6\x96?}(\xe1\x7fr'
        known_md5_base64 = 'kAFQmDzST7DWlj99KOF/cg=='
        self.assertEqual(known_md5, hr.hexdigest('md5'))
        self.assertEqual(known_md5_bytes, hr.digest('md5'))
        self.assertEqual(known_md5_base64, hr.base64digest('md5'))
        
    def testHashRecordEqualOneSame(self):
        """Test HashRecord Equals with a single matching hash"""
        hr1 = HashRecord(('md5', 'sha1'), data=b'abc')
        hr2 = HashRecord(('sha256', 'md5'), data=b'abc')
        self.assertEqual(hr1, hr2)
        
    def testHashRecordNotEqual(self):
        """Test HashRecord Equals"""
        hr1 = HashRecord(('md5', 'sha1'), data=b'abc')
        hr2 = HashRecord(('md5', 'sha1'), data=b'123')
        self.assertNotEqual(hr1, hr2)
        
    def testHashRecordEqualTwoDifferent(self):
        """Test HashRecord Not Equal"""
        hr1 = HashRecord(('md5', 'sha1'), data=b'abc')
        hr2 = HashRecord(('sha512', 'sha256'), data=b'abc')
        self.assertNotEqual(hr1, hr2)    

class TestVerifier(unittest.TestCase):
    
    def setUp(self):
        self.test_fpath = TEMP_DIRPATH / 'testfile'   
    
    def verifyFileHelper(self, algnames, data):
        hr = HashRecord(algnames, data=data)
        with self.test_fpath.open('wb') as fout:
            fout.write(data)
        return hr
    
    def testVerifyMatch(self):
        data = b'abc'
        algnames = ('md5', 'sha1')
        hr = self.verifyFileHelper(algnames, data)
        verifier = Verifier(*algnames)
        res = verifier.verify(self.test_fpath, hr)
        self.test_fpath.unlink()
        self.assertEqual(res, Verifier.MATCH)
        self.assertEqual(verifier.errors, 0)
        self.assertEqual(verifier.files, 1)
        self.assertEqual(verifier.hashed, 1)
        self.assertEqual(verifier.matching, 1)
        self.assertEqual(verifier.non_matching, 0)
        
    def testVerifyNoMatch(self):
        data = b'abc'
        algnames = ('md5', 'sha1')
        hr = self.verifyFileHelper(algnames, data)
        with self.test_fpath.open('ab') as fout:
            fout.write(b'123')
        verifier = Verifier(*algnames)
        res = verifier.verify(self.test_fpath, hr)
        self.test_fpath.unlink()
        self.assertEqual(res, Verifier.NO_MATCH)
        self.assertEqual(verifier.errors, 0)
        self.assertEqual(verifier.files, 1)
        self.assertEqual(verifier.hashed, 1)
        self.assertEqual(verifier.matching, 0)
        self.assertEqual(verifier.non_matching, 1)        
        
    def testVerifyFileNotFound(self):
        data = b'abc'
        algnames = ('md5', 'sha1')
        hr = self.verifyFileHelper(algnames, data)
        self.test_fpath.unlink()
        verifier = Verifier(*algnames)
        res = verifier.verify(self.test_fpath, hr)
        self.assertEqual(res, Verifier.FILE_NOT_FOUND)
        self.assertEqual(verifier.errors, 0)
        self.assertEqual(verifier.files, 0)
        self.assertEqual(verifier.hashed, 0)
        self.assertEqual(verifier.matching, 0)
        self.assertEqual(verifier.non_matching, 0)
       
        
    
if __name__ == '__main__':
    unittest.main()
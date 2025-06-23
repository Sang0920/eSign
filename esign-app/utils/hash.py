import hashlib

def get_hash_function(algorithm):
    """Get the appropriate hash function based on algorithm name"""
    hash_functions = {
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_512': hashlib.sha3_512
    }
    
    if algorithm not in hash_functions:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    return hash_functions[algorithm]

def compute_hash(data, algorithm):
    """Compute hash of data using specified algorithm"""
    hash_func = get_hash_function(algorithm)
    return hash_func(data).digest()

def compute_file_hash(file_path, algorithm):
    """Compute hash of a file using specified algorithm"""
    hash_func = get_hash_function(algorithm)()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def get_algorithm_oid(algorithm):
    """Get the OID for the hash algorithm (for ASN.1 encoding)"""
    oids = {
        'sha256': '2.16.840.1.101.3.4.2.1',
        'sha384': '2.16.840.1.101.3.4.2.2', 
        'sha512': '2.16.840.1.101.3.4.2.3',
        'sha3_256': '2.16.840.1.101.3.4.2.8',
        'sha3_512': '2.16.840.1.101.3.4.2.10'
    }
    return oids.get(algorithm)
#!/usr/bin/env python3

import sys
print("Testing fpylll installation...")

try:
    import fpylll
    print(f"fpylll version: {fpylll.__version__}")
    
    from fpylll import LLL, IntegerMatrix
    print("Successfully imported LLL and IntegerMatrix")
    
    # Test basic functionality
    A = IntegerMatrix.random(4, "uniform", bits=4)
    print("Created random matrix:")
    print(A)
    
    LLL.reduction(A)
    print("LLL reduction successful!")
    print("Matrix after reduction:")
    print(A)
    
    print("fpylll is working correctly!")
    
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

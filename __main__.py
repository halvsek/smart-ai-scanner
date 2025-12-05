#!/usr/bin/env python3
"""
SMART-01 AI Security Scanner - Package Entry Point
Enables execution via: python -m smart_ai_scanner

Author: SMART-01 AI Security Research Team
License: MIT
Version: 2.0.0
"""

import sys
import os

def main():
    """Main entry point for package execution"""
    
    # Ensure proper path setup for package execution
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    
    try:
        # Import and run the unified smart-ai-scanner CLI
        import importlib.util
        
        # Load smart-ai-scanner.py as a module
        spec = importlib.util.spec_from_file_location(
            "smart_ai_scanner_main", 
            os.path.join(current_dir, "smart-ai-scanner.py")
        )
        smart_ai_scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smart_ai_scanner)
        
        return smart_ai_scanner.main()
        
    except ImportError as e:
        print(f"Error: Unable to import smart-ai-scanner module: {e}")
        print("Falling back to launcher if available...")
        
        try:
            from launcher import main as launcher_main
            return launcher_main()
        except ImportError:
            print("Error: No CLI modules available")
            return 1
    
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
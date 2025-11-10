#!/usr/bin/env python
import sys
import subprocess

def check_python_version():
    print("Checking Python version...", end=" ")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"✓ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"✗ Python {version.major}.{version.minor}.{version.micro} (need 3.8+)")
        return False

def check_tshark():
    print("Checking tshark installation...", end=" ")
    try:
        result = subprocess.run(['tshark', '-v'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"✓ {version_line}")
            return True
        else:
            print("✗ Not found or error")
            return False
    except FileNotFoundError:
        print("✗ Not found in PATH")
        return False
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        return False

def check_env_file():
    print("Checking .env file...", end=" ")
    try:
        with open('.env', 'r') as f:
            content = f.read()
            if 'SUPABASE_URL' in content and 'VIRUSTOTAL_API_KEY' in content:
                print("✓ Found")
                return True
            else:
                print("✗ Missing required variables")
                return False
    except FileNotFoundError:
        print("✗ Not found")
        return False

def check_directories():
    print("Checking data directories...", end=" ")
    import os
    required_dirs = ['data/uploads', 'data/json_outputs', 'data/vector_db']
    all_exist = all(os.path.exists(d) for d in required_dirs)
    if all_exist:
        print("✓ All present")
        return True
    else:
        print("✗ Some missing")
        return False

def check_ollama_connection():
    print("Checking Ollama connection...", end=" ")
    try:
        import requests
        response = requests.get('http://130.232.102.188:11434/api/tags', timeout=5)
        if response.status_code == 200:
            print("✓ Connected")
            return True
        else:
            print(f"✗ HTTP {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("✗ Connection failed")
        return False
    except requests.exceptions.Timeout:
        print("✗ Timeout")
        return False
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        return False

def check_dependencies():
    print("Checking Python dependencies...", end=" ")
    required = ['fastapi', 'uvicorn', 'pyshark', 'chromadb', 'supabase', 'requests']
    missing = []

    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    if not missing:
        print("✓ All installed")
        return True
    else:
        print(f"✗ Missing: {', '.join(missing)}")
        return False

def main():
    print("\n" + "=" * 60)
    print("PCAP LLM Analyzer - Setup Verification")
    print("=" * 60 + "\n")

    results = []
    results.append(("Python Version", check_python_version()))
    results.append(("Python Dependencies", check_dependencies()))
    results.append(("TShark", check_tshark()))
    results.append(("Environment File", check_env_file()))
    results.append(("Data Directories", check_directories()))
    results.append(("Ollama Connection", check_ollama_connection()))

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {name:.<40} {status}")

    print("\n" + "=" * 60)
    print(f"Result: {passed}/{total} checks passed")
    print("=" * 60 + "\n")

    if passed == total:
        print("✓ All checks passed! You're ready to run the application.")
        print("\nTo start the server, run:")
        print("  python run.py")
        print("  or")
        print("  python -m uvicorn app.main:app --host 0.0.0.0 --port 8000")
    else:
        print("✗ Some checks failed. Please address the issues above.")
        print("\nCommon solutions:")
        print("  - Install dependencies: pip install -r requirements.txt")
        print("  - Install tshark: sudo apt-get install tshark (Linux)")
        print("  - Configure .env file with your API keys")
        print("  - Ensure Ollama is running at http://130.232.102.188:11434")

    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())

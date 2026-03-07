#!/usr/bin/env python3
"""
Quick test script to verify VulnSpectra installation
"""
import sys
import subprocess
import importlib.util

def check_python_version():
    """Check Python version"""
    print("Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"✓ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"✗ Python {version.major}.{version.minor}.{version.micro} (Requires 3.8+)")
        return False

def check_java():
    """Check Java installation"""
    print("\nChecking Java installation (optional for risk analysis)...")
    try:
        result = subprocess.run(['java', '-version'],
                              capture_output=True,
                              text=True)
        if result.returncode == 0:
            print("✓ Java installed")
            return True
        else:
            print("○ Java not found (optional - needed for Java risk analyzer)")
            return True  # Don't fail on missing Java
    except FileNotFoundError:
        print("○ Java not found (optional - needed for Java risk analyzer)")
        return True  # Don't fail on missing Java

def check_maven():
    """Check Maven installation"""
    print("\nChecking Maven installation (optional for building Java module)...")
    try:
        result = subprocess.run(['mvn', '-version'],
                              capture_output=True,
                              text=True)
        if result.returncode == 0:
            print("✓ Maven installed")
            return True
        else:
            print("○ Maven not found (optional - needed to build Java module)")
            return True  # Don't fail on missing Maven
    except FileNotFoundError:
        print("○ Maven not found (optional - needed to build Java module)")
        return True  # Don't fail on missing Maven

def check_dependencies():
    """Check Python dependencies"""
    print("\nChecking Python dependencies...")

    required = [
        'fastapi',
        'uvicorn',
        'requests',
        'colorlog',
        'pydantic',
        'tabulate'
    ]

    optional = [
        'scapy',
        'pandas',
        'numpy'
    ]

    missing = []
    for package in required:
        spec = importlib.util.find_spec(package)
        if spec is None:
            print(f"✗ {package} (required)")
            missing.append(package)
        else:
            print(f"✓ {package}")

    print("\nOptional packages:")
    for package in optional:
        spec = importlib.util.find_spec(package)
        if spec is None:
            print(f"○ {package} (optional - not installed)")
        else:
            print(f"✓ {package} (optional)")

    if missing:
        print(f"\n✗ Missing required packages: {', '.join(missing)}")
        print("Install with: pip install -r requirements.txt")
        return False

    return True

def check_project_structure():
    """Check project structure"""
    print("\nChecking project structure...")

    import os

    required_dirs = [
        'scanner',
        'intelligence',
        'api',
        'dashboard',
        'reporting',
        'utils',
        'analysis_java'
    ]

    required_files = [
        'main.py',
        'requirements.txt',
        'README.md'
    ]

    all_ok = True

    for directory in required_dirs:
        if os.path.isdir(directory):
            print(f"✓ {directory}/")
        else:
            print(f"✗ {directory}/")
            all_ok = False

    for file in required_files:
        if os.path.isfile(file):
            print(f"✓ {file}")
        else:
            print(f"✗ {file}")
            all_ok = False

    return all_ok

def main():
    """Run all checks"""
    print("=" * 60)
    print("VulnSpectra Installation Verification")
    print("=" * 60)

    checks = [
        ("Python Version", check_python_version),
        ("Java", check_java),
        ("Maven", check_maven),
        ("Dependencies", check_dependencies),
        ("Project Structure", check_project_structure)
    ]

    results = []
    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"Error checking {name}: {e}")
            results.append((name, False))

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{name}: {status}")

    all_passed = all(result for _, result in results)

    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All checks passed! VulnSpectra is ready to use.")
        print("\nTry running:")
        print("  python main.py --target 127.0.0.1 --ports 80,443")
    else:
        print("✗ Some checks failed. Please fix the issues above.")
    print("=" * 60)

    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())


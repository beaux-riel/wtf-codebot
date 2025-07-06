#!/usr/bin/env python3
"""Packaging and deployment helper script for WTF CodeBot."""

import argparse
import subprocess
import sys
import os
from pathlib import Path
from typing import List, Tuple


def run_command(cmd: List[str], cwd: str = ".") -> Tuple[int, str]:
    """Run a command and return exit code and output."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode, result.stdout + result.stderr


def check_prerequisites() -> bool:
    """Check if all prerequisites are installed."""
    print("🔍 Checking prerequisites...")
    
    prerequisites = [
        ("poetry", ["poetry", "--version"]),
        ("docker", ["docker", "--version"]),
        ("git", ["git", "--version"]),
    ]
    
    for name, cmd in prerequisites:
        exit_code, _ = run_command(cmd)
        if exit_code != 0:
            print(f"❌ {name} is not installed or not in PATH")
            return False
        print(f"✅ {name} is available")
    
    return True


def run_tests() -> bool:
    """Run the test suite."""
    print("🧪 Running tests...")
    exit_code, _ = run_command(["poetry", "run", "pytest", "--cov=wtf_codebot", "-v"])
    return exit_code == 0


def run_linting() -> bool:
    """Run code quality checks."""
    print("🎨 Running code quality checks...")
    
    checks = [
        (["poetry", "run", "black", "--check", "wtf_codebot/", "tests/"], "Black formatting"),
        (["poetry", "run", "isort", "--check-only", "wtf_codebot/", "tests/"], "Import sorting"),
        (["poetry", "run", "flake8", "wtf_codebot/"], "Flake8 linting"),
        (["poetry", "run", "mypy", "wtf_codebot/"], "Type checking"),
        (["poetry", "run", "bandit", "-r", "wtf_codebot/"], "Security scanning"),
    ]
    
    for cmd, description in checks:
        print(f"Running {description}...")
        exit_code, _ = run_command(cmd)
        if exit_code != 0:
            print(f"❌ {description} failed")
            return False
        print(f"✅ {description} passed")
    
    return True


def build_package() -> bool:
    """Build the Python package."""
    print("📦 Building Python package...")
    exit_code, _ = run_command(["poetry", "build"])
    if exit_code == 0:
        print("✅ Package built successfully")
        # List built files
        dist_dir = Path("dist")
        if dist_dir.exists():
            for file in dist_dir.glob("*"):
                print(f"   📄 {file.name}")
    return exit_code == 0


def build_docker_image(tag: str = "wtfcodebot/wtf-codebot:latest") -> bool:
    """Build Docker image."""
    print(f"🐳 Building Docker image: {tag}")
    exit_code, _ = run_command(["docker", "build", "-t", tag, "."])
    if exit_code == 0:
        print(f"✅ Docker image built successfully: {tag}")
    return exit_code == 0


def test_docker_image(tag: str = "wtfcodebot/wtf-codebot:latest") -> bool:
    """Test Docker image functionality."""
    print(f"🧪 Testing Docker image: {tag}")
    
    tests = [
        (["docker", "run", "--rm", tag, "--help"], "Help command"),
        (["docker", "run", "--rm", tag, "version"], "Version command"),
    ]
    
    for cmd, description in tests:
        print(f"Testing {description}...")
        exit_code, _ = run_command(cmd)
        if exit_code != 0:
            print(f"❌ {description} failed")
            return False
        print(f"✅ {description} passed")
    
    return True


def publish_package() -> bool:
    """Publish package to PyPI."""
    print("🚀 Publishing package to PyPI...")
    
    # Check if PYPI_TOKEN is set
    if not os.getenv("POETRY_PYPI_TOKEN_PYPI"):
        print("❌ POETRY_PYPI_TOKEN_PYPI environment variable not set")
        print("   Set your PyPI token with: export POETRY_PYPI_TOKEN_PYPI=your-token")
        return False
    
    exit_code, _ = run_command(["poetry", "publish"])
    if exit_code == 0:
        print("✅ Package published successfully")
    return exit_code == 0


def push_docker_image(tag: str = "wtfcodebot/wtf-codebot:latest") -> bool:
    """Push Docker image to registry."""
    print(f"🚀 Pushing Docker image: {tag}")
    exit_code, _ = run_command(["docker", "push", tag])
    if exit_code == 0:
        print(f"✅ Docker image pushed successfully: {tag}")
    return exit_code == 0


def clean() -> bool:
    """Clean build artifacts."""
    print("🧹 Cleaning build artifacts...")
    
    paths_to_clean = [
        "dist/",
        "build/",
        "*.egg-info/",
        "__pycache__/",
        ".pytest_cache/",
        ".coverage",
        "htmlcov/",
    ]
    
    for pattern in paths_to_clean:
        if "*" in pattern:
            # Use find for glob patterns
            run_command(["find", ".", "-name", pattern, "-exec", "rm", "-rf", "{}", "+"])
        else:
            path = Path(pattern)
            if path.exists():
                if path.is_dir():
                    run_command(["rm", "-rf", str(path)])
                else:
                    run_command(["rm", "-f", str(path)])
    
    print("✅ Cleaned build artifacts")
    return True


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(description="WTF CodeBot packaging and deployment helper")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Build command
    build_parser = subparsers.add_parser("build", help="Build package and Docker image")
    build_parser.add_argument("--skip-tests", action="store_true", help="Skip running tests")
    build_parser.add_argument("--skip-lint", action="store_true", help="Skip linting checks")
    build_parser.add_argument("--docker-tag", default="wtfcodebot/wtf-codebot:latest", help="Docker image tag")
    
    # Test command
    test_parser = subparsers.add_parser("test", help="Run tests and quality checks")
    test_parser.add_argument("--skip-lint", action="store_true", help="Skip linting checks")
    
    # Package command
    package_parser = subparsers.add_parser("package", help="Build Python package only")
    
    # Docker command
    docker_parser = subparsers.add_parser("docker", help="Build and test Docker image")
    docker_parser.add_argument("--tag", default="wtfcodebot/wtf-codebot:latest", help="Docker image tag")
    docker_parser.add_argument("--test", action="store_true", help="Test the Docker image after building")
    
    # Publish command
    publish_parser = subparsers.add_parser("publish", help="Publish package and Docker image")
    publish_parser.add_argument("--package-only", action="store_true", help="Publish package only")
    publish_parser.add_argument("--docker-only", action="store_true", help="Publish Docker image only")
    publish_parser.add_argument("--docker-tag", default="wtfcodebot/wtf-codebot:latest", help="Docker image tag")
    
    # Clean command
    clean_parser = subparsers.add_parser("clean", help="Clean build artifacts")
    
    # All command
    all_parser = subparsers.add_parser("all", help="Run complete build and test pipeline")
    all_parser.add_argument("--docker-tag", default="wtfcodebot/wtf-codebot:latest", help="Docker image tag")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    success = True
    
    if args.command == "test":
        success &= run_tests()
        if not args.skip_lint:
            success &= run_linting()
    
    elif args.command == "package":
        success &= build_package()
    
    elif args.command == "docker":
        success &= build_docker_image(args.tag)
        if args.test:
            success &= test_docker_image(args.tag)
    
    elif args.command == "build":
        if not args.skip_tests:
            success &= run_tests()
        if not args.skip_lint:
            success &= run_linting()
        success &= build_package()
        success &= build_docker_image(args.docker_tag)
        success &= test_docker_image(args.docker_tag)
    
    elif args.command == "publish":
        if not args.docker_only:
            success &= publish_package()
        if not args.package_only:
            success &= push_docker_image(args.docker_tag)
    
    elif args.command == "clean":
        success &= clean()
    
    elif args.command == "all":
        success &= run_tests()
        success &= run_linting()
        success &= build_package()
        success &= build_docker_image(args.docker_tag)
        success &= test_docker_image(args.docker_tag)
    
    if success:
        print("\n🎉 All operations completed successfully!")
    else:
        print("\n❌ Some operations failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()

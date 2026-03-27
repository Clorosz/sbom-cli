# Contributing to SBOM CLI

Thank you for considering contributing to SBOM CLI! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions.

## How to Contribute

### Reporting Issues

Before creating an issue, please check if it already exists. When creating an issue, include:

- A clear, descriptive title
- Steps to reproduce the problem
- Expected vs. actual behavior
- Python version and OS
- SBOM file sample (if applicable)

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest tests/`)
5. Run linter (`ruff check .`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to your branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/sbom-cli.git
cd sbom-cli

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run linter
ruff check .
```

### Code Style

- Follow PEP 8 guidelines
- Use type hints for function signatures
- Write docstrings for public functions and classes
- Keep functions focused and small
- Use meaningful variable names

### Testing

- Write tests for new features
- Ensure all existing tests pass
- Aim for good test coverage
- Test with different SBOM formats (CycloneDX, SPDX)

### Commit Messages

Follow conventional commit format:

```
feat: add support for SPDX 3.0
fix: resolve database locking issue
docs: update README with new examples
test: add tests for wildcard queries
refactor: simplify license parsing logic
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

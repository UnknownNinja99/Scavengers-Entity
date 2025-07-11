# Contributing to Entity Toolkit

Thank you for your interest in contributing to Entity! This document provides guidelines for contributing to the project.

## 🤝 How to Contribute

### Reporting Issues
1. Check existing issues first
2. Create a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version)

### Suggesting Features
1. Open an issue with the "enhancement" label
2. Describe the feature and its use case
3. Explain why it would be valuable

### Code Contributions

#### Setup Development Environment
1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Scavengers-Entity.git
   cd Scavengers-Entity
   ```
3. Create a virtual environment:
   ```bash
   python -m venv dev-env
   source dev-env/bin/activate  # Linux/Mac
   # or
   dev-env\Scripts\activate     # Windows
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

#### Coding Standards
- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to all functions
- Include error handling
- Test your changes thoroughly

#### Pull Request Process
1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes
3. Test thoroughly
4. Commit with clear messages:
   ```bash
   git commit -m "Add feature: description of what you added"
   ```
5. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
6. Create a Pull Request

## 📋 Development Guidelines

### Adding New Features
- Ensure new features follow the existing menu structure
- Add appropriate error handling
- Include user-friendly output with Rich library
- Test with various inputs and edge cases

### Security Considerations
- Never include hardcoded API keys or credentials
- Validate all user inputs
- Follow responsible disclosure for any vulnerabilities
- Ensure tools are used ethically

### Documentation
- Update README.md for new features
- Add comments for complex code sections
- Include usage examples
- Update SETUP.md if installation changes

## 🐛 Bug Fixes
- Include tests that reproduce the bug
- Explain the fix in the commit message
- Ensure the fix doesn't break existing functionality

## 📝 License
By contributing, you agree that your contributions will be licensed under the same license as the project.

## 🙏 Recognition
Contributors will be acknowledged in the README.md file and release notes.

## ❓ Questions?
Open an issue with the "question" label or contact the maintainers.

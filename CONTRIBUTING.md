# Contributing to Entity

Thanks for considering contributing! This project started as a learning exercise, and I'm excited to see what the community can add to it.

## How Can I Contribute?

### Reporting Bugs

Found a bug? Please open an issue with:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Your environment (OS, Python version)
- Screenshots if relevant

### Suggesting Features

Have an idea? Open an issue with the `enhancement` label and describe:
- What problem it solves
- How it would work
- Why it would be useful for learning cybersecurity

### Code Contributions

#### Getting Started

1. **Fork the repo** and clone your fork
   ```bash
   git clone https://github.com/YOUR-USERNAME/Scavengers-Entity.git
   cd Scavengers-Entity
   ```

2. **Create a branch** for your feature
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Install dependencies**
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

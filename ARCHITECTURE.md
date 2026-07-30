# NetInsight Architecture

## Overview

NetInsight is a modular Python application designed to analyze nearby Wi-Fi networks. The project is built around independent modules, each with a single responsibility, making the code easier to maintain, test and extend.

The architecture prioritizes readability, scalability and long-term maintainability over short-term implementation speed.

---

## Design Principles

The project follows several software engineering principles:

- Single Responsibility Principle (SRP)
- Modular architecture
- High readability
- Scalability
- Maintainability
- Code reusability
- Cross-platform compatibility
- Type-safe development

---

## Project Structure

```
NetInsight/
├── main.py
├── scanner.py
├── network.py
├── analyzer.py
├── exporter.py
├── requirements.txt
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ROADMAP.md
│   └── CHANGELOG.md
│
└── tests/
```

---

## Module Description

### main.py

The application's entry point. It initializes the program, coordinates the execution flow and connects the different modules. Business logic should never be implemented here.

### scanner.py

Responsible for discovering nearby Wi-Fi networks and collecting information from the operating system. This module abstracts platform-specific implementations so that the rest of the application remains platform independent.

### network.py

Defines the data model used throughout the project. Every detected network is represented as an object, providing a consistent and structured way to exchange information between modules.

### analyzer.py

Processes collected network information to generate useful insights. It evaluates signal quality, detects channel congestion, compares available networks and prepares statistical information.

### exporter.py

Exports processed information into multiple formats such as CSV, JSON or PDF without modifying the original data.

---

## Module Interaction

The application has been designed so that every module performs one specific task.

The scanner discovers nearby networks and converts the raw operating system output into structured objects.

Those objects are then processed by the analyzer, which extracts useful information and computes metrics.

Finally, the processed data can either be displayed to the user or exported into different formats through the exporter module.

This separation keeps each component independent while making future maintenance significantly easier.

---

## Coding Standards

The project follows modern Python development practices.

- PEP 8
- Type hints
- Google-style docstrings
- Modular design
- Small reusable functions
- Clear naming conventions
- Comprehensive documentation

---

## Future Expansion

The architecture has been designed to support future features without requiring major structural changes.

Future modules may include a graphical user interface, persistent storage, configuration management, automatic updates, plugin support, real-time monitoring and cross-platform compatibility for Linux and macOS.

---

## Design Philosophy

NetInsight is intended to be a software engineering project rather than a collection of scripts.

Every architectural decision aims to improve readability, maintainability and scalability while keeping the codebase simple enough for contributors to understand and extend.
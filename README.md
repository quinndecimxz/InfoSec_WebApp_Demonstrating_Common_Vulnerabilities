# InfoSec WebApp – Demonstrating Common Vulnerabilities

## Design, Exploitation and Mitigation of Common Web Application Vulnerabilities in a Controlled Flask-Based Environment

This project focuses on the practical implementation and demonstration of common web application security vulnerabilities within a controlled environment.

It contains a minimal web application built using Python (Flask) and SQLite, incorporating:

- User authentication
- Role-based access control
- Basic data storage functionality

---

## Intentionally Vulnerable Application

An intentionally vulnerable version of the application is implemented to demonstrate the following security flaws:

- SQL Injection
- Broken Access Control (including IDOR – Insecure Direct Object Reference)
- Weak Password Hashing
- Session Management Weaknesses
- Improper Input Validation

Each vulnerability is practically exploited to demonstrate its real-world impact, including:

- Unauthorized data access
- Privilege escalation
- Authentication bypass

---

## Secure Application Implementation

After demonstrating the attacks, a secure version of the application is implemented using appropriate mitigation strategies, including:

- Parameterized SQL queries
- Secure password hashing (Bcrypt or equivalent)
- Proper role-based access control checks
- Secure session handling
- Input validation and sanitization

---

## Project Objective

This project compares the insecure and secure implementations to clearly demonstrate:

- How improper security design leads to exploitation
- How standard security practices effectively mitigate these risks

The focus of this project is on implementation, practical exploitation, and defense demonstration rather than purely theoretical analysis.

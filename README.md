# InfoSec_WebApp_Demonstrating_Common_Vulnerabilities
Design, Exploitation and Mitigation of Common Web Application Vulnerabilities in a Controlled Flask-Based Environment.

This project focuses on the practical implementation and demonstration of common web application security vulnerabilities within a controlled environment.It contains a minimal web application using Python (Flask) and SQLite, 
incorporating user authentication, role-based access control, and basic data storage functionality.

An intentionally vulnerable version of the application is implemented to demonstrate the following security flaws:
•	SQL Injection
•	Broken Access Control (including IDOR – Insecure Direct Object Reference)
•	Weak Password Hashing
•	Session Management Weaknesses
•	Improper Input Validation

Each vulnerability is shown to be practically exploited to demonstrate its impact, including unauthorized data access, privilege escalation, and authentication bypass.
After demonstrating the attacks, a secure version of the application is also implemented using appropriate mitigation strategies, including:
•	Parameterized SQL queries
•	Secure password hashing (Bcrypt or equivalent)
•	Proper role-based access control checks
•	Secure session handling
•	Input validation and sanitization
The project compares the insecure and secure implementations to clearly demonstrate how improper security design leads to exploitation, and how standard security practices mitigate these risks.
The focus of the project is on implementation, practical exploitation, and defense demonstration rather than theoretical analysis.

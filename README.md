# InfoSec WebApp – Demonstrating Common Vulnerabilities
##**Staging and Setup**


Run it from the project folder with the virtual environment Python, not the system Python.

Open a terminal in the project directory.
Activate the venv:
source .venv/bin/activate

Start the app:

If .venv does not exist yet, create it once with:
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python app.py # seeds DB automatically on first run

# [visit http://127.0.0.1:5000](http://127.0.0.1:5001 (for secure app , use port 5000 for vuln app))

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

This project compares the insecure and secure implementations to clearly demonstrate vulnerabilities and flaws:

- How improper security design leads to exploitation
- How standard security practices effectively mitigate these risks

The focus of this project is on implementation, practical exploitation, and defense demonstration rather than purely theoretical analysis.

##Components:
vulnerable/
├── requirements.txt          Flask==3.0.3 only
├── schema.sql                Table definitions + FK
├── database.py               DB init, seeding, md5_hash helper
├── app.py                    All routes — vulnerabilities fully commented
└── templates/
    ├── base.html             Nav, layout, minimal CSS
    ├── index.html            Home with seed credentials
    ├── login.html            [V1] SQLi target noted in template
    ├── register.html         [V3][V5] noted
    ├── dashboard.html        [V2] IDOR walkthrough hint
    ├── profile.html          [V2] Private notes exposed to all users
    ├── edit_profile.html     [V2][V5] no ownership check, no CSRF
    ├── admin.html            [V2] cookie-forgeable access
    └── search.html           [V1] UNION injection target noted

secure/
├── requirements.txt        Flask==3.0.3  +  bcrypt==4.1.3
├── schema.sql              Identical table structure
├── database.py             bcrypt hashing (rounds=12, auto-salt)
├── app.py                  All mitigations applied inline
└── templates/              (same 8 pages, identical UI)





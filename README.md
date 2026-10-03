# Secure Data Protection Web Application

A Flask and MySQL web application developed as part of the CodeAlpha Cyber Security Internship.

The project demonstrates how common web application security risks can be reduced by using secure database queries, password hashing, encryption, input validation, and session-based authentication.

## Features

- User registration and login
- SQL injection protection using parameterized SQL queries
- Password hashing using Werkzeug
- AES-256 encryption for sensitive user data
- Secure decryption after successful authentication
- Server-side input validation
- Session-based authentication
- HTTPOnly and SameSite session cookie settings
- Duplicate username and email protection
- HTML output escaping

## Technologies Used

- Python 3
- Flask
- MySQL
- mysql-connector-python
- Werkzeug
- Cryptography
- python-dotenv
- HTML
- CSS

## Security Implementation

### 1. SQL Injection Protection

The application uses parameterized SQL queries instead of directly inserting user input into SQL statements.

Example:

```python
cursor.execute(query, (username,))

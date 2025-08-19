# Flask Authentication System

A robust Flask-based authentication system with JWT support, role-based access control, and blog post management functionality.

## Features

- **Authentication & Authorization**
  - JWT-based authentication
  - Role-based access control (User, Manager, Admin)
  - Token refresh mechanism
  - Secure password hashing
  - Session management with cookies

- **Blog Post Management**
  - Create, Read, Update, Delete (CRUD) operations
  - Content management with rich text support
  - Author attribution
  - Timestamp tracking

- **User Interface**
  - Modern, responsive design with Bootstrap 5
  - Flash messages for user feedback
  - Secure forms with CSRF protection
  - Clean and intuitive navigation

## Tech Stack

- **Backend**
  - Python 3.x
  - Flask
  - SQLAlchemy
  - Flask-JWT-Extended
  - Flask-RESTful
  - Flask-Migrate
  - Flask-Bcrypt

- **Frontend**
  - Bootstrap 5
  - Jinja2 Templates
  - Font Awesome icons

- **Database**
  - SQLite (development)
  - PostgreSQL (production ready)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Flask-Auth
```

2. Install Pipenv if you haven't already:
```bash
pip install pipenv
```

3. Create virtual environment and install dependencies:
```bash
pipenv install
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize the database:
```bash
pipenv run flask db upgrade
```

## Development

Activate the Pipenv shell:
```bash
pipenv shell
```

Start the development server:
```bash
flask run
```

Access the application at `http://localhost:5000`

## Testing

Run the test suite:
```bash
pipenv run pytest
```

## Security Features

- Password hashing with Bcrypt
- JWT token-based authentication
- CSRF protection
- HTTP-only cookies
- Role-based access control
- Input validation and sanitization

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
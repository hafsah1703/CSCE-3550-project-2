# Project 2: Enhanced JWKS Server with SQLite

## Introduction

Hey there! Welcome to my Project 2: Enhanced JWKS Server with SQLite. This project builds upon the foundation of a JWKS (JSON Web Key Set) server by integrating SQLite as a database to securely store private keys. I've taken steps to fortify the server against SQL injection vulnerabilities and enhance its resilience.

## Project Overview

In this project, I've accomplished the following:

- **Integrated SQLite Database:** I utilized SQLite to create a single-file database (`totally_not_my_privateKeys.db`) for persisting private keys securely.
- **Enhanced Endpoints:** I modified the server's endpoints to read and serve private keys from the SQLite database.
- **Secure Database Interactions:** I ensured secure database interactions to prevent SQL injection attacks and maintain the integrity of the authentication system.

## Getting Started

To run the server and test suite:

1. **Clone the Repository:**

2. **Install Dependencies:**

3. **Run the Server:**

4. **Run Tests:**
## Project Structure

The project directory includes the following files and directories:

- `app.py`: Main server implementation.
- `test_server.py`: Test suite for the server.
- `totally_not_my_privateKeys.db`: SQLite database file for storing private keys.
- `README.md`: Project documentation and instructions.

## Usage

- **Endpoints:**
- `POST:/auth`: Endpoint for user authentication and JWT generation.
- `GET:/.well-known/jwks.json`: Endpoint for retrieving public keys in JWKS format.

- **SQLite Database:**
- Ensure that the `totally_not_my_privateKeys.db` file is accessible to the server for storing and retrieving private keys.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

If you have any questions or need further assistance, please don't hesitate to contact me at [hafsahiqbal@my.unt.edu](hafsahiqbal@my.unt.edu).

---


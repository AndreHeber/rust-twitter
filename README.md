# Twitter Clone

This is a simple Twitter clone built with Rust and Actix-web.

## Features

- User authentication (login and registration)
- Fetch user details by ID
- Secure password hashing with bcrypt
- JWT token generation for authentication

## Dependencies

- actix-web
- rusqlite
- r2d2
- r2d2_sqlite
- serde
- futures-util
- tokio
- tracing
- chrono
- env_logger
- jsonwebtoken
- bcrypt

## Setup

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/twitter-clone.git
    cd twitter-clone
    ```

2. Install Rust and Cargo if you haven't already:
    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

3. Build the project:
    ```sh
    cargo build
    ```

4. Run the server:
    ```sh
    cargo run
    ```

## Usage

- The server will start on `http://localhost:8080`.
- Use tools like Postman or curl to interact with the API.

## API Endpoints

- `GET /user/{id}`: Fetch user details by ID.
- `POST /auth`: Authenticate user and get JWT token.

## License

This project is licensed under the MIT License.
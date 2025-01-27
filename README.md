# LibraNet

## Overview
This project is a simplified Library Book Management System implemented as a basic client-server application using the socket interface. The system enables functionalities such as searching for books, managing borrowed books, and providing recommendations. This assignment introduces key networking concepts like client-server architecture, socket programming, and secure communication. 

The system is built with the following learning objectives:
- Understanding the basics of socket programming.
- Familiarizing with Linux system calls.
- Gaining a foundational understanding of network protocols and communication primitives.

## Features

### Functionalities
1. **Search**:
   - Search for books by title or author and return a list of matching results.
   - Retrieve detailed information (author and availability) for a specific book.

2. **Book Management**:
   - Check out a book (if available).
   - Return a checked-out book.
   - List all currently checked-out books.

3. **Recommendations**:
   - Get book recommendations based on a genre.
   - Rate a book on a scale of 1 to 5.

### Protocol Interaction
The client communicates with the server using a set of commands, adhering to the following specifications:

- **USER `<username>`**: Sends the username to the server. The server checks if the username is a known value:
    - If **YES**, it awaits the password.
    - If **NO**, it initiates the New User Registration Protocol (see below).
- **PASS `<password>`**: Sends the user’s password to the server. The server processes the password using the Authentication Protocol (see below).
- **SEARCH**: Enters search mode for book-related queries.
  - **FIND `<search_term>`**: Searches for books matching the term.
  - **DETAILS `<book_id>`**: Retrieves detailed information about a specific book.
- **MANAGE**: Enters book management mode.
  - **CHECKOUT `<book_id>`**: Checks out a book.
  - **RETURN `<book_id>`**: Returns a checked-out book.
  - **LIST**: Lists all available books for checkout.
- **RECOMMEND**: Enters recommendation mode.
  - **GET `<genre>`**: Retrieves book recommendations based on genre.
  - **RATE `<book_id> <rating>`**: Rates a book.
- **BYE**: Closes the client-server connection gracefully.

### Response Codes
The server uses numeric reply codes to indicate the status of client requests:
- **200**: General success.
- **210/220/230**: Mode-switch success (Search/Manage/Recommend).
- **250 `<data>`**: Command success with requested data.
- **304**: No content available for the request.
- **400/403/404**: Errors (bad request, forbidden, or not found).
- **500**: Internal server error.

## Technical Specifications

### Server Requirements
- Capable of accepting TCP client requests.
- Supports concurrency to handle multiple simultaneous client connections using multithreading or `fork()`.

### Secure Communication
- Implements TLS 1.3 for secure client-server communication using OpenSSL.
- Generates self-signed certificates (`p3server.key` and `p3server.crt`) for encryption.

### Secure Login System
- Replaces the HELO command with USER → PASS for authentication.
- Generates a secure 5-character password with interleaved salting.
- Encrypts passwords using a pre-shared key (`F24447TG`).

### Password Management
- Uses SHA-512 for hashing salted passwords.
- Stores credentials in a hidden `.book_shadow` file with the format: `username:salt:salted_password_hash`.

### Network Setup
- The client-server connection is TCP-based.
- Clients gracefully exit using the BYE command.

### Testing & Deployment
- Tested with at least two simultaneous client connections on Linux.
- Developed and debugged on Linux servers using `vim`, command-line tools, and network analyzers like Wireshark and `tshark`.

## Usage

### Compilation
To compile the server and client, run:
```bash
make
```
### Configuration
- **Server Configuration (`server.conf`)**:
  ```plaintext
  TCP_PORT=[enter a relevant port]
  HEARTBEAT_INTERVAL=[enter the frequency of heartbeat]
  STATS_INTERVAL=[enter the frequency of statistics]
  ```
- **Client Configuration (`client.conf`)**:
  ```plaintext
  SERVER_IP=[enter the server's IP address]
  SERVER_PORT=[enter the server's port]
  ```
### Usage
Run the following command to compile the server and client
```plaintext
make
```
### Running the server
```plaintext
./server server.conf
```
### Running the client
```plaintext
./client client.conf
```
## Generating a secured key for both client and server
Generate self-signed certificates for testing using OpenSSL’s command-line tools. Ensure your generated files are named p3server.key and p3server.crt
## Development Environment
This project was developed and tested on a Linux server using vim and related utilities. Wireshark and tshark were used to validate secure communication and debug network interactions.

## Future Enhancements
- Adding server-to-server communication for distributed book management.
- Enhancing the client with a graphical interface.
- Implementing a database for persistent storage of user and book data.


# Authentication, Authorization, Accounting (AAA)

The Authentication Microservice is a secure and versatile identity management system built using TypeScript and NestJS. It provides robust authentication features, supporting various authentication methods such as SMS OTP, password, Google Authenticator for two-factor authentication (2FA), and Metamask wallet connect. The service integrates with PostgreSQL as the primary database for user information, Redis for caching and bloomfilter, RabbitMQ for asynchronous communication, and Minio for storing multiple avatars.

## Table of Contents

- [Dependencies](#dependencies)
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Contributing](#contributing)
- [License](#license)

## Dependencies

All the dependecies are covered in docker compose file.

- NodeJS
- Postgresql
- Redis
- RabbitMQ

## Installation

In case where you host all dependecies localy, you can provide connection parameters and configuration in .env file. A boilerplate of needed parameters is available in sample.env.

```
$ PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true npm install

$ npm run build
```

## Usage

Guidelines and examples on how to use the project. Include any relevant command line options or configurations.

Provide necessary environment variables in a .env file. (look .env-sample)
### Development

```
$ npm run start:dev
```

### Production

```
$ npm run start
```

### Docker

Start infrastructure needed for app first

```
$ docker-compose up -t .infra.dockeer-compose.yml -d
```

```
$ docker-compose up -d
```

## Features

List the key features and functionality of the service.

    Authentication Methods:
        SMS OTP: Users can authenticate using one-time passwords sent via SMS.
        Password: Traditional username and password authentication.
        Google Authenticator: Two-factor authentication using time-based one-time passwords (TOTP).
        Metamask Wallet Connect: Secure authentication through the Metamask wallet.

    Token Generation:
        The service generates JSON Web Tokens (JWT) for secure and stateless authentication.
        It also can work with Kraken Gateway to sign Tokens.

    Two-Factor Authentication (2FA):
        Supports Google Authenticator for an additional layer of security.

    Access Control Lists (ACL):
        Implements an ACL system for managing user permissions, roles and access levels.

    Asynchronous Communication:
        RabbitMQ for facilitates interconnections and asynchronous APIs for improved responsiveness and scalability.

    Avatar Management:
        Capable of storing multiple avatars for users in Minio, providing flexibility in profile customization.

    Database Integration:
        PostgreSQL: Serves as the primary database for storing user information securely.

    Caching and Bloomfilter:
        Redis: Used as a secondary database for caching and bloomfilter implementation, improving performance and reducing redundant queries.

## Conclusion

The Authentication Microservice provides a secure, scalable, and extensible solution for identity management. By incorporating various authentication methods, asynchronous communication, and database technologies, it meets the requirements of modern applications while prioritizing security and performance.

## License

```
MIT License
```

## Contact

contact us for questions or feedback related to the project.

- Email: Valizadearshia8@gmail.com

Feel free to customize this service to fit the specific needs of your project.

## Set up project using Docker compose

- Install Docker: [https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)
- Install Docker Compose: [https://docs.docker.com/compose/install/](https://docs.docker.com/compose/install/)
- Clone repository
  ```bash
  git clone https://github.com/BeyondTrust/ps-integration-library.git
  ```
- Edit .env file, including needed data.
- Build the image using docker compose
  ```bash
  docker-compose build
  ```
- Run the image using docker compose
  ```bash
  docker-compose up
  ```
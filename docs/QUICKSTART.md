# CloudSentinel Quick Start

This is the shortest path from a fresh machine to a working local CloudSentinel dashboard.

## Requirements

- Git
- Docker Engine
- Docker Compose v2
- OpenSSL

You do not need AWS credentials to start the dashboard. You need an AWS account and configured IAM role only when you want to run a real AWS scan.

## 1. Clone

~~~bash
git clone https://github.com/pentest-sourav/cloudsentinel.git
cd cloudsentinel
~~~

## 2. Configure .env

~~~bash
cp .env.example .env
openssl rand -hex 32
~~~

Put the generated value into JWT_SECRET_KEY and set a strong POSTGRES_PASSWORD in .env.

Keep .env local. Never commit real passwords, JWT secrets, AWS credentials, or production backup credentials.

## 3. Start

~~~bash
docker compose up -d --build
docker compose exec api alembic upgrade head
docker compose ps
~~~

## 4. Verify

~~~bash
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8000/ready
~~~

Open http://localhost:8000.

The API image serves the bundled web console. No separate frontend server is required for this normal Docker setup.

## 5. Create an account

In the web console select **Create account**, then enter:

- full name;
- organization;
- email;
- password.

## 6. Connect AWS

Open **Cloud Accounts → Add AWS Account**.

Enter the AWS account ID, IAM Role ARN, account name and region. Save the account.

CloudSentinel shows the current principal ARN, generated External ID and trust-policy template. Configure the customer IAM role, then return and select **Test Connection**.

See AWS_ONBOARDING.md for the complete procedure.

## 7. Run a scan

Open **Overview → Run AWS Security Scan**, select the connected AWS account and start the scan.

The worker processes the queued job. Findings appear in **Findings** when the scan completes.

## Troubleshooting

Containers:

~~~bash
docker compose ps
docker compose logs --tail=200 api
docker compose logs --tail=200 worker
docker compose logs --tail=200 postgres
docker compose logs --tail=200 redis
~~~

Migration:

~~~bash
docker compose exec api alembic upgrade head
~~~

Reset local data:

~~~bash
docker compose down -v
docker compose up -d --build
docker compose exec api alembic upgrade head
~~~

Stop:

~~~bash
docker compose down
~~~

## Tests

~~~bash
python -m compileall -q backend engine scanner reporting
pytest -q
git diff --check
~~~

## Local vs production

The root Compose file is for development/testing. It publishes the API directly and is not a hardened Internet-facing deployment.

For a controlled deployment use deploy/docker-compose.prod.yml and read docs/DEPLOYMENT.md and docs/OPERATIONS_RUNBOOK.md.

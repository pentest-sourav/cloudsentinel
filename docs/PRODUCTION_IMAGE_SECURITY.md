# Production image security contract

The production container intentionally excludes the repository test suite.

Tests remain available to CI from the checked-out source tree, while the runtime
image contains only application code and files required to start the API/worker
and run database migrations. This reduces image size and removes test-only code
and fixtures from the production attack surface.

Do not add test directories to the runtime image unless a production execution
path explicitly requires them.

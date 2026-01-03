# Durable Functions vs Step Functions

A comparison of Durable Functions and AWS Step Functions for managing asynchronous workflows with task tokens.

## Architecture

![Architecture](./architecture.png)

## Setup

```bash
bun install
```

## Commands

```bash
# Build / Type check
bun run build

# Run all tests
bun test

# Run single test
bun test path/to/file.test.ts

# Deploy infrastructure
npx cdk deploy

# Synthesize CloudFormation template
npx cdk synth

# Destroy infrastructure
npx cdk destroy
```

## Project Structure

- `lambdas/shared/` - Shared business logic and types
- `lambdas/step-functions/` - Step Functions specific handlers
- `lambdas/durable/` - Durable Functions implementation
- `infra/stack.ts` - AWS CDK v2 infrastructure definition

## Workflow

![Workflow](./flow.png)

The demo implements a verification code workflow:
1. Send email with a 6-digit code
2. Wait for user input (max 15 minutes)
3. Verify the code matches

Both implementations use DynamoDB for state management and SES for email delivery.

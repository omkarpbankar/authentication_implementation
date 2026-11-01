# App 4 Setup: Connect Your Own AWS Account

This app has been tested against a simulated provider. These steps connect it to real Amazon Cognito. The AWS CLI on this machine currently has no valid credentials, so `aws configure` comes first.

## Before you start: protect yourself from cost

1. Create an AWS Budget with an email alert.
2. Stay on the Essentials plan.
3. Use email, not SMS.
4. Check the [pricing page](https://aws.amazon.com/cognito/pricing/) before using machine-to-machine access, as it may be billed separately.
5. Delete the stack when you finish.

## 1. Deploy

```powershell
aws configure
aws cloudformation deploy `
  --template-file infra/cognito.yaml `
  --stack-name auth-course-app4 `
  --capabilities CAPABILITY_IAM `
  --parameter-overrides DomainPrefix=app4-yourname
aws cloudformation describe-stacks --stack-name auth-course-app4 --query "Stacks[0].Outputs"
```

## 2. Get the client secret

```powershell
aws cognito-idp describe-user-pool-client --user-pool-id POOL_ID --client-id CLIENT_ID --query "UserPoolClient.ClientSecret"
```

## 3. Configure the app

Create `apps/app4_cognito/.env`, which Git ignores:

```
APP4_REGION=your-region
APP4_USER_POOL_ID=from-outputs
APP4_CLIENT_ID=from-outputs
APP4_CLIENT_SECRET=from-step-2
APP4_M2M_CLIENT_ID=from-outputs
APP4_DOMAIN=from-outputs
```

## 4. Run it

```powershell
uv run uvicorn apps.app4_cognito.main:app --port 8004
```

Open http://localhost:8004 and sign up with an email you can read.

## 5. What to try

- Decode an ID token and an access token, and compare `aud`, `client_id`, and `token_use`.
- Add your user to the `member` group, sign in again, and call `/api/members`.
- See the custom `plan` claim added by the Lambda.
- Call the API with your ID token, and confirm it gets a 401.
- Get a machine token using the client credentials flow, and call `/api/orders`.

## 6. Tear down

```powershell
aws cloudformation delete-stack --stack-name auth-course-app4
```

Then check the AWS console, and your bill the next day.

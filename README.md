# S3 Lambda Authorizer Example

A modernised AWS Lambda JWT authorizer that protects API Gateway endpoints and controls access to S3 resources. The authorizer validates bearer tokens, verifies optional audience and issuer claims, and checks whether the caller belongs to one of the allowed roles.

## Features

- ✅ JWT validation with [`jsonwebtoken`](https://www.npmjs.com/package/jsonwebtoken) including audience and issuer checks.
- ✅ Configurable role-based access using environment variables.
- ✅ Safe policy document generation with request context metadata.
- ✅ [OpenAPI 3.0](openapi.yaml) specification describing a sample protected endpoint.

## Getting Started

1. Install dependencies in your deployment package:
   ```bash
   npm install jsonwebtoken
   ```
2. Copy the `index.js` file into your Lambda source bundle.
3. Provide the environment variables listed below (a `.env` template is available in [.env.example](.env.example)).
4. Deploy the Lambda function and configure it as a JWT authorizer in API Gateway.

### Environment Variables

| Name | Required | Description |
| --- | --- | --- |
| `JWT_SECRET` | Yes | Symmetric key used to verify incoming JWT tokens. |
| `JWT_AUDIENCE` | No | Comma-separated list of valid audiences. Leave empty to accept any audience. |
| `JWT_ISSUER` | No | Expected issuer (`iss`) value. Leave empty to skip issuer validation. |
| `ALLOWED_ROLES` | No | Comma-separated list of role names that are permitted to access the API. Defaults to `admin`. |
| `REQUIRE_ROLE` | No | Set to `false` to allow tokens without role information. Defaults to `true`. |
| `AWS_REGION` | No | Region where the API Gateway stage and Lambda authorizer are deployed. Requests from other regions are rejected when set. |
| `AWS_ACCOUNT_ID` | No | AWS account identifier that owns the API Gateway deployment. Requests from other accounts are rejected when set. |
| `S3_BUCKET_NAME` | No | Private S3 bucket that the downstream integration should expose to authorized callers. Added to the request context. |
| `S3_PREFIX` | No | Optional prefix that narrows the accessible portion of the bucket. Added to the request context. |

### Sample `.env` configuration

See [.env.example](.env.example) for a ready-to-copy template.

### Testing the Authorizer Locally

You can invoke the authorizer locally by simulating the API Gateway event:

```bash
node <<'NODE'
const { handler } = require('./index');

async function main() {
  const event = {
    type: 'TOKEN',
    methodArn: 'arn:aws:execute-api:us-east-1:111122223333:abcdefghij/dev/GET/protected/files',
    authorizationToken: 'Bearer <your-jwt-here>'
  };

  const response = await handler(event);
  console.log(response);
}

main().catch((error) => {
  console.error('Invocation failed:', error.message);
});
NODE
```

Replace `<your-jwt-here>` with a token signed using the `JWT_SECRET` value. The authorizer validates that the invocation ARN
matches the configured `AWS_REGION`/`AWS_ACCOUNT_ID` (when provided) and injects the bucket details (`S3_BUCKET_NAME` and
`S3_PREFIX`) into the API Gateway request context for downstream services.

## OpenAPI Documentation

The [`openapi.yaml`](openapi.yaml) file documents a sample `GET /protected/files` endpoint guarded by this Lambda authorizer. Import it into API Gateway or share it with API consumers to communicate the contract and required security scheme.

## Deployment Tips

- Ensure that the Lambda execution role has permission to assume the IAM role required to access your S3 bucket and other downstream services.
- Keep the `JWT_SECRET` in AWS Secrets Manager or Parameter Store and reference it using environment variables or Lambda extensions.
- Configure caching on the API Gateway authorizer to reduce latency for repeated invocations with the same token.

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

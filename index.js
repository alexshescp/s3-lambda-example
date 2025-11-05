'use strict';

const jwt = require('jsonwebtoken');

const DEFAULT_ALLOWED_ROLES = ['admin'];
const CLAIM_ROLE_KEYS = ['roles', 'role', 'cognito:groups', 'scope'];

/**
 * Lambda authorizer entrypoint.
 * Validates a JWT token and returns an IAM policy that allows the invocation
 * when the decoded token satisfies the configured requirements.
 *
 * Environment variables:
 * - JWT_SECRET (required): symmetric key used to validate incoming JWT tokens.
 * - JWT_AUDIENCE (optional): comma separated list of allowed audiences.
 * - JWT_ISSUER (optional): expected issuer claim.
 * - ALLOWED_ROLES (optional): comma separated list of roles that are permitted to
 *   access the API. Defaults to `admin` if not provided.
 * - REQUIRE_ROLE (optional): when set to `false` the authorizer allows tokens without role information. Defaults to `true`.
 */
exports.handler = async function handler(event) {
  const methodArn = event.methodArn;
  console.log('Authorizing invocation of %s', methodArn);

  enforceAwsScope(methodArn);

  const token = extractBearerToken(event.authorizationToken);
  if (!token) {
    console.warn('Missing bearer token in the request');
    throwUnauthorized();
  }

  const verifyOptions = buildVerifyOptions();
  let decoded;
  try {
    decoded = jwt.verify(token, getSecret(), verifyOptions);
  } catch (err) {
    console.error('Token verification failed', err);
    throwUnauthorized();
  }

  const principalId = decoded.sub || decoded.username || 'anonymous';
  const isAllowed = isRoleAllowed(decoded);

  if (!isAllowed) {
    console.warn('Token for principal %s does not satisfy role requirements', principalId);
    throwUnauthorized();
  }

  const policy = buildIamPolicy(principalId, 'Allow', methodArn, {
    tokenIssuedAt: decoded.iat,
    tokenExpiresAt: decoded.exp,
    roles: JSON.stringify(getRoles(decoded)),
    ...buildAwsContext(),
  });

  return policy;
};

function buildVerifyOptions() {
  const options = {};
  const audience = getList(process.env.JWT_AUDIENCE);
  if (audience.length > 0) {
    options.audience = audience;
  }
  if (process.env.JWT_ISSUER) {
    options.issuer = process.env.JWT_ISSUER;
  }
  options.complete = false;
  return options;
}

function getSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    console.error('JWT_SECRET environment variable is not configured');
    throw new Error('Server configuration error');
  }
  return secret;
}

function enforceAwsScope(methodArn) {
  if (!methodArn || typeof methodArn !== 'string') {
    return;
  }

  const arnSegments = methodArn.split(':');
  if (arnSegments.length < 6) {
    console.warn('Unexpected method ARN format: %s', methodArn);
    return;
  }

  const region = arnSegments[3];
  const accountId = arnSegments[4];

  if (process.env.AWS_REGION && process.env.AWS_REGION !== region) {
    console.warn('Invocation region %s does not match configured AWS_REGION %s', region, process.env.AWS_REGION);
    throwUnauthorized();
  }

  if (process.env.AWS_ACCOUNT_ID && process.env.AWS_ACCOUNT_ID !== accountId) {
    console.warn('Invocation account %s does not match configured AWS_ACCOUNT_ID %s', accountId, process.env.AWS_ACCOUNT_ID);
    throwUnauthorized();
  }
}

function extractBearerToken(authHeader) {
  if (!authHeader || typeof authHeader !== 'string') {
    return undefined;
  }
  const parts = authHeader.trim().split(/\s+/);
  if (parts.length === 1) {
    return parts[0];
  }
  if (parts.length === 2 && /^bearer$/i.test(parts[0])) {
    return parts[1];
  }
  return undefined;
}

function isRoleAllowed(decodedToken) {
  const allowedRoles = getAllowedRoles();
  const requireRole = process.env.REQUIRE_ROLE !== 'false';
  if (allowedRoles.length === 0) {
    return true;
  }
  const tokenRoles = getRoles(decodedToken);
  if (tokenRoles.length === 0) {
    return !requireRole;
  }
  return tokenRoles.some((role) => allowedRoles.includes(role));
}

function getAllowedRoles() {
  const configured = getList(process.env.ALLOWED_ROLES);
  return configured.length > 0 ? configured : DEFAULT_ALLOWED_ROLES;
}

function getRoles(decodedToken) {
  for (const key of CLAIM_ROLE_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(decodedToken, key)) {
      continue;
    }

    const value = decodedToken[key];
    if (Array.isArray(value)) {
      return value.map(String);
    }
    if (typeof value === 'string') {
      if (key === 'scope') {
        return value.split(' ').filter(Boolean);
      }
      if (value.includes(',')) {
        return value.split(',').map((entry) => entry.trim()).filter(Boolean);
      }
      return [value];
    }
  }
  return [];
}

function getList(value) {
  if (!value || typeof value !== 'string') {
    return [];
  }
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function buildIamPolicy(principalId, effect, resource, context = {}) {
  const response = {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: effect,
          Resource: resource,
        },
      ],
    },
  };

  const sanitizedContext = {};
  for (const [key, value] of Object.entries(context)) {
    if (value === undefined || value === null) {
      continue;
    }
    sanitizedContext[key] = String(value).slice(0, 1000);
  }

  if (Object.keys(sanitizedContext).length > 0) {
    response.context = sanitizedContext;
  }

  return response;
}

function buildAwsContext() {
  const context = {};
  if (process.env.AWS_REGION) {
    context.awsRegion = process.env.AWS_REGION;
  }
  if (process.env.AWS_ACCOUNT_ID) {
    context.awsAccountId = process.env.AWS_ACCOUNT_ID;
  }
  if (process.env.S3_BUCKET_NAME) {
    context.s3Bucket = process.env.S3_BUCKET_NAME;
  }
  if (process.env.S3_PREFIX) {
    context.s3Prefix = process.env.S3_PREFIX;
  }
  return context;
}

function throwUnauthorized() {
  const error = new Error('Unauthorized');
  error.name = 'Unauthorized';
  throw error;
}

# faas-middleware
HTTP middleware for OpenFaaS

## Components
### Concurrency Limiter
`concurrency-limiter` is a tool that can be used to limit the number of active inflight requests for a given http request handler.

### JWT Authenticator middleware

The JWT authenticator middleware can be used to authorize http request for functions with IAM for OpenFaaS. The middleware verifies the permissions in the `function` claim of an OpenFaaS function access token that is set in the `Authorization` header of the request.

The middleware is configured through env variables:

| Name                 | Description             |
|------------------------|--------------|
| `jwt_auth_debug`                 | Print out debug messages from the JWT authentication process. |
| `jwt_auth_local`                 | When set to `true`, the watchdog will attempt to validate the JWT token using a port-forwarded or local gateway running at `http://127.0.0.1:8000` instead of attempting to reach it via an in-cluster service. |
| `OPNEFAAS_NAME` | Name if the authenticated function |
| `OPENFAAS_NAMESPACE` | Name if the namespace for the authenticated function. If this variable is not set the middleware will try to read the namespace from `/var/run/secrets/kubernetes.io/serviceaccount/namespace` | 


This middleware is used by the [classic-watchdog](https://github.com/openfaas/classic-watchdog) and [of-watchdog](https://github.com/openfaas/of-watchdog)
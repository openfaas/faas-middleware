# faas-middleware
HTTP middleware for OpenFaaS

## Components
### Concurrency Limiter
`concurrency-limiter` is a tool that can be used to limit the number of active inflight requests for a given http request handler.

### JWT Authenticator middleware

The JWT authenticator middleware can be used to authorize http request for functions with IAM for OpenFaaS. The middleware verifies the permissions in the `function` claim of an OpenFaaS function access token that is set in the `Authorization` header of the request.

This middleware is used by the [classic-watchdog](https://github.com/openfaas/classic-watchdog) and [of-watchdog](https://github.com/openfaas/of-watchdog)
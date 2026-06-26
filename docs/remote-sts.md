# Remote STS

Remote STS is a future team-mode architecture and is out of scope for the Local MVP. The Local MVP has no hosted EnvVault service, no central profile registry, and no automatic remote trust anchor.

## Local MVP Trust

Local process JWTs and browser bootstrap JWTs are signed by local issuer material. A backend that trusts them must explicitly register the local issuer and JWKS, or load the exported JWKS for local development.

Do not configure a production service to trust arbitrary developer-local JWKS files. Local keys are scoped to one OS user and one machine.

## Future Centralized STS

A future centralized STS can exchange a developer login for short-lived credentials under organization policy. Expected building blocks include OIDC login, authorization code with PKCE or device flow, central profile policy, team audit, rate limiting, and CI federation.

The intended UX is that local and remote modes keep the same `envvault://` reference shape while changing the issuer backend and trust anchor.

## Migration Notes

Until remote STS exists, backends should validate issuer, signature, expiry, scope, resource, and purpose against an explicitly configured local JWKS. When central STS is introduced, backends should switch to the centralized JWKS and remove ad hoc local issuer trust.

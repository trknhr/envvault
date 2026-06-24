# Release Gate

This page maps the Local MVP P0 acceptance IDs to the tests and commands that
must pass before a v0.1 release candidate is treated as releasable.

Run the full gate:

```bash
go test ./...
go vet ./...
go test -race ./...
go test ./test/acceptance -run TestRelease -count=1
go run ./cmd/credlease-ci secret-scan .
```

The GitHub Actions workflow runs the same gate on the configured Ubuntu and
macOS Tier 1 runners. Package publication is separate and requires explicit
maintainer action.

## P0 Coverage Map

| ID | Evidence |
|---|---|
| AT-INIT-001 | `test/acceptance.TestATINIT001And002InitCreatesLocalStateAndIsIdempotent` verifies CLI init creates config, SQLite, JWKS, managed runtime artifact, and keyring secrets; `internal/bootstrap.TestInitializerCreatesConfigRuntimeSQLiteJWKSAndKeyringSecrets`; `internal/bootstrap.TestInitializerPreparesRuntimeWithStoredSecretsBeforeJWKS`; `internal/cli.TestRunInitCallsInitializer` |
| AT-INIT-002 | `test/acceptance.TestATINIT001And002InitCreatesLocalStateAndIsIdempotent` verifies rerunning CLI init does not reinstall, refetch JWKS, regenerate secrets, rotate keys, or destroy state; `internal/bootstrap.TestInitializerIsIdempotentAndDoesNotRotateExistingSecrets` |
| AT-SEC-001 | `test/acceptance.TestATSEC001LocalFlowDoesNotPersistRawLongLivedSecretMarkers`; `cmd/credlease-ci` secret scan |
| AT-PROFILE-001 | `test/acceptance.TestATPROFILE001ProfileAddCreatesSeparateParentKeysWithBoundedTalosScopes` verifies CLI profile creation, separate keyring parent keys, Talos parent-key metadata, and profile-bounded parent scopes; `internal/profilemgr.TestAddProcessProfileIssuesParentKeyStoresSecretInKeyringOnly`; `internal/profilemgr.TestAddBrowserSessionProfileIssuesParentKeyAndStoresPolicy` |
| AT-REF-001 | `test/acceptance.TestExecResolvesReferenceAndDoesNotPassParentAuthority` verifies `.env` reference resolution, file preservation, and the signed process JWT injected into the child |
| AT-REF-002 | `test/acceptance.TestExecUnknownProfileFailsClosedWithoutParentFallback`; `internal/config.TestLoadProfileRejectsUnknownProfileFailClosed` |
| AT-REF-003 | `test/acceptance.TestExecRejectsQueryReferenceBeforeStartingChild`; `internal/envref` reference parser tests |
| AT-EXEC-001 | `test/acceptance.TestExecResolvesReferenceAndDoesNotPassParentAuthority`; `internal/process.TestBuildEnvWorksWithLocalIssuerAndDropsCredleaseAuthorityEnv` |
| AT-EXEC-002 | `test/acceptance.TestExecStartsChildAfterOnDemandRuntimeStops` verifies child start after on-demand runtime shutdown and closed loopback port; `internal/issuer/talosruntime.TestClientDerivesJWTThroughRuntimeAndStopsBeforeReturning`; `internal/runtime/talos.TestRuntimeStartsOnLoopbackRandomPortAndStopsCleanly` |
| AT-EXEC-003 | `test/acceptance.TestExecPropagatesChildExitCode` |
| AT-EXEC-004 | `test/acceptance.TestExecForwardsSIGINTToChild`; `internal/cli.TestRunExecProvidesSignalChannelToRunner` |
| AT-JWT-001 | `test/acceptance.TestSampleBackendEnforcesProcessJWTTTLScopesResourcesAndJWKS`; `pkg/verifier` expiry tests |
| AT-JWT-002 | `test/acceptance.TestSampleBackendEnforcesProcessJWTTTLScopesResourcesAndJWKS`; `examples/backend-go.TestProcessJWTAuthorizesReadEndpointAndRejectsMissingScope` |
| AT-JWT-003 | `test/acceptance.TestSampleBackendEnforcesProcessJWTTTLScopesResourcesAndJWKS`; `pkg/verifier` resource tests |
| AT-JWKS-001 | `test/acceptance.TestSampleBackendEnforcesProcessJWTTTLScopesResourcesAndJWKS`; `internal/cli` JWKS export tests |
| AT-LOG-001 | `test/acceptance.TestATLOG001SecretRedactionAcrossIssueFailuresAndCrashOutput` verifies successful issue, Talos HTTP 500, and managed-runtime crash output do not leak JWTs, parent keys, Authorization headers, HMAC/signing canaries, or crash-output canaries across stdout, stderr, and audit logs; `internal/runtime/talos.TestRuntimeStartFailureKillsProcessAndRedactsOutput`; `internal/issuer/talos.TestTalosHTTPErrorDoesNotEchoSecretOrBody`; audit and browser redaction tests |
| AT-CRASH-001 | `test/acceptance.TestATCRASH001DoctorRepairCleansStaleRuntimeArtifactsAndChecksDBs`; `internal/doctor` stale-lock and temp-file repair tests |
| AT-CONCURRENCY-001 | `test/acceptance.TestATCONCURRENCY001ConcurrentTokenIssuance`; `go test -race ./...` |
| AT-BROWSER-001 | `test/acceptance.TestOpenCreatesBrowserSessionThroughSampleBackend`; `examples/backend-go.TestBrowserSessionExchangeAndCompleteSetSecureCookie` |
| AT-BROWSER-002 | `test/acceptance.TestOpenCreatesBrowserSessionThroughSampleBackend`; `pkg/browsersession.TestExchangeUsesAuthorizationBearerAndReturnsFixedCompleteURL` |
| AT-BROWSER-003 | `test/acceptance.TestOpenCreatesBrowserSessionThroughSampleBackend`; `pkg/browsersession.TestCompleteRejectsReusedCodeWithGenericError`; SQLite store single-use tests |
| AT-BROWSER-004 | `test/acceptance.TestATBROWSER004ExpiredLoginCodeDoesNotCreateSessionThroughSampleBackend` verifies the sample backend rejects an expired 2-second login code without creating a session; `pkg/browsersession` login-code expiration tests; SQLite store expiration tests |
| AT-BROWSER-005 | `test/acceptance.TestATBROWSER005BootstrapJWTReplayRejectedThroughSampleBackend` verifies replaying the same bootstrap JWT/session ID against the sample backend only issues the first code and rejects the replay; `pkg/browsersession.TestExchangeRejectsBootstrapSessionReplay`; SQLite replay persistence tests |
| AT-BROWSER-006 | `test/acceptance.TestATBROWSER006LaunchURLAllowlistRejectsEvilBackendResponse` verifies `credlease open` rejects a backend-provided evil launch URL before starting the browser and without leaking the code or JWT; `internal/browser.TestOpenRejectsBackendLaunchURLOutsideProfilePolicy`; profile launch URL validation tests |
| AT-BROWSER-007 | `test/acceptance.TestATBROWSER007ProductionHTTPSCookieSecurityAttributesThroughSampleBackend` verifies the sample backend over HTTPS sets `HttpOnly`, `Secure`, and `SameSite=Lax` session cookies; `examples/backend-go.TestBrowserSessionExchangeAndCompleteSetSecureCookie`; `pkg/browsersession.TestCompleteConsumesCodeSetsCookieAndRedirectsToFixedPostLoginURL` |
| AT-BROWSER-008 | `test/acceptance.TestOpenCreatesBrowserSessionThroughSampleBackend`; `examples/backend-go.TestBrowserSessionExchangeAndCompleteSetSecureCookie`; `pkg/browsersession.TestCompleteConsumesCodeSetsCookieAndRedirectsToFixedPostLoginURL` |
| AT-KEYRING-001 | `test/acceptance.TestATKEYRING001InitFailsClosedWhenKeyringUnavailable`; keyring and bootstrap fail-closed tests |
| AT-RESET-001 | `test/acceptance.TestATRESET001ResetRequiresConfirmationDeletesCredleaseStateAndPreservesRepository` verifies CLI confirmation, Credlease-owned file/cache deletion, keyring entry deletion, and repository file preservation; `internal/reset.TestPlannerResetDeletesCredleaseFilesAndKnownKeyringEntries`; `internal/cli` reset command tests |

## Open Release Notes

- Parent and signing key rotation is not exposed in v0.1. The current release
  gate instead enforces that re-running init does not silently rotate or destroy
  existing local secrets. Rotation policy depends on the unresolved parent-key
  expiry and JWKS overlap decisions in the implementation spec.
- System-installed Talos is not a v0.1 user path. The supported path is the
  managed runtime pinned by the embedded release manifest and verified by
  artifact digest.

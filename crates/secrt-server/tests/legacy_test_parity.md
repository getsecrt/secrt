# Legacy Test Parity (Go -> Rust)

This file tracks parity from legacy Go tests in `legacy/secrt-server` to the Rust implementation.

Status values:
- `PORTED`: Feasible legacy behavior is covered by Rust tests.
- `NOT_FEASIBLE_COMPENSATED`: Legacy test shape cannot be ported 1:1 due architecture/runtime changes; compensating Rust tests are listed.

Unresolved feasible entries: none.

## `legacy/secrt-server/internal/api/server_test.go`
- `PORTED` `TestPublicCreateAndClaimFlow` -> `crates/secrt-server/tests/api_behavior.rs` (`public_create_and_claim_flow`)
- `PORTED` `TestAuthedCreateRequiresAPIKey` -> `crates/secrt-server/tests/api_behavior.rs` (`authed_create_requires_api_key`)
- `PORTED` `TestInfoUnauthenticated` -> `crates/secrt-server/tests/api_behavior.rs` (`info_endpoint_authenticated_and_cache_header`)
- `PORTED` `TestInfoAuthenticated` -> `crates/secrt-server/tests/api_behavior.rs` (`info_endpoint_authenticated_and_cache_header`)
- `PORTED` `TestInfoInvalidKey` -> `crates/secrt-server/tests/api_error_paths.rs` (`info_with_invalid_api_key_returns_authenticated_false`)
- `PORTED` `TestInfoCacheHeader` -> `crates/secrt-server/tests/api_behavior.rs` (`info_endpoint_authenticated_and_cache_header`)

## `legacy/secrt-server/internal/api/server_more_test.go`
- `PORTED` `TestHealthz` -> `crates/secrt-server/tests/api_behavior.rs` (`healthz_route_returns_ok_payload`)
- `PORTED` `TestCreateSecret_ValidationAndRateLimit` -> `crates/secrt-server/tests/api_behavior.rs` (`create_validation_and_content_type_errors`), `crates/secrt-server/tests/api_quota.rs` (`public_rate_limit_burst`)
- `PORTED` `TestCreateSecret_InternalErrors` -> `crates/secrt-server/tests/api_error_paths.rs` (`create_usage_error_is_500`, `create_store_error_is_500`)
- `NOT_FEASIBLE_COMPENSATED` `TestCreateSecret_IDGenerationError`
  - Rationale: Legacy Go injected RNG/read failures directly into ID generation; Rust uses `ring::rand::SystemRandom` without injectable failure hook in production path.
  - Compensating tests: `crates/secrt-server/tests/api_error_paths.rs` (`create_duplicate_id_exhaustion_is_500`), `crates/secrt-server/src/domain/secret_rules.rs` unit coverage (`id_generation`)
- `PORTED` `TestCreateSecret_IDCollisionRetry` -> `crates/secrt-server/tests/api_error_paths.rs` (`create_duplicate_id_retries_then_succeeds`)
- `PORTED` `TestClaimSecret_ValidationAndRateLimit` -> `crates/secrt-server/tests/api_behavior.rs` (`claim_validation_and_not_found_masking`), `crates/secrt-server/tests/api_quota.rs` (`claim_rate_limit_after_burst`), `crates/secrt-server/tests/api_error_paths.rs` (`claim_bad_content_type_is_400`)
- `PORTED` `TestBurnSecret` -> `crates/secrt-server/tests/api_behavior.rs` (`burn_flow_and_owner_scope`)
- `PORTED` `TestBurnSecret_MethodAndStoreErrors` -> `crates/secrt-server/tests/api_error_paths.rs` (`method_not_allowed_on_burn_and_info`, `burn_store_error_is_500`, `burn_requires_api_key`)
- `PORTED` `TestClaimSecret_MethodIdAndStoreErrors` -> `crates/secrt-server/tests/api_error_paths.rs` (`method_not_allowed_on_authed_create_and_claim`, `claim_store_error_is_500`, `claim_invalid_json_envelope_from_store_is_500`)
- `PORTED` `TestAuthedCreate_RateLimitedAndAuthFailures` -> `crates/secrt-server/tests/api_error_paths.rs` (`authed_create_rate_limited_path`, `authed_create_with_non_bearer_authorization_is_401`), `crates/secrt-server/tests/api_behavior.rs` (`authed_create_requires_api_key`)
- `PORTED` `TestClientIP` -> `crates/secrt-server/src/http/mod.rs` unit tests (`client_ip_from_loopback_proxy`, `client_ip_fallback_paths`)

## `legacy/secrt-server/internal/api/server_behavioral_test.go`
- `PORTED` `TestFullLifecycle_CreateClaimVerifyDeletion` -> `crates/secrt-server/tests/api_behavior.rs` (`public_create_and_claim_flow`)
- `PORTED` `TestFullLifecycle_AuthedCreateBurnVerify` -> `crates/secrt-server/tests/api_behavior.rs` (`burn_flow_and_owner_scope`)
- `PORTED` `TestFullLifecycle_WrongClaimTokenReturns404` -> `crates/secrt-server/tests/api_behavior.rs` (`wrong_claim_then_right_claim`)
- `PORTED` `TestClaimPreservesEnvelopeFidelity` -> `crates/secrt-server/tests/api_behavior.rs` (`binary_payload_envelope_roundtrip`)
- `PORTED` `TestSecurityHeaders_OnAllResponses` -> `crates/secrt-server/tests/api_behavior.rs` (`method_not_allowed_and_headers`)
- `PORTED` `TestRequestID_PropagatedOnAllResponses` -> `crates/secrt-server/tests/api_behavior.rs` (`incoming_request_id_is_echoed`)
- `PORTED` `TestConcurrentClaim_OnlyOneSucceeds` -> `crates/secrt-server/tests/api_behavior.rs` (`concurrent_claim_only_one_succeeds`)
- `PORTED` `TestConcurrentCreate_UniqueIDs` -> `crates/secrt-server/tests/api_behavior.rs` (`concurrent_create_generates_unique_ids`)
- `NOT_FEASIBLE_COMPENSATED` `TestMemStore_ConcurrentMixedOps`
  - Rationale: Legacy test was tightly coupled to Go in-memory store internals and goroutine scheduling details.
  - Compensating tests: `crates/secrt-server/tests/api_behavior.rs` (`concurrent_claim_only_one_succeeds`, `concurrent_create_generates_unique_ids`), `crates/secrt-server/src/http/mod.rs` unit test (`memstore_trait_methods_are_exercised`)
- `PORTED` `TestCreateSecret_EnvelopeEdgeCases` -> `crates/secrt-server/tests/api_behavior.rs` (`create_validation_and_content_type_errors`, `binary_payload_envelope_roundtrip`), `crates/secrt-server/tests/domain_secret_rules.rs` (`envelope_validation_and_size`)
- `PORTED` `TestCreateSecret_TTLEdgeCases` -> `crates/secrt-server/tests/api_error_paths.rs` (`create_invalid_ttl_with_valid_claim_hash`), `crates/secrt-core/src/server.rs` unit tests (`normalize_ttl_default_and_bounds`)
- `PORTED` `TestClaimSecret_ShortClaimToken` -> `crates/secrt-server/tests/api_behavior.rs` (`claim_validation_and_not_found_masking`), `crates/secrt-core/src/server.rs` unit tests (`claim_token_rejects_short_or_invalid`)
- `PORTED` `TestCreateSecret_OversizeBodyRejected` -> `crates/secrt-server/tests/api_error_paths.rs` (`create_envelope_too_large_and_invalid_claim_hash`), `crates/secrt-server/src/http/mod.rs` unit test (`read_json_body_too_large_with_and_without_custom_message`)
- `PORTED` `TestCreateSecret_ContentTypeWithCharset` -> `crates/secrt-server/tests/api_behavior.rs` (`create_accepts_json_content_type_with_charset`)

## `legacy/secrt-server/internal/api/quota_test.go`
- `PORTED` `TestCreateSecret_QuotaSecretCountExceeded` -> `crates/secrt-server/tests/api_quota.rs` (`public_secret_count_quota_exceeded`)
- `PORTED` `TestCreateSecret_QuotaTotalBytesExceeded` -> `crates/secrt-server/tests/api_quota.rs` (`public_total_bytes_quota_exceeded`)
- `PORTED` `TestCreateSecret_AuthedQuotaHigherLimits` -> `crates/secrt-server/tests/api_quota.rs` (`authed_quota_higher_than_public`)
- `PORTED` `TestCreateSecret_QuotaGetUsageError` -> `crates/secrt-server/tests/api_error_paths.rs` (`create_usage_error_is_500`)
- `PORTED` `TestCreateSecret_QuotaResetsAfterClaim` -> `crates/secrt-server/tests/api_quota.rs` (`quota_resets_after_claim`)
- `PORTED` `TestCreateSecret_QuotaZeroMeansUnlimited` -> `crates/secrt-server/tests/api_quota.rs` (`quota_zero_limits_mean_unlimited`)

## `legacy/secrt-server/internal/api/binary_payload_test.go`
- `PORTED` `TestBinaryPayload_SmallPNG` -> `crates/secrt-server/tests/api_behavior.rs` (`binary_payload_envelope_roundtrip`)
- `PORTED` `TestBinaryPayload_JPEG` -> `crates/secrt-server/tests/api_behavior.rs` (`binary_payload_envelope_roundtrip`)
- `PORTED` `TestBinaryPayload_NearMaxSize` -> `crates/secrt-server/tests/api_quota.rs` (`public_envelope_near_max_size_allowed`)
- `PORTED` `TestBinaryPayload_ExceedsMaxSize` -> `crates/secrt-server/tests/api_error_paths.rs` (`create_envelope_too_large_and_invalid_claim_hash`)
- `PORTED` `TestBinaryPayload_NullBytes` -> `crates/secrt-server/tests/api_behavior.rs` (`binary_payload_envelope_roundtrip`)
- `PORTED` `TestBinaryPayload_MultipleFields` -> `crates/secrt-server/tests/api_behavior.rs` (`binary_payload_envelope_roundtrip`)
- `PORTED` `TestBinaryPayload_Base64URLEncoding` -> `crates/secrt-server/tests/api_behavior.rs` (`binary_payload_envelope_roundtrip`)

## `legacy/secrt-server/internal/api/middleware_test.go`
- `PORTED` `TestRequestIDMiddleware_UsesIncomingID` -> `crates/secrt-server/tests/api_behavior.rs` (`incoming_request_id_is_echoed`)
- `PORTED` `TestRequestIDMiddleware_GeneratesID` -> `crates/secrt-server/tests/api_behavior.rs` (`method_not_allowed_and_headers`)
- `PORTED` `TestSecurityHeadersMiddleware_SetsHeaders` -> `crates/secrt-server/tests/api_behavior.rs` (`method_not_allowed_and_headers`)
- `PORTED` `TestRecoverMiddleware_ConvertsPanicTo500` -> `crates/secrt-server/src/http/mod.rs` unit test (`catch_panic_layer_converts_panics_to_500`)
- `NOT_FEASIBLE_COMPENSATED` `TestStatusRecorder_DefaultStatusAndBytes`
  - Rationale: Legacy Go test targets a custom `statusRecorder`; Axum/Tower provide response status/body accounting via framework internals and no equivalent recorder type exists.
  - Compensating tests: `crates/secrt-server/src/http/mod.rs` request middleware coverage plus `crates/secrt-server/tests/api_behavior.rs` (`method_not_allowed_and_headers`)
- `NOT_FEASIBLE_COMPENSATED` `TestStatusRecorder_WriteHeader`
  - Rationale: Same recorder-specific implementation detail removed in Axum port.
  - Compensating tests: `crates/secrt-server/src/http/mod.rs` middleware/request logging path exercised through API integration tests
- `PORTED` `TestPrivacyLogCheckMiddleware` -> `crates/secrt-server/tests/api_behavior.rs` (`privacy_check_triggers_on_first_proxied_request`), `crates/secrt-server/src/http/mod.rs` unit test (`privacy_log_header_modes`)
- `PORTED` `TestPrivacyLogCheckMiddleware_FiresOnlyOnce` -> `crates/secrt-server/tests/api_behavior.rs` (`privacy_check_triggers_on_first_proxied_request`)
- `PORTED` `TestPrivacyLogCheckMiddleware_SkipsDirectThenFiresOnProxy` -> `crates/secrt-server/src/http/mod.rs` unit test (`privacy_log_header_modes`)

## `legacy/secrt-server/internal/api/errors_test.go`
- `PORTED` `TestIsJSONContentType` -> `crates/secrt-server/src/http/mod.rs` unit test (`json_content_type`)
- `PORTED` `TestMapDecodeError` -> `crates/secrt-server/src/http/mod.rs` unit test (`decode_error_maps_data_errors`)

## `legacy/secrt-server/internal/auth/api_keys_test.go`
- `PORTED` `TestParseAPIKey` -> `crates/secrt-server/tests/domain_auth.rs` (`parse_and_hash_helpers`)
- `PORTED` `TestHashAPIKeySecret` -> `crates/secrt-server/tests/domain_auth.rs` (`parse_and_hash_helpers`)
- `PORTED` `TestGenerateAndAuthenticateAPIKey` -> `crates/secrt-server/tests/domain_auth.rs` (`authenticate_success_and_failure`, `parse_and_hash_helpers`)
- `PORTED` `TestAuthenticate_ErrorCases` -> `crates/secrt-server/tests/domain_auth.rs` (`authenticate_maps_storage_errors`, `authenticate_rejects_revoked_key`)
- `PORTED` `TestSecureEqualsHex` -> `crates/secrt-server/tests/domain_auth.rs` (`parse_and_hash_helpers`)
- `NOT_FEASIBLE_COMPENSATED` `TestGenerateAPIKey_FirstRandReadError`
  - Rationale: Legacy Go injected deterministic read failures into RNG; `ring` RNG in Rust is sealed and not directly mock-injectable in production path.
  - Compensating tests: `crates/secrt-server/src/domain/auth.rs` unit tests (`generate_key`, `hash_requires_pepper`) and `crates/secrt-server/tests/domain_auth.rs` (`parse_and_hash_helpers`)
- `NOT_FEASIBLE_COMPENSATED` `TestGenerateAPIKey_SecondRandReadError`
  - Rationale: Same sealed RNG limitation as above.
  - Compensating tests: `crates/secrt-server/src/domain/auth.rs` unit tests (`generate_key`), `crates/secrt-server/tests/domain_auth.rs` (`authenticate_maps_storage_errors`)

## `legacy/secrt-server/internal/secrets/secrets_test.go`
- `PORTED` `TestGenerateID` -> `crates/secrt-server/tests/domain_secret_rules.rs` (`generated_ids_are_url_safe_and_uniqueish`)
- `PORTED` `TestNormalizePublicTTL` -> `crates/secrt-core/src/server.rs` unit test (`normalize_ttl_default_and_bounds`)
- `PORTED` `TestTTLV1SpecValues` -> `crates/secrt-cli/tests/ttl_vectors.rs` and `crates/secrt-core/src/ttl.rs` vector/unit coverage
- `PORTED` `TestNormalizeAuthedTTL` -> `crates/secrt-core/src/server.rs` unit test (`normalize_ttl_default_and_bounds`)
- `PORTED` `TestValidateEnvelope` -> `crates/secrt-server/tests/domain_secret_rules.rs` (`envelope_validation_and_size`)
- `PORTED` `TestHashClaimToken` -> `crates/secrt-core/src/server.rs` unit test (`claim_hash_roundtrip`)
- `PORTED` `TestValidateClaimHash` -> `crates/secrt-core/src/server.rs` unit tests (`claim_hash_roundtrip`, `claim_token_rejects_short_or_invalid`)
- `NOT_FEASIBLE_COMPENSATED` `TestGenerateID_RandReadError`
  - Rationale: Go test injected entropy-read failures; Rust `ring` RNG is sealed in production code path.
  - Compensating tests: `crates/secrt-server/src/domain/secret_rules.rs` unit test (`id_generation`) plus server create duplicate/error-path tests.
- `PORTED` `TestNormalizeTTLWithMax_OverflowGuard` -> `crates/secrt-core/src/server.rs` unit test (`normalize_ttl_default_and_bounds`)
- `PORTED` `TestValidateEnvelope_BoundarySize` -> `crates/secrt-server/tests/domain_secret_rules.rs` (`envelope_validation_and_size`)
- `PORTED` `TestFormatBytes` -> `crates/secrt-server/tests/domain_secret_rules.rs` (`format_bytes_cases`)

## `legacy/secrt-server/internal/storage/postgres/*.go`
- `PORTED` `TestStore_SecretLifecycle` -> `crates/secrt-server/tests/postgres_integration.rs` (`postgres_secret_lifecycle_and_api_keys`)
- `PORTED` `TestStore_APIKeys` -> `crates/secrt-server/tests/postgres_integration.rs` (`postgres_secret_lifecycle_and_api_keys`)
- `NOT_FEASIBLE_COMPENSATED` `TestStore_ClosedDB_ReturnsErrors`
  - Rationale: Legacy test closes `database/sql` handles directly; deadpool/tokio-postgres lifecycle differs and does not expose same closed-handle behavior.
  - Compensating tests: `crates/secrt-server/tests/postgres_integration.rs` (`postgres_invalid_url_errors`) and `crates/secrt-server/src/storage/mod.rs` unit tests (`storage_error_from_*` conversions)
- `PORTED` `TestStore_GetUsage_EmptyOwner` -> `crates/secrt-server/tests/postgres_integration.rs` (`postgres_secret_lifecycle_and_api_keys` usage section)
- `PORTED` `TestStore_GetUsage_ExcludesExpired` -> `crates/secrt-server/tests/postgres_integration.rs` (`postgres_secret_lifecycle_and_api_keys` usage section)
- `PORTED` `TestStore_GetUsage_SumsBytes` -> `crates/secrt-server/tests/postgres_integration.rs` (`postgres_secret_lifecycle_and_api_keys` usage section)
- `PORTED` `TestStore_GetUsage_SeparateOwners` -> `crates/secrt-server/tests/postgres_integration.rs` (`postgres_secret_lifecycle_and_api_keys` usage section)

## `legacy/secrt-server/internal/database/*.go`
- `NOT_FEASIBLE_COMPENSATED` `TestConnection_Close_NilSafe`
  - Rationale: Go connection wrapper type was removed; Rust uses pooled `deadpool-postgres` clients.
  - Compensating tests: `crates/secrt-server/tests/postgres_integration.rs` (`postgres_invalid_url_errors`) and runtime startup tests with schema migration.
- `NOT_FEASIBLE_COMPENSATED` `TestConnection_DBAndClose`
  - Rationale: No equivalent exported connection wrapper in Rust architecture.
  - Compensating tests: `crates/secrt-server/tests/postgres_integration.rs` (`postgres_secret_lifecycle_and_api_keys`)
- `NOT_FEASIBLE_COMPENSATED` `TestOpenPostgres_PingFailure`
  - Rationale: Rust startup verifies connectivity through pool acquisition rather than explicit wrapper ping.
  - Compensating tests: `crates/secrt-server/tests/postgres_integration.rs` (`postgres_invalid_url_errors`), `crates/secrt-server/src/runtime.rs` (`run_server_invalid_database_url_errors`)
- `PORTED` `TestMigrator_ErrorPaths` -> `crates/secrt-server/src/storage/migrations.rs` unit test (`migrations_sorted_and_non_empty`), `crates/secrt-server/tests/postgres_integration.rs` (`postgres_invalid_url_errors`)
- `PORTED` `TestMigrator_Migrate_ClosedDB` -> `crates/secrt-server/tests/postgres_integration.rs` (`postgres_invalid_url_errors`)
- `PORTED` `TestMigrator_getMigrationFiles` -> `crates/secrt-server/src/storage/migrations.rs` unit test (`migrations_sorted_and_non_empty`)
- `PORTED` `TestMigrator_Migrate_HappyPath` -> `crates/secrt-server/tests/postgres_integration.rs` (`postgres_secret_lifecycle_and_api_keys`, idempotent migrate assertions)

## `legacy/secrt-server/cmd/secrt-server/reaper_test.go`
- `PORTED` `TestRunExpiryReaperOnceUsesUTCAndTimeout` -> `crates/secrt-server/tests/reaper_runtime.rs` (`reaper_once_timeout_path`, `reaper_once_invokes_delete`)
- `PORTED` `TestRunExpiryReaperRunsImmediatelyAndStopsOnCancel` -> `crates/secrt-server/tests/reaper_runtime.rs` (`reaper_runs_once_immediately_and_can_stop`)
- `PORTED` `TestRunExpiryReaperOnce_CancelledContext` -> `crates/secrt-server/tests/reaper_runtime.rs` (`reaper_runs_once_immediately_and_can_stop` stop-path coverage)
- `PORTED` `TestRunExpiryReaperOnce_StoreError` -> `crates/secrt-server/tests/reaper_runtime.rs` (`reaper_once_error_path`)
- `PORTED` `TestRunExpiryReaperOnce_DeletedCountLogged` -> `crates/secrt-server/tests/reaper_runtime.rs` (`reaper_once_logs_deleted_count_path`)
- `NOT_FEASIBLE_COMPENSATED` `TestRunExpiryReaper_InvalidInterval`
  - Rationale: Rust reaper interval is a constant in this milestone and not runtime-configurable.
  - Compensating tests: `crates/secrt-server/tests/reaper_runtime.rs` (`reaper_runs_once_immediately_and_can_stop`)
- `NOT_FEASIBLE_COMPENSATED` `TestRunExpiryReaper_NilLoggerAndNow`
  - Rationale: Rust implementation uses `tracing` and `Utc::now()` directly; no injectable logger/clock hooks in v1 parity scope.
  - Compensating tests: `crates/secrt-server/tests/reaper_runtime.rs` full path coverage + API integration tests for expiry behavior.

## `legacy/secrt-server/internal/api/pages_test.go`
- `PORTED` `TestPages_IndexAndSecretAndRobots` -> `crates/secrt-server/tests/api_behavior.rs` (`page_and_robots_routes`), `crates/secrt-server/src/http/mod.rs` unit test (`secret_page_includes_id_and_noindex_headers`)

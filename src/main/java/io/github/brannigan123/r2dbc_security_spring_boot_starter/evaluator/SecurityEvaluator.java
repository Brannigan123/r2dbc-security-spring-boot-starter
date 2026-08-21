package io.github.brannigan123.r2dbc_security_spring_boot_starter.evaluator;

import org.aspectj.lang.JoinPoint;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.DatabaseClient.GenericExecuteSpec;

import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.And;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Or;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Permission;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Role;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Secured;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.exception.AccessDeniedException;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.service.SecurityContextUserResolver;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public class SecurityEvaluator {

    private final DatabaseClient databaseClient;
    private final SecurityContextUserResolver userResolver;
    private final SpelExpressionEvaluator spelEvaluator;

    public SecurityEvaluator(DatabaseClient databaseClient,
            SecurityContextUserResolver userResolver,
            SpelExpressionEvaluator spelEvaluator) {
        this.databaseClient = databaseClient;
        this.userResolver = userResolver;
        this.spelEvaluator = spelEvaluator;
    }

    public Mono<Void> evaluate(Secured secured, JoinPoint joinPoint) {
        return userResolver.getCurrentUserId()
                .switchIfEmpty(
                        Mono.error(new AccessDeniedException("You need to be logged in to access this resource")))
                .flatMap(userId -> evaluateSecured(secured, userId, joinPoint))
                .flatMap(allowed -> allowed
                        ? Mono.empty()
                        : Mono.error(new AccessDeniedException(
                                "Access denied: You do not have the required roles or permissions to access this resource")));
    }

    private Mono<Boolean> evaluateSecured(Secured secured, String userId, JoinPoint joinPoint) {
        Mono<Boolean> directRoles = evaluateRoles(secured.roles(), userId, joinPoint);
        Mono<Boolean> directPermissions = evaluatePermissions(secured.permissions(), userId, joinPoint);
        Mono<Boolean> andBlocks = evaluateAndBlocks(secured.and(), userId, joinPoint);
        Mono<Boolean> orBlocks = evaluateOrBlocks(secured.or(), userId, joinPoint);

        return Flux.just(directRoles, directPermissions, andBlocks, orBlocks)
                .flatMap(mono -> mono)
                .any(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluateOrBlocks(Or[] ors, String userId, JoinPoint joinPoint) {
        if (ors.length == 0) {
            return Mono.just(false);
        }

        return Flux.fromArray(ors)
                .flatMap(or -> {
                    Mono<Boolean> roles = evaluateRoles(or.roles(), userId, joinPoint);
                    Mono<Boolean> perms = evaluatePermissions(or.permissions(), userId, joinPoint);
                    Mono<Boolean> ands = evaluateAndBlocks(or.and(), userId, joinPoint);

                    return Flux.just(roles, perms, ands)
                            .flatMap(mono -> mono)
                            .any(Boolean::booleanValue);
                })
                .any(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluateAndBlocks(And[] ands, String userId, JoinPoint joinPoint) {
        if (ands.length == 0) {
            return Mono.just(false);
        }

        return Flux.fromArray(ands)
                .flatMap(and -> {
                    Mono<Boolean> rolesMatch = evaluateRolesAll(and.roles(), userId, joinPoint);
                    Mono<Boolean> permsMatch = evaluatePermissionsAll(and.permissions(), userId, joinPoint);
                    return Mono.zip(rolesMatch, permsMatch, (r, p) -> r && p);
                })
                .any(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluateRoles(Role[] roles, String userId, JoinPoint joinPoint) {
        if (roles.length == 0) {
            return Mono.just(false);
        }
        return Flux.fromArray(roles)
                .flatMap(role -> hasRole(role, userId, joinPoint))
                .any(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluateRolesAll(Role[] roles, String userId, JoinPoint joinPoint) {
        if (roles.length == 0) {
            return Mono.just(true);
        }
        return Flux.fromArray(roles)
                .flatMap(role -> hasRole(role, userId, joinPoint))
                .all(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluatePermissions(Permission[] permissions, String userId, JoinPoint joinPoint) {
        if (permissions.length == 0) {
            return Mono.just(false);
        }
        return Flux.fromArray(permissions)
                .flatMap(perm -> hasPermission(perm, userId, joinPoint))
                .any(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluatePermissionsAll(Permission[] permissions, String userId, JoinPoint joinPoint) {
        if (permissions.length == 0) {
            return Mono.just(true);
        }
        return Flux.fromArray(permissions)
                .flatMap(perm -> hasPermission(perm, userId, joinPoint))
                .all(Boolean::booleanValue);
    }

    private Mono<Boolean> hasRole(Role role, String userId, JoinPoint joinPoint) {
        if (!spelEvaluator.evaluateBoolean(role.condition(), joinPoint)) {
            return Mono.just(false);
        }

        String tenantId = spelEvaluator.evaluateString(role.tenantId(), joinPoint);

        String sql = """
                SELECT COUNT(*) AS total
                FROM assigned_roles
                WHERE user_id = :userId
                  AND role_name = :roleName
                  AND (:tenantId IS NULL OR tenant_id = :tenantId)
                """;

        GenericExecuteSpec spec = databaseClient.sql(sql)
                .bind("userId", userId)
                .bind("roleName", role.value());

        if (tenantId != null) {
            spec = spec.bind("tenantId", tenantId);
        } else {
            spec = spec.bindNull("tenantId", String.class);
        }

        return spec.map((row, metadata) -> row.get("total", Long.class))
                .one()
                .map(count -> count != null && count > 0)
                .defaultIfEmpty(false);
    }

    private Mono<Boolean> hasPermission(Permission permission, String userId, JoinPoint joinPoint) {
        if (!spelEvaluator.evaluateBoolean(permission.condition(), joinPoint)) {
            return Mono.just(false);
        }

        String tenantId = spelEvaluator.evaluateString(permission.tenantId(), joinPoint);

        String sql = """
                SELECT COUNT(*) AS total
                FROM assigned_roles ar
                JOIN role_permissions rp ON ar.tenant_id = rp.tenant_id AND ar.role_name = rp.role_name
                WHERE ar.user_id = :userId
                  AND rp.permission_name = :permissionName
                  AND (:tenantId IS NULL OR ar.tenant_id = :tenantId)
                """;

        GenericExecuteSpec spec = databaseClient.sql(sql)
                .bind("userId", userId)
                .bind("permissionName", permission.value());

        if (tenantId != null) {
            spec = spec.bind("tenantId", tenantId);
        } else {
            spec = spec.bindNull("tenantId", String.class);
        }

        return spec.map((row, metadata) -> row.get("total", Long.class))
                .one()
                .map(count -> count != null && count > 0)
                .defaultIfEmpty(false);
    }
}
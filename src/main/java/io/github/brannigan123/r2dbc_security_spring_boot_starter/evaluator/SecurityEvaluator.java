package io.github.brannigan123.r2dbc_security_spring_boot_starter.evaluator;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

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
    private final SecurityContextUserResolver<? extends Principal> userResolver;
    private final SpelExpressionEvaluator spelEvaluator;

    public SecurityEvaluator(DatabaseClient databaseClient,
            SecurityContextUserResolver<? extends Principal> userResolver,
            SpelExpressionEvaluator spelEvaluator) {
        this.databaseClient = databaseClient;
        this.userResolver = userResolver;
        this.spelEvaluator = spelEvaluator;
    }

    public Mono<Void> evaluate(Secured secured, JoinPoint joinPoint) {
        return userResolver.getCurrentUserId()
                .switchIfEmpty(
                        Mono.error(new AccessDeniedException("You need to be logged in to access this resource")))
                .flatMap(userId -> userResolver.getCurrentPrincipal()
                        .cast(Object.class)
                        .defaultIfEmpty(userId)
                        .flatMap(principal -> evaluateSecured(secured, userId, principal, joinPoint)))
                .flatMap(allowed -> allowed
                        ? Mono.empty()
                        : Mono.error(new AccessDeniedException(
                                "Access denied: You do not have the required roles or permissions to access this resource")));
    }

    private Mono<Boolean> evaluateSecured(Secured secured, String userId, Object principal, JoinPoint joinPoint) {
        Mono<Boolean> directRoles = evaluateRoles(secured.roles(), userId, principal, joinPoint);
        Mono<Boolean> directPermissions = evaluatePermissions(secured.permissions(), userId, principal, joinPoint);
        Mono<Boolean> directConditions = evaluateConditions(secured.condition(), secured.conditions(), principal,
                joinPoint);
        Mono<Boolean> andBlocks = evaluateAndBlocks(secured.and(), userId, principal, joinPoint);
        Mono<Boolean> orBlocks = evaluateOrBlocks(secured.or(), userId, principal, joinPoint);

        return Flux.just(directRoles, directPermissions, directConditions, andBlocks, orBlocks)
                .flatMap(mono -> mono)
                .any(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluateOrBlocks(Or[] ors, String userId, Object principal, JoinPoint joinPoint) {
        if (ors.length == 0) {
            return Mono.just(false);
        }

        return Flux.fromArray(ors)
                .flatMap(or -> {
                    Mono<Boolean> roles = evaluateRoles(or.roles(), userId, principal, joinPoint);
                    Mono<Boolean> perms = evaluatePermissions(or.permissions(), userId, principal, joinPoint);
                    Mono<Boolean> conds = evaluateConditions(or.condition(), or.conditions(), principal, joinPoint);
                    Mono<Boolean> ands = evaluateAndBlocks(or.and(), userId, principal, joinPoint);

                    return Flux.just(roles, perms, conds, ands)
                            .flatMap(mono -> mono)
                            .any(Boolean::booleanValue);
                })
                .any(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluateAndBlocks(And[] ands, String userId, Object principal, JoinPoint joinPoint) {
        if (ands.length == 0) {
            return Mono.just(false);
        }

        return Flux.fromArray(ands)
                .flatMap(and -> {
                    Mono<Boolean> rolesMatch = evaluateRolesAll(and.roles(), userId, principal, joinPoint);
                    Mono<Boolean> permsMatch = evaluatePermissionsAll(and.permissions(), userId, principal, joinPoint);
                    Mono<Boolean> condsMatch = evaluateConditionsAll(and.condition(), and.conditions(), principal,
                            joinPoint);
                    return Mono.zip(rolesMatch, permsMatch, condsMatch)
                            .map(tuple -> tuple.getT1() && tuple.getT2() && tuple.getT3());
                })
                .any(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluateRoles(Role[] roles, String userId, Object principal, JoinPoint joinPoint) {
        if (roles.length == 0) {
            return Mono.just(false);
        }
        return Flux.fromArray(roles)
                .flatMap(role -> hasRole(role, userId, principal, joinPoint))
                .any(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluateRolesAll(Role[] roles, String userId, Object principal, JoinPoint joinPoint) {
        if (roles.length == 0) {
            return Mono.just(true);
        }
        return Flux.fromArray(roles)
                .flatMap(role -> hasRole(role, userId, principal, joinPoint))
                .all(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluatePermissions(Permission[] permissions, String userId, Object principal,
            JoinPoint joinPoint) {
        if (permissions.length == 0) {
            return Mono.just(false);
        }
        return Flux.fromArray(permissions)
                .flatMap(perm -> hasPermission(perm, userId, principal, joinPoint))
                .any(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluatePermissionsAll(Permission[] permissions, String userId, Object principal,
            JoinPoint joinPoint) {
        if (permissions.length == 0) {
            return Mono.just(true);
        }
        return Flux.fromArray(permissions)
                .flatMap(perm -> hasPermission(perm, userId, principal, joinPoint))
                .all(Boolean::booleanValue);
    }

    private Mono<Boolean> evaluateConditions(String condition, String[] conditions, Object principal,
            JoinPoint joinPoint) {
        List<String> validConditions = getValidConditions(condition, conditions);
        if (validConditions.isEmpty()) {
            return Mono.just(false);
        }
        boolean anyMatch = validConditions.stream()
                .anyMatch(cond -> spelEvaluator.evaluateBoolean(cond, joinPoint, principal));
        return Mono.just(anyMatch);
    }

    private Mono<Boolean> evaluateConditionsAll(String condition, String[] conditions, Object principal,
            JoinPoint joinPoint) {
        List<String> validConditions = getValidConditions(condition, conditions);
        if (validConditions.isEmpty()) {
            return Mono.just(true);
        }
        boolean allMatch = validConditions.stream()
                .allMatch(cond -> spelEvaluator.evaluateBoolean(cond, joinPoint, principal));
        return Mono.just(allMatch);
    }

    private boolean checkConditionsPass(String condition, String[] conditions, JoinPoint joinPoint, Object principal) {
        List<String> validConditions = getValidConditions(condition, conditions);
        for (String cond : validConditions) {
            if (!spelEvaluator.evaluateBoolean(cond, joinPoint, principal)) {
                return false;
            }
        }
        return true;
    }

    private List<String> getValidConditions(String condition, String[] conditions) {
        List<String> list = new ArrayList<>();
        if (condition != null && !condition.isBlank()) {
            list.add(condition);
        }
        if (conditions != null) {
            for (String c : conditions) {
                if (c != null && !c.isBlank()) {
                    list.add(c);
                }
            }
        }
        return list;
    }

    private Mono<Boolean> hasRole(Role role, String userId, Object principal, JoinPoint joinPoint) {
        if (!checkConditionsPass(role.condition(), role.conditions(), joinPoint, principal)) {
            return Mono.just(false);
        }

        String tenantId = spelEvaluator.evaluateString(role.tenantId(), joinPoint, principal);

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

    private Mono<Boolean> hasPermission(Permission permission, String userId, Object principal, JoinPoint joinPoint) {
        if (!checkConditionsPass(permission.condition(), permission.conditions(), joinPoint, principal)) {
            return Mono.just(false);
        }

        String tenantId = spelEvaluator.evaluateString(permission.tenantId(), joinPoint, principal);

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
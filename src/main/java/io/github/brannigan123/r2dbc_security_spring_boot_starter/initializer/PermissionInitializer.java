package io.github.brannigan123.r2dbc_security_spring_boot_starter.initializer;

import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.And;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Or;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Permission;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Secured;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.util.ClassUtils;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public class PermissionInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(PermissionInitializer.class);

    private final ApplicationContext applicationContext;
    private final DatabaseClient databaseClient;

    public PermissionInitializer(ApplicationContext applicationContext, DatabaseClient databaseClient) {
        this.applicationContext = applicationContext;
        this.databaseClient = databaseClient;
    }

    @Override
    public void run(ApplicationArguments args) {
        Set<String> permissions = scanPermissions();
        if (permissions.isEmpty()) {
            log.info("No permissions found in @Secured annotations to initialize.");
            return;
        }

        log.info("Found {} permission(s) across annotations. Syncing with database...", permissions.size());

        initializePermissions(permissions)
                .doOnSuccess(v -> log.info("Permission initialization completed successfully."))
                .doOnError(ex -> log.error("Failed to initialize permissions", ex))
                .block();
    }

    private Set<String> scanPermissions() {
        Set<String> permissionNames = new HashSet<>();
        String[] beanDefinitionNames = applicationContext.getBeanDefinitionNames();

        for (String beanName : beanDefinitionNames) {
            Class<?> beanType = applicationContext.getType(beanName);
            if (beanType == null) {
                continue;
            }

            Class<?> targetClass = ClassUtils.getUserClass(beanType);

            Secured classSecured = AnnotatedElementUtils.findMergedAnnotation(targetClass, Secured.class);
            if (classSecured != null) {
                permissionNames.addAll(extractPermissions(classSecured));
            }

            for (Method method : targetClass.getDeclaredMethods()) {
                Secured methodSecured = AnnotatedElementUtils.findMergedAnnotation(method, Secured.class);
                if (methodSecured != null) {
                    permissionNames.addAll(extractPermissions(methodSecured));
                }
            }
        }
        return permissionNames;
    }

    private Set<String> extractPermissions(Secured secured) {
        Set<String> names = new HashSet<>();
        if (secured == null) {
            return names;
        }

        for (Permission perm : secured.permissions()) {
            if (!perm.value().isBlank()) {
                names.add(perm.value());
            }
        }

        for (Or or : secured.or()) {
            names.addAll(extractFromOr(or));
        }

        for (And and : secured.and()) {
            names.addAll(extractFromAnd(and));
        }

        return names;
    }

    private Set<String> extractFromOr(Or or) {
        Set<String> names = new HashSet<>();
        for (Permission perm : or.permissions()) {
            if (!perm.value().isBlank()) {
                names.add(perm.value());
            }
        }
        for (And and : or.and()) {
            names.addAll(extractFromAnd(and));
        }
        return names;
    }

    private Set<String> extractFromAnd(And and) {
        Set<String> names = new HashSet<>();
        for (Permission perm : and.permissions()) {
            if (!perm.value().isBlank()) {
                names.add(perm.value());
            }
        }
        return names;
    }

    private Mono<Void> initializePermissions(Set<String> permissionNames) {
        String selectSql = "SELECT name FROM permissions WHERE name IN (:names)";

        return databaseClient.sql(selectSql)
                .bind("names", permissionNames)
                .map((row, metadata) -> row.get("name", String.class))
                .all()
                .collectList()
                .flatMap(existingPermissions -> {
                    Set<String> existingSet = new HashSet<>(existingPermissions);
                    Set<String> missingPermissions = new HashSet<>(permissionNames);
                    missingPermissions.removeAll(existingSet);

                    if (missingPermissions.isEmpty()) {
                        log.info("All scanned permissions already exist in the database.");
                        return Mono.empty();
                    }

                    log.info("Inserting {} missing permission(s): {}", missingPermissions.size(), missingPermissions);

                    String insertSql = "INSERT INTO permissions (name) VALUES (:name)";

                    return Flux.fromIterable(missingPermissions)
                            .flatMap(perm -> databaseClient.sql(insertSql)
                                    .bind("name", perm)
                                    .then())
                            .then();
                });
    }
}

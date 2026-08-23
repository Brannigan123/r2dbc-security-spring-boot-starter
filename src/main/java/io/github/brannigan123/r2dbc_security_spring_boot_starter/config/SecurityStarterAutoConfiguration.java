package io.github.brannigan123.r2dbc_security_spring_boot_starter.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.r2dbc.core.DatabaseClient;

import io.github.brannigan123.r2dbc_security_spring_boot_starter.aspect.SecurityAspect;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.evaluator.SecurityEvaluator;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.evaluator.SpelExpressionEvaluator;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.initializer.PermissionInitializer;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.service.DefaultSecurityContextUserResolver;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.service.SecurityContextUserResolver;

@AutoConfiguration
@EnableAspectJAutoProxy(proxyTargetClass = true)
public class SecurityStarterAutoConfiguration {

    @SuppressWarnings("rawtypes")
    @Bean
    @ConditionalOnMissingBean
    public SecurityContextUserResolver securityContextUserResolver() {
        return new DefaultSecurityContextUserResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public SpelExpressionEvaluator spelExpressionEvaluator() {
        return new SpelExpressionEvaluator();
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Bean
    @ConditionalOnMissingBean
    public SecurityEvaluator securityEvaluator(DatabaseClient databaseClient,
            SecurityContextUserResolver userResolver,
            SpelExpressionEvaluator spelEvaluator) {
        return new SecurityEvaluator(databaseClient, userResolver, spelEvaluator);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityAspect securityAspect(SecurityEvaluator securityEvaluator) {
        return new SecurityAspect(securityEvaluator);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionInitializer permissionInitializer(ApplicationContext applicationContext,
            DatabaseClient databaseClient) {
        return new PermissionInitializer(applicationContext, databaseClient);
    }
}

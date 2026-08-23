package io.github.brannigan123.r2dbc_security_spring_boot_starter.aspect;

import java.lang.reflect.Method;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;

import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Secured;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.evaluator.SecurityEvaluator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Aspect
public class SecurityAspect {

    private final SecurityEvaluator securityEvaluator;

    public SecurityAspect(SecurityEvaluator securityEvaluator) {
        this.securityEvaluator = securityEvaluator;
    }

    @Around("@annotation(io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Secured) || " +
            "@within(io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Secured)")
    public Object intercept(ProceedingJoinPoint joinPoint) throws Throwable {
        Secured secured = extractAnnotation(joinPoint);
        if (secured == null) {
            return joinPoint.proceed();
        }

        Mono<Void> authCheck = securityEvaluator.evaluate(secured, joinPoint);
        Object proceedResult = joinPoint.proceed();

        switch (proceedResult) {
            case Mono<?> monoResult -> {
                return authCheck.then(monoResult);
            }
            case Flux<?> fluxResult -> {
                return authCheck.thenMany(fluxResult);
            }
            default -> {
            }
        }

        return authCheck.thenReturn(proceedResult);
    }

    private Secured extractAnnotation(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Secured secured = method.getAnnotation(Secured.class);

        if (secured == null) {
            secured = joinPoint.getTarget().getClass().getAnnotation(Secured.class);
        }
        return secured;
    }
}
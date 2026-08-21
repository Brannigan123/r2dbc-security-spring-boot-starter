package io.github.brannigan123.r2dbc_security_spring_boot_starter.aspect;

import io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation.Secured;
import io.github.brannigan123.r2dbc_security_spring_boot_starter.evaluator.SecurityEvaluator;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Aspect
public class SecurityAspect {

    private final SecurityEvaluator securityEvaluator;

    public SecurityAspect(SecurityEvaluator securityEvaluator) {
        this.securityEvaluator = securityEvaluator;
    }

    @Around("@annotation(secured) || @within(secured)")
    public Object intercept(ProceedingJoinPoint joinPoint, Secured secured) throws Throwable {
        Mono<Void> authCheck = securityEvaluator.evaluate(secured, joinPoint);

        Object proceedResult = joinPoint.proceed();

        if (proceedResult instanceof Mono<?>) {
            return authCheck.then((Mono<?>) proceedResult);
        } else if (proceedResult instanceof Flux<?>) {
            return authCheck.thenMany((Flux<?>) proceedResult);
        }

        return authCheck.thenReturn(proceedResult).block();
    }
}

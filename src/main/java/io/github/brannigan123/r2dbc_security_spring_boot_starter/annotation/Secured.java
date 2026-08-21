package io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Secured {
    Or[] or() default {};
    And[] and() default {};
    Role[] roles() default {};
    Permission[] permissions() default {};
}

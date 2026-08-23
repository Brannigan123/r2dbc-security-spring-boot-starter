package io.github.brannigan123.r2dbc_security_spring_boot_starter.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface And {
    Role[] roles() default {};

    Permission[] permissions() default {};

    String condition() default "";

    String[] conditions() default {};
}
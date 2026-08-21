package io.github.brannigan123.r2dbc_security_spring_boot_starter.service;

import java.security.Principal;

import reactor.core.publisher.Mono;

public interface SecurityContextUserResolver<T extends Principal> {

    Mono<String> getCurrentUserId();

    Mono<T> getCurrentPrincipal();
}
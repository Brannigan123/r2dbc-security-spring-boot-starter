package io.github.brannigan123.r2dbc_security_spring_boot_starter.service;

import reactor.core.publisher.Mono;

public interface SecurityContextUserResolver {
    Mono<String> getCurrentUserId();
}

# R2DBC Security Spring Boot Starter

A reactive Spring Boot starter for Method and Type-level security evaluations using Spring Data R2DBC and AOP.

## Features
- `@Secured` annotation with boolean composition (`@Or`, `@And`, `@Role`, `@Permission`).
- SpEL support for evaluating method parameters (e.g. `condition = "#tenantId"` or `condition = "#req.tenantId"`).
- Application startup scanning to automatically seed missing permission names into the `permissions` database table.
- Plug-and-play reactive user resolution (`SecurityContextUserResolver`).

## Package Name
`io.github.brannigan123.r2dbc_security_spring_boot_starter`

## Usage Example
```java
@RestController
@RequestMapping("/api/stats")
public class StatsController {

    @GetMapping("/{tenantId}")
    @Secured(
        or = @Or(
            roles = @Role("super_admin"),
            permissions = @Permission(value = "read_stats_xyz", condition = "#tenantId")
        )
    )
    public Mono<String> getStats(@PathVariable("tenantId") String tenantId) {
        return Mono.just("Stats for " + tenantId);
    }
}
```

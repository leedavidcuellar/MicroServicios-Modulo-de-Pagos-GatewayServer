package com.Microservice.ModulosPagosGateway.GatewayServer.Security;

import io.netty.resolver.DefaultAddressResolverGroup;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.netty.http.client.HttpClient;

@EnableWebFluxSecurity
public class SpringSecurityConfig {
    @Autowired
    private JwtAuthenticationFilter authenticationFilter;

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http) {
        return http.authorizeExchange()
                .pathMatchers("/api/security/oauth/**","/api/user/findByMail/**").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/user/generatedUser").permitAll()
                .pathMatchers(HttpMethod.GET, "/api/user/**", "/api/account/**", "/api/transaction").hasAnyRole("ADMIN", "USER")
                .pathMatchers(HttpMethod.POST, "/api/user/**", "/api/account/**", "/api/transaction").hasAnyRole("ADMIN", "USER")
                .pathMatchers(HttpMethod.PUT, "/api/user/**", "/api/account/**", "/api/transaction").hasAnyRole("ADMIN", "USER")
                .pathMatchers("/api/user/deleteUser/{idUser}", "/api/user/getConfig").hasRole("ADMIN")
                .anyExchange().authenticated()
                .and().addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .csrf().disable()
                .build();
    }

    @Bean
    public HttpClient httpClient() {
        return HttpClient.create().resolver(DefaultAddressResolverGroup.INSTANCE);
    }
}

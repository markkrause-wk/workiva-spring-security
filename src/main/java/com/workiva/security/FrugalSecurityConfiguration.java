package com.workiva.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;


@Configuration
public class FrugalSecurityConfiguration {

    @Bean
    public AuthenticationManager authenticationManager(
        ObjectPostProcessor<Object> objectPostProcessor,
        AnonymousAuthenticationProvider anonymousAuthenticationProvider,
        JwtAuthenticationProvider jwtAuthenticationProvider
    ) throws Exception {
        return new AuthenticationManagerBuilder(objectPostProcessor)
            .authenticationProvider(anonymousAuthenticationProvider)
            .authenticationProvider(jwtAuthenticationProvider)
            .build();
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider(WorkivaJwtDecoder workivaJwtDecoder,
                                                               WorkivaJwtAuthenticationConverter workivaJwtAuthenticationConverter) {
        JwtAuthenticationProvider jwtAuthProvider = new JwtAuthenticationProvider(workivaJwtDecoder);
        jwtAuthProvider.setJwtAuthenticationConverter(workivaJwtAuthenticationConverter);
        return jwtAuthProvider;
    }

    @Bean
    public AnonymousAuthenticationProvider anonymousAuthenticationProvider() {
        return new AnonymousAuthenticationProvider(SpringSecurityMiddleware.class.getSimpleName());
    }

    @Bean
    public SpringSecurityMiddleware springSecurityMiddleware(AuthenticationManager authenticationManager) {
        return new SpringSecurityMiddleware(SpringSecurityMiddleware.class.getSimpleName(), authenticationManager);
    }
}

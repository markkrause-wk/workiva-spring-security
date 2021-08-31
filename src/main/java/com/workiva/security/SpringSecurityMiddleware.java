package com.workiva.security;

import com.workiva.frugal.FContext;
import com.workiva.frugal.middleware.InvocationHandler;
import com.workiva.frugal.middleware.ServiceMiddleware;
import com.workiva.messaging_sdk.exception.IamException;
import com.workiva.messaging_sdk.iam.Headers;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

import java.lang.reflect.Method;

/**
 * A {@link ServiceMiddleware} for handling authentication backed by Spring Security classes.
 */
@Slf4j
public class SpringSecurityMiddleware implements ServiceMiddleware {

    private final String anonymousKey;
    private final AuthenticationManager authenticationManager;

    public SpringSecurityMiddleware(String anonymousKey, AuthenticationManager authenticationManager) {
        this.anonymousKey = anonymousKey;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public <T> InvocationHandler<T> apply(T next) {
        return new InvocationHandler<>(next) {
            @Override
            public Object invoke(Method method, Object receiver, Object[] args) throws Throwable {
                FContext fContext = (FContext) args[0];
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                try {
                    Authentication authRequest = getAuthenticationRequest(fContext);
                    Authentication authResult = authenticationManager.authenticate(authRequest);
                    context.setAuthentication(authResult);
                } catch (AuthenticationException ex) {
                    log.debug("Authentication failed, building an anonymous authentication", ex);
                    // authentication "failed" so continue as "anonymous"
                    Authentication anonymous = getAnonymousAuthentication();
                    context.setAuthentication(anonymous);
                    // OR could get to the point and just throw new UnauthorizedException();
                }
                SecurityContextHolder.setContext(context);

                // authentication has done all it can, continue down the chain
                try {
                    return method.invoke(receiver, args);
                } finally {
                    SecurityContextHolder.clearContext();
                }
            }
        };
    }

    /**
     * Build an {@link Authentication} to represent the given {@link FContext}.
     */
    private Authentication getAuthenticationRequest(FContext fContext) {
        Authentication authRequest;
        try {
            String iamToken = Headers.getIamToken(fContext);
            authRequest = new BearerTokenAuthenticationToken(iamToken);
        } catch (IamException e) {
            log.warn("Unable to extract IamToken, authenticating anonymously", e);
            authRequest = getAnonymousAuthentication();
        }
        return authRequest;
    }

    /**
     * Consistently build an {@link AnonymousAuthenticationToken} for un-authenticated requests.
     */
    private Authentication getAnonymousAuthentication() {
        return new AnonymousAuthenticationToken(
            anonymousKey,
            "anonymousUser",
            AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")
        );
    }
}

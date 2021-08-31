package com.workiva.security;

import com.workiva.platform.iam.alpha.authentication.core.principals.WorkivaPrincipal;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * An {@link AbstractAuthenticationToken} representing an authenticated "user" with a {@link WorkivaPrincipal} principal.
 */
public class WorkivaAuthenticationToken extends AbstractAuthenticationToken {

    private final WorkivaPrincipal principal;
    private final String token;

    public WorkivaAuthenticationToken(
        Collection<? extends GrantedAuthority> authorities,
        WorkivaPrincipal principal,
        String token
    ) {
        super(authorities);
        Assert.notNull(principal, "principal cannot be null");
        this.principal = principal;
        this.token = token;

        setAuthenticated(true);
    }

    @Override
    public String getCredentials() {
        return token;
    }

    @Override
    public WorkivaPrincipal getPrincipal() {
        return principal;
    }
}

package com.security.jwt.security;

import org.springframework.security.authentication.AuthenticationManager;

public class JwtAuthenticationTokenFilter extends{


    private AuthenticationManager authenticationManager;
    private JwtSuccessHandler jwtSuccessHandler;

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void setAuthenticationSuccessHandler(JwtSuccessHandler jwtSuccessHandler) {
        this.jwtSuccessHandler = jwtSuccessHandler;
    }
}

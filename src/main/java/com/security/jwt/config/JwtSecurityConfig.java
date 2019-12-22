package com.security.jwt.config;

import com.security.jwt.security.JwtAuthenticationEntryPoint;
import com.security.jwt.security.JwtAuthenticationProvider;
import com.security.jwt.security.JwtAuthenticationTokenFilter;
import com.security.jwt.security.JwtSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collections;

/**
 * This class create to provide web based security
 * @Configuration - This class is configuration class
 * @EnableWebSecurity - Enable web configuration
 * @EnableGlobalMethodSecurity - This enable method level security
 */

@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
@EnableWebSecurity
public class JwtSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 03
     * This is the custom authentication provider
     */
    private JwtAuthenticationProvider authenticationProvider;
    private JwtAuthenticationEntryPoint entryPoint;

    /**
     * 02
     * This provide by spring. Here we going to create authentication manger
     */
    @Bean
    public AuthenticationManager authenticationManager(){
        /**
         * Authentication manger with custom authentication provider
         */
        return new ProviderManager(Collections.singletonList(authenticationProvider));
    }

    /**
     * 01
     * This class is created me
     */
    @Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilter(){
        /**
         * Here we going to crete custom filter for jwt.
         */
        JwtAuthenticationTokenFilter filter = new JwtAuthenticationTokenFilter();
        /**
         * Inject to above created manager to the filter
         */
        filter.setAuthenticationManager(authenticationManager());
        /**
         * This is the success filter. You can redirect to the particular handler and can to any process if you wish.
         */
        filter.setAuthenticationSuccessHandler(new JwtSuccessHandler());

        return filter;
    }

    /**
     * Configure http security filters.
     */

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * .antMatchers() - decided which kind of request pattern should be allow.
         * .exceptionHandling().authenticationEntryPoint(entryPoint)- what need to do if throws some exception.
         * .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) -Say to http, hei http don't make my security stateful
         */
        http.csrf().disable()
                .authorizeRequests().antMatchers("**/rest/**").authenticated()
                .and()
                .exceptionHandling().authenticationEntryPoint(entryPoint)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        /**
         *  Before use default spring UsernamePasswordAuthenticationFilter filter use we created authenticationTokenFilter()
         * (UsernamePasswordAuthenticationFilter is default filter in spring)
         */
        http.addFilterBefore(authenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        /**
         * Add some default headers to the request.
         */
        http.headers().cacheControl();
    }
}

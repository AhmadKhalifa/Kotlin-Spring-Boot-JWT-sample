package com.jwt.spring.springjwt.security.configuration

import com.jwt.spring.springjwt.security.filter.JwtAuthenticationFilter
import com.jwt.spring.springjwt.security.filter.JwtAuthorizationFilter
import com.jwt.spring.springjwt.security.util.JwtAuthenticationEntryPoint
import com.jwt.spring.springjwt.security.util.PUBLIC_PATHS
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
open class WebSecurityConfiguration(
        @Qualifier("userService") private val userDetailsService: UserDetailsService,
        private val unauthorizedHandler: JwtAuthenticationEntryPoint
) : WebSecurityConfigurerAdapter() {

    @Bean
    open fun bCryptPasswordEncoder() = BCryptPasswordEncoder()

    @Autowired
    fun globalUserDetails(authenticationManagerBuilder: AuthenticationManagerBuilder) {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder())
    }

    override fun configure(http: HttpSecurity?) {
        http?.run {
            cors().and().csrf().disable()
                    .authorizeRequests()
                    .antMatchers(*PUBLIC_PATHS).permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
                    .and()
                    .addFilter(JwtAuthenticationFilter(authenticationManager()))
                    .addFilterBefore(
                            JwtAuthorizationFilter(authenticationManager(), userDetailsService),
                            UsernamePasswordAuthenticationFilter::class.java
                    )
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        }
    }
}
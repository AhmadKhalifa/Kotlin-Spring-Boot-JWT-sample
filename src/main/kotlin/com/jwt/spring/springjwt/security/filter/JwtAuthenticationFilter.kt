package com.jwt.spring.springjwt.security.filter

import com.fasterxml.jackson.databind.ObjectMapper
import com.jwt.spring.springjwt.model.Credentials
import com.jwt.spring.springjwt.security.util.HEADER_STRING
import com.jwt.spring.springjwt.security.util.JwtTokenUtil
import com.jwt.spring.springjwt.security.util.TOKEN_PREFIX
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtAuthenticationFilter(private val authManager: AuthenticationManager)
    : UsernamePasswordAuthenticationFilter() {

    override fun attemptAuthentication(request: HttpServletRequest?, response: HttpServletResponse?): Authentication {
        val credentials = ObjectMapper().readValue(request?.inputStream, Credentials::class.java)
        return authManager.authenticate(UsernamePasswordAuthenticationToken(
                credentials.username,
                credentials.password
        ))
    }

    override fun successfulAuthentication(
            request: HttpServletRequest?,
            response: HttpServletResponse?,
            chain: FilterChain?,
            authResult: Authentication?
    ) {
        (authResult?.principal as? User)?.username?.let { username ->
            response?.addHeader(HEADER_STRING, "$TOKEN_PREFIX ${JwtTokenUtil.generateToken(username)}")
        }
    }
}

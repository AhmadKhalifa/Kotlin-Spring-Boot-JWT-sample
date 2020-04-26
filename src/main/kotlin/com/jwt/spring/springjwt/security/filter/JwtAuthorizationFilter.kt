package com.jwt.spring.springjwt.security.filter

import com.jwt.spring.springjwt.security.util.HEADER_STRING
import com.jwt.spring.springjwt.security.util.JwtTokenUtil
import com.jwt.spring.springjwt.security.util.Role
import com.jwt.spring.springjwt.security.util.TOKEN_PREFIX
import com.jwt.spring.springjwt.util.error
import com.jwt.spring.springjwt.util.info
import com.jwt.spring.springjwt.util.warn
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.SignatureException
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtAuthorizationFilter(
        authenticationManager: AuthenticationManager,
        private val userDetailsService: UserDetailsService
) : BasicAuthenticationFilter(authenticationManager) {

    override fun doFilterInternal(
            request: HttpServletRequest,
            response: HttpServletResponse,
            filterChain: FilterChain
    ) {
        val header = request.getHeader(HEADER_STRING)
        var username: String? = null
        var token: String? = null
        if (!header.isNullOrEmpty() && header.startsWith(TOKEN_PREFIX)) {
            token = header.replace(TOKEN_PREFIX, "")
            try {
                username = JwtTokenUtil.getUsernameFromToken(token)
            } catch (exception: IllegalArgumentException) {
                error("Error getting username from token $token", exception)
            } catch (exception: ExpiredJwtException) {
                warn("The token $token is expired and not valid anymore", exception)
            } catch (exception: SignatureException) {
                error("Authorization failed", exception)
            }
        } else {
            warn("Couldn't find Bearer string, will ignore this header")
        }
        if (username != null && token != null && SecurityContextHolder.getContext().authentication != null) {
            val userDetails = userDetailsService.loadUserByUsername(username)
            if (JwtTokenUtil.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        listOf(SimpleGrantedAuthority(Role.ADMIN))
                ).let { authentication ->
                    authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
                    info("Authenticated user $username, setting security context")
                    SecurityContextHolder.getContext().authentication = authentication
                }
            }
        }
        filterChain.doFilter(request, response)
    }
}
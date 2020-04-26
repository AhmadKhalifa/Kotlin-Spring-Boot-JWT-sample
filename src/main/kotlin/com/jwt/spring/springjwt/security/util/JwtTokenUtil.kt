package com.jwt.spring.springjwt.security.util

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.io.Serializable
import java.util.*

object JwtTokenUtil : Serializable {

    @Value("\${signing.key}")
    lateinit var SIGNING_KEY: String
    private const val ACCESS_TOKEN_VALIDITY_MILLI_SEC = 5 * 60 * 60 * 1000.toLong()
    private const val KEY_SCOPES = "scopes"
    private const val ISSUER = "https://spring.io"

    fun getUsernameFromToken(token: String): String = getClaimFromToken(token, Claims::getSubject)

    private fun getExpirationDateFromToken(token: String) = getClaimFromToken(token, Claims::getExpiration)

    private fun <T> getClaimFromToken(token: String, claimsResolver: (Claims) -> T): T =
            claimsResolver(getAllClaimsFromToken(token))

    private fun getAllClaimsFromToken(token: String): Claims =
            Jwts.parser().setSigningKey(SIGNING_KEY).parseClaimsJws(token).body

    private fun isTokenExpired(token: String) = getExpirationDateFromToken(token).before(Date())

    fun validateToken(token: String, user: UserDetails) =
            !isTokenExpired(token) && getUsernameFromToken(token) == user.username

    fun generateToken(username: String): String = Jwts.builder()
            .setClaims(
                    Jwts.claims().setSubject(username).apply {
                        put(KEY_SCOPES, listOf(SimpleGrantedAuthority(Role.ADMIN)))
                    }
            )
            .setIssuer(ISSUER)
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDITY_MILLI_SEC))
            .signWith(SignatureAlgorithm.ES256, SIGNING_KEY)
            .compact()
}
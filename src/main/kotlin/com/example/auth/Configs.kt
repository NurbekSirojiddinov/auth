package com.example.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.fasterxml.jackson.databind.ObjectMapper
import lombok.extern.slf4j.Slf4j
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Slf4j
class CustomAuthorizationFilter : OncePerRequestFilter() {
    @Throws(ServletException::class, IOException::class)
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        if (request.servletPath == "/api/login" || request.servletPath == "/api/token/v1/refresh") {
            filterChain.doFilter(request, response)
        } else {
            val authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION)
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                try {
                    val token = authorizationHeader.substring("Bearer ".length)
                    val algorithm = Algorithm.HMAC256("password".toByteArray())
                    val verifier: JWTVerifier = JWT.require(algorithm).build()
                    val decodedJWT: DecodedJWT = verifier.verify(token)
                    val username: String = decodedJWT.subject
                    val roles: Array<String> = decodedJWT.getClaim("roles").asArray<String>(
                        String::class.java
                    )
                    val authorities: MutableCollection<SimpleGrantedAuthority> = ArrayList<SimpleGrantedAuthority>()
                    Arrays.stream(roles).forEach { role: String? -> authorities.add(SimpleGrantedAuthority(role)) }
                    val authenticationToken = UsernamePasswordAuthenticationToken(username, null, authorities)
                    SecurityContextHolder.getContext().authentication = authenticationToken
                    filterChain.doFilter(request, response)
                } catch (exception: Exception) {
                    logger.error("Error logging in : {}", exception)
                    exception(response, exception)
                }
            } else {
                filterChain.doFilter(request, response)
            }
        }
    }

    companion object {
        @Throws(IOException::class)
        fun exception(response: HttpServletResponse, exception: Exception) {
            response.setHeader("error", exception.message)
            response.status = HttpStatus.FORBIDDEN.value()
            val error: MutableMap<String, String?> = HashMap()
            error["error_message"] = exception.message
            response.contentType = MediaType.APPLICATION_JSON_VALUE
            ObjectMapper().writeValue(response.outputStream, error)
        }
    }
}
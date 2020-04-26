package com.jwt.spring.springjwt.service

import com.jwt.spring.springjwt.repository.UserRepository
import com.jwt.spring.springjwt.security.util.Role
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import com.jwt.spring.springjwt.model.User as UserDto

@Service
class UserService(/*private val userRepository: UserRepository*/) : UserDetailsService {

    companion object {

        const val QUALIFIER = "userService"
    }

    private val authority: List<SimpleGrantedAuthority>
        get() = listOf(SimpleGrantedAuthority(Role.ADMIN))

    override fun loadUserByUsername(username: String?) = /*username?.run(userRepository::findByUsername)?.let { userDto ->
        User(userDto.username, userDto.password, authority)
    } ?:*/ throw UsernameNotFoundException("Invalid username")

    fun register(user: UserDto): Mono<UserDto> = Mono.empty() // userRepository.save(user)
}
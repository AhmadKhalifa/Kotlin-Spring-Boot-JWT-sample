package com.jwt.spring.springjwt.controller

import com.jwt.spring.springjwt.model.User
import com.jwt.spring.springjwt.service.UserService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/user")
class UserController(private val userService: UserService, private val bCryptPasswordEncoder: BCryptPasswordEncoder) {

    @PostMapping("/register")
    fun register(@RequestBody user: User) =
            userService.register(user.apply { password = bCryptPasswordEncoder.encode(password) })
}
package com.jwt.spring.springjwt.repository

import com.jwt.spring.springjwt.model.User
import org.springframework.data.mongodb.repository.ReactiveMongoRepository

interface UserRepository : ReactiveMongoRepository<User, Long> {

    fun findByUsername(username: String): User?
}
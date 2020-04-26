package com.jwt.spring.springjwt

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication

@SpringBootApplication
open class SpringJwtApplication

fun main(args: Array<String>) {
    SpringApplication.run(SpringJwtApplication::class.java, *args)
}
package com.jwt.spring.springjwt.model

import com.fasterxml.jackson.annotation.JsonIgnore
import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.index.Indexed
import org.springframework.data.mongodb.core.mapping.Document

@Document
class User(
        @Id var id: Long = -1,
        @Indexed(unique = true) var username: String? = null,
        @JsonIgnore var password: String? = null,
        var age: Int = -1
)
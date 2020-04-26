package com.jwt.spring.springjwt.util

import org.slf4j.Logger
import org.slf4j.LoggerFactory

private val loggerMap = hashMapOf<Class<*>, Logger>()

fun getLogger(clazz: Class<*>): Logger = loggerMap[clazz]
        ?: LoggerFactory.getLogger(clazz).also { logger -> loggerMap[clazz] = logger }

inline fun <reified T : Any> T.info(message: String?) =
        getLogger(T::class.java).info(message ?: "")

inline fun <reified T : Any> T.debug(message: String?) =
        getLogger(T::class.java).debug(message ?: "")

inline fun <reified T : Any> T.warn(message: String?, throwable: Throwable? = null) =
        getLogger(T::class.java).warn(message ?: "", throwable)

inline fun <reified T : Any> T.error(message: String?, throwable: Throwable? = null) =
        getLogger(T::class.java).error(message ?: "", throwable)

inline fun <reified T : Any> T.trace(message: String?) =
        getLogger(T::class.java).trace(message ?: "")
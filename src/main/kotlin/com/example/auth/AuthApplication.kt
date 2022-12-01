package com.example.auth

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cloud.netflix.eureka.EnableEurekaClient

@EnableEurekaClient
@SpringBootApplication
class AuthApplication

fun main(args: Array<String>) {
    runApplication<AuthApplication>(*args)
}

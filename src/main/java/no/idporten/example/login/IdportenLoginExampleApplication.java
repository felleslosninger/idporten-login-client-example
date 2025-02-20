package no.idporten.example.login;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
@ConfigurationPropertiesScan
public class IdportenLoginExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdportenLoginExampleApplication.class, args);
    }
}

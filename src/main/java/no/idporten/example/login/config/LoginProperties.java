package no.idporten.example.login.config;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.URI;

@Validated
@ConfigurationProperties(prefix = "login-application")
public record LoginProperties(
    @NotNull URI baseUri,
    @NotNull RpProperties rp,
    @NotNull OpProperties op
) {

    public record RpProperties(
        @NotNull ServiceProperties service,
        @NotNull WebProperties web
    ) {

        @ConfigurationProperties(prefix = "login-application.rp.service")
        public record ServiceProperties(
            @NotNull ClientID clientID,
            @NotNull Secret clientSecret
        ) {}

        @ConfigurationProperties(prefix = "login-application.rp.web")
        public record WebProperties(
            @NotNull URI redirectUri
        ) {}
    }

    @ConfigurationProperties(prefix = "login-application.op")
    public record OpProperties(
        @NotNull Issuer issuer
    ) {}
}

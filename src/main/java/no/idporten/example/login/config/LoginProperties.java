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
    @NotNull ClientProperties client,
    @NotNull OpProperties op
) {

    public record ClientProperties(
        @NotNull ClientID clientID,
        @NotNull Secret clientSecret,
        @NotNull URI redirectUri
    ) {}

    public record OpProperties(
        @NotNull Issuer issuer
    ) {}
}

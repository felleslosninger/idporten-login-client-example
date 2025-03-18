package no.idporten.example.login.config;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoginConfiguration {

    private final LoginProperties.OpProperties opProperties;

    public LoginConfiguration(LoginProperties.OpProperties opProperties) {
        this.opProperties = opProperties;
    }

    @Bean
    public OIDCProviderMetadata getOidcProviderMetaData() throws Exception {
        // TODO: timeout?
        return OIDCProviderMetadata.resolve(opProperties.issuer());
    }
}

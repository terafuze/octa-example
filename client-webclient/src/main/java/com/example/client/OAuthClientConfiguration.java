package com.example.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class OAuthClientConfiguration {

  private final Logger log = LoggerFactory.getLogger(OAuthClientConfiguration.class);

    @Bean
    ReactiveClientRegistrationRepository clientRegistrations(
            @Value("${spring.security.oauth2.client.provider.okta.token-uri}") String token_uri,
            @Value("${spring.security.oauth2.client.registration.okta.client-id}") String client_id,
            @Value("${spring.security.oauth2.client.registration.okta.client-secret}") String client_secret,
            @Value("${spring.security.oauth2.client.registration.okta.scope}") String scope,
            @Value("${spring.security.oauth2.client.registration.okta.authorization-grant-type}") String authorizationGrantType

    ) {
      log.info("Token URI: {}", token_uri);
      log.info("Client ID: {}", client_id);
      log.info("Client Secret: {}", client_secret);
      log.info("Scope: {}", scope);;
      log.info("Authorization Grant Type: {}", authorizationGrantType);
        ClientRegistration registration = ClientRegistration
                .withRegistrationId("okta")
                .tokenUri(token_uri)
                .clientId(client_id)
                .clientSecret(client_secret)
                .scope(scope)
                .authorizationGrantType(new AuthorizationGrantType(authorizationGrantType))
                .build();
        return new InMemoryReactiveClientRegistrationRepository(registration);
    }

    @Bean
    WebClient webClient(ReactiveClientRegistrationRepository clientRegistrations) {
        
        InMemoryReactiveOAuth2AuthorizedClientService clientService = new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrations);
        
        AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(clientRegistrations, clientService);
        
        ServerOAuth2AuthorizedClientExchangeFilterFunction oauth = new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        
        oauth.setDefaultClientRegistrationId("okta");
        
        WebClient webClient = WebClient
            .builder()
            .filter(oauth)
            .filter(WebClientFilter.logRequest())
            .build();
        
        log.info("Okta Web Client: {}", webClient);
        return webClient;
    }

}

package it.itsacademy.ordiniepagamentigateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity // Simile a EnableWebSecurity ma per web flux
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtFilter jwtFilter;

    // Siccome stiamo usando web flux dobbiamo usare SecurityWebFilterChain invece che una SecurityFilterChain normale
    @Bean
    public SecurityWebFilterChain securityFilterChain(
            ServerHttpSecurity http // DI grazie a EnableWebFluxSecurity
    ) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange( // Differente da quello di mvc che è authorizeHttpRequests
                        e -> e.pathMatchers("/api/auth/**").permitAll() // invece di requestMatchers
                                .anyExchange().authenticated()
                )

                /*
                In WebFlux, il salvataggio del contesto di sicurezza è gestito da un componente chiamato ServerSecurityContextRepository.
                Per dire a Spring di non salvare mai il contesto nella sessione (l'equivalente esatto di SessionCreationPolicy.STATELESS),
                dobbiamo impostare questo repository su NoOpServerSecurityContextRepository
                */
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())

                // Usiamo addFilterAt. Sostanzialmente nel nostro caso non ci sta nessuna differenza con addFilterBefore.
                // In questo caso diciamo "esegui il filtro esattamente durante l'autenticazione". Nell'altro dicevamo
                // "eseguilo un attimo prima dell'autenticazione". Se non abbiamo altri filtri non c'è differenza.
                .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
}

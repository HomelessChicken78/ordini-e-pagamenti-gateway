package it.itsacademy.ordiniepagamentigateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collections;

@Component
@RequiredArgsConstructor
public class JwtFilter implements WebFilter {
    private final JwtService jwtService;

    /*
     Nella programmazione tradizionale, un metodo "blocca" il server finché non ha un
     risultato da restituire (es. "Utente"). In WebFlux (che è reattivo), non si blocca mai nulla.
     "Mono" è un oggetto che rappresenta una promessa asincrona di avere al massimo UN (1)
     risultato nel futuro. È come il cerca-persone che ti danno al fast food: il server
     ti dà il Mono e va a servire altri clienti; quando il risultato sarà pronto, il Mono
     "suonerà" per consegnartelo.
     Al momento il Mono non fa nulla, ma successivamente Spring si "iscrive" a quel Mono,
     ovvero esegue le sue istruzioni.
     PERCHÉ "MONO<VOID>"?
     "Void" significa "nessun tipo di dato". Quindi Mono<Void> è una promessa speciale
     che dice: "Farò il mio lavoro in background, ma quando avrò finito non ti restituirò
     nessun oggetto. Ti avviserò semplicemente che l'operazione è completata con successo".
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String jwt = estraiTokenDallaExchange(exchange);

        // Controlla che il parser non sia fallito e che sia validato
        if (jwt != null && jwtService.validateToken(jwt)) {
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    jwtService.extractUsername(jwt),
                    null,
                    Collections.emptyList()
            );

            // Continua la catena ma con nel contesto di sicurezza metti l'autenticazione
            // (guarda sotto per la spiegazione di "return chain.filter(exchange);
            return chain.filter(exchange)
                    .contextWrite(
                            ReactiveSecurityContextHolder.withAuthentication(auth)
                    );
        }

        // Passiamo la richiesta al filtro successivo.
        // Dobbiamo ritornare il suo risultato invece di chiamarlo e basta perchè in WebFlux,
        // chiamare un metodo non esegue il codice, ma si limita a creare un oggetto (il Mono)
        // che contiene le istruzioni da eseguire.
        // Usando "return" appiccichiamo (senza eseguirle) le istruzioni dei filtri successivi e lo ritorniamo al filtro prima.
        // Se prima non vi sono filtri, si consegna il Mono finale a Spring che si occuperà di eseguirle. Se omettiamo il "return",
        // l'oggetto viene cancellato dalla memoria di Java, le istruzioni vanno perse
        // e la richiesta HTTP si blocca senza dare risposta al client.
        // FiltroC ritorna l'istruzione di printare "3" a FiltroB. FiltroB aggiunge un'istruzione (printa "2") e passa
        // le due istruzioni a filtroA. FiltroA aggiunge un'istruzione (printa "1") e ritorna le azioni a spring.
        // Spring legge il Mono finale che contiene tutte e tre le istruzioni e le esegue
        return chain.filter(exchange);
    }

    // Metodo che estrae il token dalla richiesta http, ignorando il resto
    private String estraiTokenDallaExchange(ServerWebExchange exchange) {
        // L'oggetto exchange contiene sia la request che la response.
        // La request di web flux è più complessa. Dobbiamo accedere a tutti gli oggetti e cercare il primo
        // "Authorization"
        String headerAuth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // StringUtils.hasText controlla che l'header esista e non sia vuoto.
        // Il metodo "startsWith" delle stringhe controlla invece che inizia con "Bearer ".
        // Esistono vari metodi per autenticarsi sul web (es. "Basic" per le password classiche).
        // La parola "Bearer " indica che a seguire sarà indicato chi è il portatore del token.
        // La stringa headerAuth è dunque "Bearer 324uiyebttbedashj7287b"
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            // Ci interessa solo sapere 324uiyebttbedashj7287b di headerAuth, non ci interessa di "Bearer ".
            // Il comando substring(7) ordina a Java di tagliare via i primi 7 caratteri,
            // ovvero quelli corrispondenti alla parola "Bearer ".
            return headerAuth.substring(7);
        }

        // Nel caso le condizioni non si verificano, ritorna null.
        return null;
    }
}
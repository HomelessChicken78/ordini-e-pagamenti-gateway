package it.itsacademy.ordiniepagamentigateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtFilter implements WebFilter {
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
}
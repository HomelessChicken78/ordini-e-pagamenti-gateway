package it.itsacademy.ordiniepagamentigateway.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Key;

public class JwtServiceImpl implements JwtService {
    // Questa variabile ospita la chiave segreta (una stringa di testo apparentemente casuale)
    // definita nel file "application.properties". È la password segreta del server.
    @Value("${security.jwt.secret-key}")
    private String secretKey;

    /**
     * Metodo che riceve il token e restituisce il nome utente scritto al suo interno.
     */
    // Il jwt è una stringa separata da tre punti "." per poter dividere il token in tre punti.
    // Il primo contiene l'header che contiene diversi meta tag (che si tratta di un jwt, quale algoritmo usa ecc.)
    // Il secondo contiene i veri dati come il subject (l'utente), e le authorities.
    // Il terzo blocco contiene la firma. Il server possiede una chiave jwt segreta, grazie alla quale codifica
    // il messaggio della seconda parte e ottiene una firma. Se la firma attesa e quella scritta non corrispondono
    // il messaggio è stato manomesso.
    // Poichè il token contiene i dati veri e non ha meccanismi di sicurezza per la lettura
    // (ne ha solo per prevenire che venga modificato da malintenzionati), può essere letto da chiunque.
    // Per questo motivo non si mettono dati come la password all'interno del token.
    @Override
    public String extractUsername(String jwt) {
        // La chiave segreta nel file di configurazione è salvata in formato Base64
        // (un sistema che trasforma i dati binari in testo leggibile).
        // L'algoritmo crittografico non può usare il testo puro, ha bisogno dei byte originali.
        // Questo prende la stringa di testo e la riconverte in un array di byte grezzi.
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);

        // Prende l'array di byte appena generato e lo trasforma in un oggetto "Key" ufficiale di Java,
        // configurandolo specificamente per l'algoritmo HMAC (il sistema matematico che gestisce le firme).
        Key key = Keys.hmacShaKeyFor(keyBytes);

        // Inizia il builder per configurare il lettore di token.
        return Jwts.parserBuilder()
                // Mette la chiave segreta appena creata. Quest'ultima verrà usata
                // per ricalcolare la firma del token e verificare che nessuno lo abbia manomesso.
                .setSigningKey(key)
                .build()

                // Analizza la stringa del token. In questa riga avviene il vero controllo di sicurezza:
                // la libreria prende la firma in fondo al token e la confronta con la chiave segreta.
                // Se il token è falso o alterato, il programma si blocca immediatamente lanciando un'eccezione.
                .parseClaimsJws(jwt)

                // Se la firma è valida, questo comando estrae il "Body",
                // ovvero la sezione centrale del token che contiene la mappa con tutti i dati dell'utente.
                .getBody()

                // All'interno dei dati, cerca il campo standard chiamato "Subject".
                // Per convenzione internazionale, in questo campo si inserisce l'identificativo unico
                // dell'utente, che nel nostro caso corrisponde all'username o all'email.
                .getSubject();
    }

    /**
     * Metodo che verifica se il token appartiene all'utente corretto e se è ancora utilizzabile.
     */
    @Override
    public boolean validateToken(String jwt) {
        try {
            // Il metodo Jwts.parserBuilder() già controlla la chiave e che il token non sia scaduto
            extractUsername(jwt);
            return true;
        } catch (Throwable e) {return false;}
    }
}

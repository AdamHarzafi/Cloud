const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
const helmet = require('helmet'); // Per header di sicurezza

const app = express();
const PORT = 5500;

// Middleware di sicurezza Helmet (imposta vari header HTTP per la sicurezza)
app.use(helmet()); 

// Content Security Policy (CSP) di base - Personalizzala attentamente per le tue esigenze!
// Questa è una CSP permissiva per una demo; in produzione, rendila più restrittiva.
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdnjs.cloudflare.com", "'unsafe-inline'"], // unsafe-inline potrebbe essere necessario per script inline, ma è meno sicuro
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https://images.unsplash.com", "blob:"], // Aggiunto blob: per Cropper.js se usa URL blob per anteprime
      connectSrc: ["'self'", `http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`], // Permetti connessioni al tuo server
      formAction: ["'self'"],
    },
  })
);

// Altri Middleware essenziali
app.use(cors({ // Configurazione CORS più specifica (opzionale per sviluppo locale semplice)
  origin: `http://localhost:${PORT}`, // O l'origine da cui servi il frontend
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Middleware di logging globale per tutte le richieste (posizionato presto)
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`[SERVER LOG] ${req.method} ${req.originalUrl} - ${res.statusCode} [${duration}ms]`);
    });
    // Log dettagliato per il debug specifico della rotta problematica
    if (req.originalUrl === '/request-otp') {
        console.log(`[SERVER LOG - /request-otp] Headers: ${JSON.stringify(req.headers, null, 2)}`);
        if (req.body && Object.keys(req.body).length > 0) {
            console.log(`[SERVER LOG - /request-otp] Body: ${JSON.stringify(req.body, null, 2)}`);
        }
    }
    next();
});


const dbDir = path.join(__dirname, 'var', 'db');
if (!fs.existsSync(dbDir)){
    fs.mkdirSync(dbDir, { recursive: true });
    console.log(`Cartella per database sessioni creata: ${dbDir}`);
}

// Configurazione Sessione
const isProduction = process.env.NODE_ENV === 'production';
app.use(session({
    store: new SQLiteStore({ db: 'sessions.db', dir: dbDir, table: 'sessions', concurrentDB: true }),
    secret: process.env.SESSION_SECRET || 'una-chiave-segreta-molto-piu-robusta-e-lunga-per-la-produzione!', // Usa variabile d'ambiente per la secret
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: isProduction, // true solo se HTTPS
        httpOnly: true, 
        sameSite: 'Lax', 
        maxAge: 1000 * 60 * 60 * 24 * 7 // 7 giorni
    }
}));


// --- Storage In-Memory per gli utenti (SOLO PER DEMO!) ---
const users = [];
(async () => {
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash("passwordValida123!", saltRounds); // Password di test più forte
    users.push({
        id: "testadam1", // Usa crypto.randomUUID() per nuovi utenti reali
        firstName: "Adam",
        lastName: "Test",
        email: "allorasonoadam@gmail.com",
        password: hashedPassword,
        country: "Italia",
        region: "Piemonte",
        dob: "1990-01-01",
        profilePicUrl: 'index.png'
    });
})();

const otpStore = {};
const OTP_EXPIRATION_MINUTES = 10; // Durata OTP in minuti

// --- Configurazione SendGrid ---
sgMail.setApiKey(process.env.SENDGRID_API_KEY || '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');
const SENDGRID_FROM_EMAIL = process.env.SENDGRID_FROM_EMAIL || 'LA_TUA_EMAIL_MITTENTE_VERIFICATA_SU_SENDGRID@example.com'; // CAMBIA QUESTO!


function requireLogin(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    } else {
        if (req.xhr || (req.headers.accept && req.headers.accept.includes('json'))) {
             return res.status(401).json({ success: false, message: 'Autenticazione richiesta.' });
        } else {
            return res.redirect('/accedi.html'); // Assicurati che 'accedi.html' sia il nome corretto
        }
    }
}

function generateOtp() {
  return crypto.randomInt(100000, 999999).toString();
}

// === DEFINIZIONE DI TUTTE LE ROTTE API ===
app.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, dob, email, password, country, region, profilePicUrl } = req.body;
        // Aggiungere validazione più robusta lato server per ogni campo
        if (!firstName || !lastName || !dob || !email || !password || !country) {
            return res.status(400).json({ success: false, message: 'Tutti i campi obbligatori devono essere compilati.' });
        }
        if (password.length < 8) { // Esempio di validazione aggiuntiva
            return res.status(400).json({ success: false, message: 'La password deve essere di almeno 8 caratteri.' });
        }
        const existingUser = users.find(user => user.email === email);
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'Utente già registrato con questa email.' });
        }
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const newUser = {
            id: crypto.randomUUID(),
            firstName, lastName, email,
            password: hashedPassword,
            country, region: region || null,
            dob,
            profilePicUrl: profilePicUrl || 'index.png'
        };
        users.push(newUser);
        console.log('[SERVER] Nuovo utente registrato:', newUser.email);
        res.status(201).json({ success: true, message: 'Registrazione avvenuta con successo!' });
    } catch (error) {
        console.error("[SERVER] ERRORE /register:", error);
        res.status(500).json({ success: false, message: 'Errore interno del server durante la registrazione.' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Inserisci email e password.' });
        }
        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(401).json({ success: false, message: 'Credenziali non valide.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Credenziali non valide.' });
        }
        
        req.session.regenerate(err => {
            if (err) {
                console.error("[SERVER] Errore rigenerazione sessione:", err);
                return res.status(500).json({ success: false, message: 'Errore di autenticazione.' });
            }
            req.session.userId = user.id;
            // Non memorizzare dati sensibili o che cambiano spesso direttamente in sessione se non necessario
            // req.session.userEmail = user.email; 
            // req.session.userName = user.firstName;
            
            req.session.save(saveErr => {
                if (saveErr) {
                    console.error("[SERVER] Errore salvataggio sessione:", saveErr);
                    return res.status(500).json({ success: false, message: 'Errore di autenticazione.' });
                }
                console.log('[SERVER] LOGIN SUCCESSO - Sessione per utente ID:', user.id);
                res.status(200).json({ success: true, message: 'Login effettuato con successo!', redirectTo: '/Harzafi%20Cloud.html' });
            });
        });

    } catch (error) {
        console.error("[SERVER] ERRORE /login:", error);
        res.status(500).json({ success: false, message: 'Errore interno del server durante il login.' });
    }
});

app.get('/api/user-info', requireLogin, (req, res) => {
    const user = users.find(u => u.id === req.session.userId);
    if (!user) {
        req.session.destroy(() => {}); // Distrugge la sessione se l'utente non esiste più
        return res.status(404).json({ success: false, message: 'Utente non trovato. Effettua nuovamente il login.' });
    }
    res.json({
        success: true,
        name: user.firstName,
        email: user.email,
        profilePicUrl: user.profilePicUrl || 'index.png'
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("[SERVER] Errore durante il logout:", err);
            return res.status(500).json({ message: 'Impossibile effettuare il logout.' });
        }
        res.clearCookie('connect.sid', { path: '/' }); 
        console.log('[SERVER] Logout effettuato.');
        if (req.xhr || (req.headers.accept && req.headers.accept.includes('json'))) {
            res.status(200).json({ success: true, message: "Logout effettuato con successo."});
        } else {
            res.redirect('/index.html');
        }
    });
});

// VERSIONE DI DEBUG per /request-otp (per isolare l'errore 405)
app.post('/request-otp', (req, res) => {
    console.log('[SERVER DEBUG] Rotta POST /request-otp RAGGIUNTA!');
    const email = req.body ? req.body.email : null;
    console.log('[SERVER DEBUG] Email ricevuta nel body:', email);
    
    if (!email) { // Aggiungere validazione email anche qui
        console.log('[SERVER DEBUG] Email non fornita o non valida nel body.');
        return res.status(400).json({ success: false, message: 'DEBUG: Email non fornita o non valida.' });
    }
    
    // Risposta di successo semplice per il test di routing
    res.status(200).json({ 
        success: true, 
        message: 'DEBUG: Richiesta POST a /request-otp gestita (versione di test). Controlla i log del server. Ora puoi decommentare la logica originale.' 
    });
});

/*
// LOGICA ORIGINALE /request-otp (DECOMMENTA E RIMUOVI QUELLA DI DEBUG QUANDO IL 405 È RISOLTO)
// ASSICURATI CHE SENDGRID_FROM_EMAIL SIA CONFIGURATO CORRETTAMENTE!
app.post('/request-otp', async (req, res) => {
    const { email } = req.body;
    // Aggiungere validazione email
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ success: false, message: 'Formato email non valido.' });
    }
    console.log(`[SERVER] Richiesta POST a /request-otp per email: ${email}`);
    const user = users.find(u => u.email === email);
    if (!user) {
        console.log(`[SERVER] Utente non trovato per email: ${email}. Invio risposta generica.`);
        return res.status(200).json({ success: true, message: 'Se l\'email è registrata, riceverai un codice OTP. Controlla la tua casella di posta, inclusa la cartella spam.' });
    }
    const otp = generateOtp();
    const expiresAt = Date.now() + OTP_EXPIRATION_MINUTES * 60 * 1000;
    otpStore[email] = { otp, expiresAt, verified: false };
    console.log(`[SERVER] OTP generato per ${email}: ${otp}`);

    const msg = {
        to: email,
        from: SENDGRID_FROM_EMAIL,
        subject: 'Il tuo codice di verifica per Harzafi Cloud',
        text: `Ciao ${user.firstName || 'utente'},\n\nIl tuo codice di verifica (OTP) per Harzafi Cloud è: ${otp}\nQuesto codice scade tra ${OTP_EXPIRATION_MINUTES} minuti.\n\nSe non hai richiesto tu questo codice, ignora questa email.\n\nGrazie,\nIl Team Harzafi Cloud`,
        html: `<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; padding: 20px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9;">... (HTML dell'email come prima) ...</div>`
    };

    try {
        if (!SENDGRID_FROM_EMAIL || SENDGRID_FROM_EMAIL === 'LA_TUA_EMAIL_MITTENTE_VERIFICATA_SU_SENDGRID@example.com') {
            console.error("[SERVER] ERRORE CRITICO: L'email mittente di SendGrid non è configurata!");
            return res.status(500).json({ success: false, message: 'Errore di configurazione del server per l\'invio email.' });
        }
        await sgMail.send(msg);
        console.log(`[SERVER] Email OTP inviata con successo a ${email}.`);
        res.status(200).json({ success: true, message: 'Se l\'email è registrata, riceverai un codice OTP. Controlla la tua casella di posta, inclusa la cartella spam.' });
    } catch (error) {
        console.error(`[SERVER] ERRORE invio email OTP a ${email}:`, JSON.stringify(error, Object.getOwnPropertyNames(error)));
        res.status(500).json({ success: false, message: 'Errore durante l\'invio dell\'email. Riprova più tardi.' });
    }
});
*/

app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp || !/^\d{6}$/.test(otp)) {
        return res.status(400).json({ success: false, message: 'Email o formato OTP non validi.' });
    }
    const storedOtpData = otpStore[email];
    if (!storedOtpData || Date.now() > storedOtpData.expiresAt) {
        if (storedOtpData) delete otpStore[email];
        return res.status(400).json({ success: false, message: 'Codice OTP non valido o scaduto. Richiedine uno nuovo.' });
    }
    if (storedOtpData.otp === otp) {
        otpStore[email].verified = true;
        otpStore[email].expiresAt = Date.now() + (5 * 60 * 1000); // 5 min per cambiare password
        res.status(200).json({ success: true, message: 'Codice OTP verificato. Ora puoi inserire la nuova password.' });
    } else {
        res.status(400).json({ success: false, message: 'Codice OTP errato.' });
    }
});

app.post('/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    // Aggiungere validazione robusta per newPassword qui
    if (!email || !otp || !newPassword || newPassword.length < 8) { // Assicurati che i criteri corrispondano a quelli del client
        return res.status(400).json({ success: false, message: 'Dati mancanti, password non conforme ai criteri di robustezza o OTP non valido.' });
    }
    const storedOtpData = otpStore[email];
    if (!storedOtpData || storedOtpData.otp !== otp || !storedOtpData.verified || Date.now() > storedOtpData.expiresAt) {
        if (storedOtpData) delete otpStore[email];
        return res.status(400).json({ success: false, message: 'Richiesta non valida, OTP errato o sessione di reimpostazione scaduta.' });
    }
    const userIndex = users.findIndex(u => u.email === email);
    if (userIndex === -1) {
        delete otpStore[email];
        return res.status(404).json({ success: false, message: 'Utente non trovato.' });
    }
    try {
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        users[userIndex].password = hashedPassword;
        delete otpStore[email];
        console.log(`[SERVER] Password aggiornata per ${email}.`);
        res.status(200).json({ success: true, message: 'Password reimpostata con successo! Ora puoi accedere con la nuova password.' });
    } catch (error) {
        console.error(`[SERVER] Errore hashing nuova password per ${email}:`, error);
        res.status(500).json({ success: false, message: 'Errore interno durante l\'aggiornamento della password.' });
    }
});

// === IL MIDDLEWARE PER I FILE STATICI VA QUI, DOPO TUTTE LE ROTTE API ===
app.use(express.static(path.join(__dirname), {
    // etag: true, // Abilita ETag per il caching
    // lastModified: true, // Abilita Last-Modified header
    // cacheControl: true, // Abilita Cache-Control header
    // maxAge: '1d' // Esempio: cache per 1 giorno per file statici
}));

// Gestore per rotte non trovate (404)
app.use((req, res, next) => {
    const R_404_PAGE = path.join(__dirname, '404.html'); // Crea questa pagina!
    if (fs.existsSync(R_404_PAGE)) {
        res.status(404).sendFile(R_404_PAGE);
    } else {
        res.status(404).send("<html><body style='font-family: Poppins, sans-serif; text-align: center; padding-top: 50px; background-color: #0f172a; color: #f1f5f9;'><h1>404 - Pagina Non Trovata</h1><p>Spiacenti, la risorsa che stai cercando non è disponibile.</p><p><a href='/' style='color: #3A8DFF; text-decoration: none; font-weight: 600;'>Torna alla Homepage</a></p></body></html>");
    }
});

// Gestore di errori generico Express (deve avere 4 argomenti)
app.use((err, req, res, next) => {
    console.error("[SERVER ERRORE NON GESTITO]", err.message, err.stack);
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Si è verificato un errore interno al server.',
        // Includere lo stack trace solo in ambiente di sviluppo
        ...(process.env.NODE_ENV !== 'production' && { error: err.stack })
    });
});


// --- Avvio del Server ---
app.listen(PORT, () => {
    console.log(`\n🚀 Server Harzafi Cloud in ascolto su http://localhost:${PORT}`);
    console.log(`   Ambiente: ${process.env.NODE_ENV || 'development (default)'}`);
    if(process.env.NODE_ENV !== 'production') {
        console.warn("   ATTENZIONE: Server in esecuzione in modalità sviluppo. Non usare in produzione con questa configurazione.");
        console.warn("   RICORDA: La chiave segreta della sessione e la chiave API SendGrid dovrebbero essere gestite tramite variabili d'ambiente in produzione.");
    }
    console.log(`   Cartella principale per file statici: ${__dirname}`);
    console.log(`   Database sessioni SQLite in: ${path.join(dbDir, 'sessions.db')}`);
    console.log("------------------------------------------------------------\n");
});
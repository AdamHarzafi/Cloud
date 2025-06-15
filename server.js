const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const axios = require('axios'); // <-- NECESSARIO per la verifica reCAPTCHA

const app = express();
const PORT = 5500;

// Middleware di sicurezza Helmet (imposta vari header HTTP per la sicurezza)
app.use(helmet()); 

// AGGIORNATO: Content Security Policy (CSP) per permettere Google reCAPTCHA
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      // Aggiunti i domini di Google per gli script
      scriptSrc: ["'self'", "https://www.google.com", "https://www.gstatic.com", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https://images.unsplash.com", "blob:"],
      // Aggiunto il dominio di Google per l'iframe del widget reCAPTCHA
      frameSrc: ["'self'", "https://www.google.com"],
      connectSrc: ["'self'", `http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`],
      formAction: ["'self'"],
    },
  })
);

// Altri Middleware essenziali
app.use(cors({
  origin: `http://localhost:${PORT}`,
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Middleware di logging
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`[SERVER LOG] ${req.method} ${req.originalUrl} - ${res.statusCode} [${duration}ms]`);
    });
    next();
});

const dbDir = path.join(__dirname, 'var', 'db');
if (!fs.existsSync(dbDir)){
    fs.mkdirSync(dbDir, { recursive: true });
}

// Configurazione Sessione
const isProduction = process.env.NODE_ENV === 'production';
app.use(session({
    store: new SQLiteStore({ db: 'sessions.db', dir: dbDir, table: 'sessions', concurrentDB: true }),
    secret: process.env.SESSION_SECRET || 'una-chiave-segreta-molto-piu-robusta-e-lunga-per-la-produzione!',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: isProduction,
        httpOnly: true, 
        sameSite: 'Lax', 
        maxAge: 1000 * 60 * 60 * 24 * 7 // 7 giorni
    }
}));


// --- Storage In-Memory per gli utenti (SOLO PER DEMO!) ---
const users = [];
(async () => {
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash("passwordValida123!", saltRounds);
    users.push({
        id: "testadam1",
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

// Funzione di utility per le altre rotte
function requireLogin(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    } else {
        if (req.xhr || (req.headers.accept && req.headers.accept.includes('json'))) {
             return res.status(401).json({ success: false, message: 'Autenticazione richiesta.' });
        } else {
            return res.redirect('/accedi.html');
        }
    }
}

// =================================================================
// === ROTTA DI LOGIN COMPLETAMENTE IMPLEMENTATA CON RECAPTCHA =====
// =================================================================
app.post('/login', async (req, res) => {
    try {
        const { email, password, recaptchaToken } = req.body;

        // --- 1. VERIFICA RECAPTCHA ---
        if (!recaptchaToken) {
            return res.status(400).json({ success: false, message: 'Verifica reCAPTCHA mancante. Impossibile procedere.' });
        }
        
        // La tua chiave segreta è stata inserita qui
        const secretKey = '6LfzqWErAAAAAIb7Mg2BA96SkUhaanXIScZyYdtQ'; 
        
        const verificationURL = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaToken}&remoteip=${req.ip}`;

        // Chiamata al server di Google per la verifica
        const recaptchaResponse = await axios.post(verificationURL);
        
        // Controlla se la verifica è andata a buon fine
        if (!recaptchaResponse.data.success) {
            console.warn('Verifica reCAPTCHA fallita:', recaptchaResponse.data['error-codes']);
            return res.status(401).json({ success: false, message: 'Verifica di sicurezza (reCAPTCHA) fallita. Riprova.' });
        }
        console.log('Verifica reCAPTCHA superata con successo.');

        // --- 2. LOGICA DI LOGIN ESISTENTE (eseguita solo se reCAPTCHA è valido) ---
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
        
        // Se tutto è corretto, rigenera la sessione
        req.session.regenerate(err => {
            if (err) {
                console.error("[SERVER] Errore rigenerazione sessione:", err);
                return res.status(500).json({ success: false, message: 'Errore di autenticazione.' });
            }
            req.session.userId = user.id;
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
        // Gestione errori specifici e generici
        if (error.isAxiosError) {
             console.error("[SERVER] Errore durante la verifica reCAPTCHA con Google:", error.message);
             return res.status(500).json({ success: false, message: 'Errore del server durante la verifica di sicurezza.' });
        }
        console.error("[SERVER] ERRORE /login:", error);
        res.status(500).json({ success: false, message: 'Errore interno del server durante il login.' });
    }
});


// === ALTRE ROTTE (INVARIATE) ===
app.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, dob, email, password, country, region, profilePicUrl } = req.body;
        if (!firstName || !lastName || !dob || !email || !password || !country) {
            return res.status(400).json({ success: false, message: 'Tutti i campi obbligatori devono essere compilati.' });
        }
        if (password.length < 8) {
            return res.status(400).json({ success: false, message: 'La password deve essere di almeno 8 caratteri.' });
        }
        const existingUser = users.find(user => user.email === email);
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'Utente già registrato con questa email.' });
        }
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const newUser = {
            id: crypto.randomUUID(), firstName, lastName, email, password: hashedPassword,
            country, region: region || null, dob, profilePicUrl: profilePicUrl || 'index.png'
        };
        users.push(newUser);
        console.log('[SERVER] Nuovo utente registrato:', newUser.email);
        res.status(201).json({ success: true, message: 'Registrazione avvenuta con successo!' });
    } catch (error) {
        console.error("[SERVER] ERRORE /register:", error);
        res.status(500).json({ success: false, message: 'Errore interno del server durante la registrazione.' });
    }
});

app.get('/api/user-info', requireLogin, (req, res) => {
    const user = users.find(u => u.id === req.session.userId);
    if (!user) {
        req.session.destroy(() => {});
        return res.status(404).json({ success: false, message: 'Utente non trovato. Effettua nuovamente il login.' });
    }
    res.json({
        success: true, name: user.firstName, email: user.email,
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


// === SERVIRE FILE STATICI E GESTIONE ERRORI ===
app.use(express.static(path.join(__dirname)));

app.use((req, res, next) => {
    const R_404_PAGE = path.join(__dirname, '404.html');
    if (fs.existsSync(R_404_PAGE)) {
        res.status(404).sendFile(R_404_PAGE);
    } else {
        res.status(404).send("<html><body style='font-family: Poppins, sans-serif; text-align: center; padding-top: 50px; background-color: #0f172a; color: #f1f5f9;'><h1>404 - Pagina Non Trovata</h1><p>Spiacenti, la risorsa che stai cercando non è disponibile.</p><p><a href='/' style='color: #3A8DFF; text-decoration: none; font-weight: 600;'>Torna alla Homepage</a></p></body></html>");
    }
});

app.use((err, req, res, next) => {
    console.error("[SERVER ERRORE NON GESTITO]", err.message, err.stack);
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Si è verificato un errore interno al server.',
    });
});


// === AVVIO DEL SERVER ===
app.listen(PORT, () => {
    console.log(`\n🚀 Server Harzafi Cloud in ascolto su http://localhost:${PORT}`);
    console.log(`   Ambiente: ${process.env.NODE_ENV || 'development (default)'}`);
});

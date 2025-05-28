const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session); // Importa connect-sqlite3
const cors = require('cors');
const path = require('path');
const fs = require('fs'); // File System module, per creare la directory se non esiste

const app = express();
const PORT = 5500;

// --- Storage In-Memory per gli utenti (SOLO PER DEMO!) ---
// Per la persistenza degli utenti, dovresti usare un database anche per loro.
const users = [];
// ---------------------------------------------------------

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Creazione della directory per il database delle sessioni, se non esiste
const dbDir = path.join(__dirname, 'var', 'db');
if (!fs.existsSync(dbDir)){
    fs.mkdirSync(dbDir, { recursive: true });
    console.log(`Cartella per database sessioni creata: ${dbDir}`);
}

// Configurazione Sessioni con SQLiteStore
app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db', // Nome del file del database SQLite
        dir: dbDir,        // Cartella dove salvare il file
        table: 'sessions', // Nome della tabella nel database (opzionale, default 'sessions')
        concurrentDB: true // Opzione per gestire meglio accessi concorrenti a SQLite
    }),
    secret: 'la-tua-chiave-segreta-molto-difficile-cambiala-per-produzione!', // CAMBIARE IN PRODUZIONE!
    resave: false, // Non risalvare la sessione se non è stata modificata
    saveUninitialized: false, // Non creare sessioni finché qualcosa non viene memorizzato (buona pratica)
    cookie: {
        secure: false, // Imposta a 'true' se usi HTTPS
        httpOnly: true, // Il cookie non è accessibile tramite JavaScript lato client
        sameSite: 'lax', // Protezione base contro CSRF
        maxAge: 1000 * 60 * 60 * 24 * 7 // Opzionale: durata del cookie (es. 7 giorni)
    }
}));

// Serve i file statici (HTML, CSS, Immagini)
// Assicurati che index.html (landing) sia servito correttamente per la root '/'
app.use(express.static(path.join(__dirname)));

// --- Funzione Middleware per proteggere le rotte ---
function requireLogin(req, res, next) {
    console.log('--- REQUIRELOGIN ---');
    console.log('Tentativo di accesso a:', req.originalUrl);
    console.log('Sessione attuale (req.session):', JSON.stringify(req.session, null, 2));
    console.log('Session ID attuale (req.sessionID):', req.sessionID);

    if (req.session && req.session.userId) {
        console.log('Accesso autorizzato da requireLogin per utente ID:', req.session.userId);
        return next(); // Utente loggato, procedi
    } else {
        console.log('Accesso NON autorizzato da requireLogin.');
        if (req.xhr || (req.headers.accept && req.headers.accept.includes('json'))) {
             console.log('Rispondo con 401 JSON.');
             return res.status(401).json({ success: false, message: 'Devi effettuare il login per accedere.' });
        } else {
            console.log('Rispondo con redirect a /accedi.html.'); // MODIFICATO QUI
            return res.redirect('/accedi.html'); // MODIFICATO QUI
        }
    }
}

// --- Rotte API ---

// Registrazione
app.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, dob, email, password, country, region } = req.body;
        console.log('--- REGISTRAZIONE ---');
        console.log('Dati ricevuti per registrazione:', req.body);

        if (!email || !password || !firstName) {
            return res.status(400).json({ success: false, message: 'Per favore, compila tutti i campi obbligatori.' });
        }
        const existingUser = users.find(user => user.email === email);
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'Utente già registrato con questa email.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: Date.now().toString(),
            firstName, lastName, email,
            password: hashedPassword,
            country, region, dob
        };
        users.push(newUser);
        console.log('Nuovo utente registrato (in memoria):', newUser.email);
        res.status(201).json({ success: true, message: 'Registrazione avvenuta con successo!' });
    } catch (error) {
        console.error("SERVER ERRORE durante /register:", error);
        res.status(500).json({ success: false, message: 'Errore interno del server.' });
    }
});

// Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('--- LOGIN ---');
        console.log('Tentativo di login per email:', email);

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Inserisci email e password.' });
        }
        const user = users.find(u => u.email === email);
        if (!user) {
            console.log('Login fallito: utente non trovato.', email);
            return res.status(401).json({ success: false, message: 'Email o password non corretti.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Login fallito: password non corretta per utente', email);
            return res.status(401).json({ success: false, message: 'Email o password non corretti.' });
        }

        req.session.userId = user.id;
        req.session.userEmail = user.email;
        req.session.userName = user.firstName;

        req.session.save(err => {
            if (err) {
                console.error('SERVER ERRORE durante il salvataggio della sessione in /login:', err);
                return res.status(500).json({ success: false, message: 'Errore nel salvataggio della sessione.' });
            }
            console.log('LOGIN SUCCESSO - Sessione creata e salvata per utente:', user.email);
            console.log('Sessione (req.session):', JSON.stringify(req.session, null, 2));
            console.log('Session ID (req.sessionID):', req.sessionID);
            res.status(200).json({ success: true, message: 'Login effettuato con successo!', redirectTo: '/Harzafi%20Cloud.html' });
        });

    } catch (error) {
        console.error("SERVER ERRORE durante /login:", error);
        res.status(500).json({ success: false, message: 'Errore interno del server.' });
    }
});

// Get user information
app.get('/api/user-info', requireLogin, (req, res) => {
    console.log('--- API USER-INFO ---');
    console.log('Accesso autorizzato per /api/user-info. Sessione utente:', JSON.stringify(req.session, null, 2));
    if (req.session.userName && req.session.userEmail) {
        res.json({
            success: true,
            name: req.session.userName,
            email: req.session.userEmail
        });
    } else {
        console.warn('/api/user-info: requireLogin superato ma dati sessione userName/userEmail mancanti.');
        res.status(404).json({ success: false, message: 'Informazioni utente non complete nella sessione.' });
    }
});

// Logout
app.get('/logout', (req, res) => {
    console.log('--- LOGOUT ---');
    console.log('Sessione prima del logout (req.session):', JSON.stringify(req.session, null, 2));
    req.session.destroy(err => {
        if (err) {
            console.error('SERVER ERRORE durante session.destroy() in /logout:', err);
            return res.status(500).json({ message: 'Impossibile effettuare il logout.' });
        }
        res.clearCookie('connect.sid'); 
        console.log('Sessione distrutta e cookie pulito. Reindirizzamento a /index.html (landing page).');
        res.redirect('/index.html'); // MODIFICATO QUI per puntare alla nuova landing page
    });
});


// --- Avvio del Server ---
app.listen(PORT, () => {
    console.log(`🚀 Server Harzafi Cloud in ascolto su http://localhost:${PORT}`);
    console.log(`Le sessioni verranno salvate in: ${path.join(dbDir, 'sessions.db')}`);
});


// In server.js
const cookieSession = require('cookie-session');
// const session = require('express-session'); // Non più necessario se usi cookie-session
// const SQLiteStore = require('connect-sqlite3')(session); // Non più necessario

// ... altro codice express ...

app.use(
  cookieSession({
    name: 'harzafi-session', // Nome del cookie
    keys: [process.env.SESSION_SECRET_KEY1 || 'una_chiave_molto_segreta_per_firmare1', process.env.SESSION_SECRET_KEY2 || 'un_altra_chiave_molto_segreta_per_firmare2'], // USA DELLE CHIAVI SEGRETE FORTI! Meglio se da variabili d'ambiente.
    // Queste 'keys' sono usate per firmare e verificare i cookie, non per la crittografia diretta dei dati nel cookie (che cookie-session non fa di default).
    // Per la crittografia, cookie-session si affida alla firma per l'integrità.
    // La vera "segretezza" del contenuto si basa sul fatto che memorizzi solo ID e non dati sensibili.

    // Opzioni del Cookie
    maxAge: 24 * 60 * 60 * 1000, // 24 ore
    secure: process.env.NODE_ENV === 'production', // Invia solo su HTTPS
    httpOnly: true // Il cookie non è accessibile da JavaScript nel browser
  })
);

// Per accedere ai dati di sessione, usi req.session (es. req.session.userId = utente.id)
// Per fare il logout: req.session = null;

// ... resto del tuo server.js ...

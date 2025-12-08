const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const crypto = require('crypto');
const { Client, GatewayIntentBits, PermissionFlagsBits } = require('discord.js');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const app = express();
app.use(cors());
app.use(express.json());

// Environment variables
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const DISCORD_REDIRECT_URI_MEMBER = process.env.DISCORD_REDIRECT_URI_MEMBER;
const FRONTEND_URL = process.env.FRONTEND_URL;
const REQUIRED_GUILD_ID = process.env.REQUIRED_GUILD_ID;
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID;
const MEMBER_ROLE_ID = process.env.MEMBER_ROLE_ID;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const RESULT_WEBHOOK_URL = process.env.RESULT_WEBHOOK_URL;

const sessions = new Map();
const memberSessions = new Map();

// ============================================
// DATABASE SETUP
// ============================================

const dbPath = path.join(__dirname, 'applications.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Database connection error:', err);
    } else {
        console.log('✅ Connected to SQLite database');
        initDatabase();
    }
});

function initDatabase() {
    db.run(`
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name_irl TEXT NOT NULL,
            name_ingame TEXT NOT NULL,
            discord TEXT NOT NULL,
            age INTEGER NOT NULL,
            job TEXT NOT NULL,
            experience TEXT NOT NULL,
            why TEXT NOT NULL,
            dynamic_answers TEXT,
            status TEXT DEFAULT 'pending',
            discord_id TEXT,
            discord_username TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error('❌ Error creating table:', err);
        } else {
            console.log('✅ Applications table ready');
        }
    });
}

// ============================================
// DISCORD BOT SETUP
// ============================================

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages
    ]
});

client.once('ready', async () => {
    console.log(`✅ Discord Bot er online som ${client.user.tag}`);

    // Registrer slash commands (hurtigt i guild hvis du har REQUIRED_GUILD_ID)
    const commands = [
        {
            name: 'accept',
            description: 'Godkend en ansøgning (admin only)',
            options: [
                { name: 'application_id', type: 4, description: 'ID på ansøgningen', required: true },
                { name: 'reason', type: 3, description: 'Begrundelse / note', required: false }
            ]
        },
        {
            name: 'deny',
            description: 'Afvis en ansøgning (admin only)',
            options: [
                { name: 'application_id', type: 4, description: 'ID på ansøgningen', required: true },
                { name: 'reason', type: 3, description: 'Begrundelse / note', required: false }
            ]
        }
    ];

    try {
        if (REQUIRED_GUILD_ID) {
            // Vent indtil guild er cached — hvis ikke cached, prøv at fetche
            let guild = client.guilds.cache.get(REQUIRED_GUILD_ID);
            if (!guild) {
                try {
                    guild = await client.guilds.fetch(REQUIRED_GUILD_ID);
                } catch (e) {
                    console.warn('⚠️ Kunne ikke fetch guild - commands registreres globalt som fallback', e);
                }
            }
            if (guild) {
                await guild.commands.set(commands);
                console.log('✅ Guild commands registered for Required Guild');
            } else {
                await client.application.commands.set(commands);
                console.log('⚠️ Guild not available, registered commands globally as fallback');
            }
        } else {
            await client.application.commands.set(commands);
            console.log('✅ Global commands registered');
        }
    } catch (err) {
        console.error('❌ Kunne ikke registrere commands:', err);
    }
});

// Hjælpefunktion til sending til result webhook (kan genbruges)
async function sendResultToWebhook(appRow, action, moderator, reason) {
    if (!RESULT_WEBHOOK_URL) return;
    const statusText = action === 'approved' ? 'godkendt' : 'afvist';
    const statusEmoji = action === 'approved' ? '✅' : '❌';
    const color = action === 'approved' ? 3066993 : 15158332;
    const messageBase = action === 'approved'
        ? `Tillykke! Din ansøgning til **${appRow.job}** er blevet godkendt. 🎉`
        : `Din ansøgning til **${appRow.job}** er desværre blevet afvist. Du kan prøve igen senere.`;
    const message = reason ? `${messageBase}\n\n**Begrundelse:** ${reason}` : messageBase;

    const resultEmbed = {
        title: `${statusEmoji} Ansøgning ${statusText.charAt(0).toUpperCase() + statusText.slice(1)}`,
        color,
        description: message,
        fields: [
            { name: '👤 Navn IRL', value: appRow.name_irl || 'Ukendt', inline: true },
            { name: '🎮 Navn Ingame', value: appRow.name_ingame || 'Ukendt', inline: true },
            { name: '💬 Discord', value: appRow.discord || 'Ukendt', inline: true },
            { name: '💼 Job', value: appRow.job || 'Ukendt', inline: true },
            { name: '👮 Behandlet af', value: `<@${moderator.id}>`, inline: true },
            { name: '📅 Behandlet', value: new Date().toLocaleString('da-DK'), inline: true }
        ],
        footer: { text: `Ansøgnings ID: ${appRow.id}` },
        timestamp: new Date().toISOString()
    };

    const content = appRow.discord_id && appRow.discord_id !== 'unknown' ? `<@${appRow.discord_id}> ${messageBase}` : messageBase;

    try {
        const webhookResponse = await fetch(RESULT_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content, embeds: [resultEmbed] })
        });
        if (!webhookResponse.ok) {
            console.error('❌ Kunne ikke sende til result webhook:', await webhookResponse.text());
        } else {
            console.log(`✅ Sent result for app ${appRow.id} to result webhook`);
        }
    } catch (e) {
        console.error('❌ Webhook error:', e);
    }
}

// Forenkl og stabiliser interaction handler for slash-commands
client.on('interactionCreate', async (interaction) => {
    try {
        if (!interaction.isChatInputCommand()) return;

        const name = interaction.commandName;
        if (name !== 'accept' && name !== 'deny') return;

        // Hent guild medlem for at sikre roles cache er opdateret
        if (!interaction.guild) {
            await interaction.reply({ content: '❌ Denne kommando skal bruges i en server (guild).', ephemeral: true });
            return;
        }

        let member;
        try {
            member = await interaction.guild.members.fetch(interaction.user.id);
        } catch (e) {
            console.error('Could not fetch member:', e);
            await interaction.reply({ content: '❌ Kunne ikke hente brugeren fra serveren.', ephemeral: true });
            return;
        }

        if (!ADMIN_ROLE_ID || !member.roles.cache.has(ADMIN_ROLE_ID)) {
            await interaction.reply({ content: '❌ Du har ikke "ejer team" rollen og kan ikke bruge denne kommando.', ephemeral: true });
            return;
        }

        const applicationId = interaction.options.getInteger('application_id', true);
        const reason = interaction.options.getString('reason', false) || null;
        const newStatus = name === 'accept' ? 'approved' : 'rejected';

        // Opdater DB
        db.run('UPDATE applications SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [newStatus, applicationId], function(err) {
            if (err) {
                console.error('Database update error (slash command):', err);
                interaction.reply({ content: '❌ Der opstod en databasefejl.', ephemeral: true }).catch(()=>{});
                return;
            }

            if (this.changes === 0) {
                interaction.reply({ content: `❌ Kunne ikke finde ansøgning med ID ${applicationId}.`, ephemeral: true }).catch(()=>{});
                return;
            }

            // Hent opdateret række
            db.get('SELECT * FROM applications WHERE id = ?', [applicationId], async (err, appRow) => {
                if (err || !appRow) {
                    console.error('Could not fetch application after update:', err);
                    interaction.reply({ content: '❌ Kunne ikke hente ansøgningen fra databasen.', ephemeral: true }).catch(()=>{});
                    return;
                }

                // Send resultat til webhook
                await sendResultToWebhook(appRow, newStatus, interaction.user, reason);

                // Reply admin
                interaction.reply({ content: `✅ Ansøgning ${newStatus === 'approved' ? 'godkendt' : 'afvist'} (ID: ${applicationId}) og sendt til result kanal.`, ephemeral: true }).catch(()=>{});
            });
        });

    } catch (error) {
        console.error('Error handling slash command:', error);
        try {
            if (interaction.replied || interaction.deferred) {
                interaction.followUp({ content: '❌ Der opstod en fejl.', ephemeral: true }).catch(()=>{});
            } else {
                interaction.reply({ content: '❌ Der opstod en fejl.', ephemeral: true }).catch(()=>{});
            }
        } catch(e) {}
    }
});

// Log ind med Discord Bot
if (DISCORD_BOT_TOKEN) {
    client.login(DISCORD_BOT_TOKEN).catch(err => {
        console.error('❌ Kunne ikke logge ind med Discord Bot:', err);
    });
} else {
    console.warn('⚠️ DISCORD_BOT_TOKEN er ikke sat - bot funktionalitet deaktiveret');
}

// ============================================
// ADMIN OAUTH ENDPOINTS
// ============================================

app.get('/api/auth/discord', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify%20guilds%20guilds.members.read&state=${state}`;
    res.json({ url });
});

app.get('/auth/callback', async (req, res) => {
    const { code } = req.query;
    
    if (!code) {
        return res.redirect(`${FRONTEND_URL}?error=no_code`);
    }

    try {
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: DISCORD_REDIRECT_URI
            })
        });

        const tokenData = await tokenResponse.json();
        
        if (!tokenData.access_token) {
            return res.redirect(`${FRONTEND_URL}?error=no_token`);
        }

        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const userData = await userResponse.json();

        const guildsResponse = await fetch('https://discord.com/api/users/@me/guilds', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const guilds = await guildsResponse.json();

        const inServer = guilds.some(g => g.id === REQUIRED_GUILD_ID);
        
        if (!inServer) {
            return res.redirect(`${FRONTEND_URL}?error=not_in_server`);
        }

        const memberResponse = await fetch(`https://discord.com/api/users/@me/guilds/${REQUIRED_GUILD_ID}/member`, {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const memberData = await memberResponse.json();

        const hasAdminRole = memberData.roles && memberData.roles.includes(ADMIN_ROLE_ID);

        if (!hasAdminRole) {
            return res.redirect(`${FRONTEND_URL}?error=no_permission`);
        }

        const sessionToken = crypto.randomBytes(32).toString('hex');
        sessions.set(sessionToken, {
            user: {
                id: userData.id,
                username: userData.username,
                discriminator: userData.discriminator,
                avatar: userData.avatar
            },
            isAdmin: true,
            createdAt: Date.now()
        });

        res.redirect(`${FRONTEND_URL}?token=${sessionToken}&admin=true`);

    } catch (error) {
        console.error('OAuth error:', error);
        res.redirect(`${FRONTEND_URL}?error=oauth_failed`);
    }
});

app.post('/api/verify', (req, res) => {
    const { token } = req.body;
    
    if (!token || !sessions.has(token)) {
        return res.json({ valid: false, isAdmin: false });
    }

    const session = sessions.get(token);
    
    if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
        sessions.delete(token);
        return res.json({ valid: false, isAdmin: false });
    }

    res.json({ 
        valid: true, 
        isAdmin: session.isAdmin,
        user: session.user 
    });
});

app.post('/api/logout', (req, res) => {
    const { token } = req.body;
    if (token) sessions.delete(token);
    res.json({ success: true });
});

// ============================================
// MEMBER OAUTH ENDPOINTS
// ============================================

app.get('/api/auth/discord-member', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI_MEMBER)}&response_type=code&scope=identify%20guilds%20guilds.members.read&state=${state}`;
    res.json({ url });
});

app.get('/auth/callback/member', async (req, res) => {
    const { code } = req.query;
    
    if (!code) {
        return res.redirect(`${FRONTEND_URL}?error=no_code`);
    }

    try {
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: DISCORD_REDIRECT_URI_MEMBER
            })
        });

        const tokenData = await tokenResponse.json();
        
        if (!tokenData.access_token) {
            return res.redirect(`${FRONTEND_URL}?error=no_token`);
        }

        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const userData = await userResponse.json();

        const guildsResponse = await fetch('https://discord.com/api/users/@me/guilds', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const guilds = await guildsResponse.json();

        const inServer = guilds.some(g => g.id === REQUIRED_GUILD_ID);
        
        if (!inServer) {
            return res.redirect(`${FRONTEND_URL}?error=not_in_server`);
        }

        const memberResponse = await fetch(`https://discord.com/api/users/@me/guilds/${REQUIRED_GUILD_ID}/member`, {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        const memberData = await memberResponse.json();

        const hasMemberRole = memberData.roles && memberData.roles.includes(MEMBER_ROLE_ID);

        if (!hasMemberRole) {
            return res.redirect(`${FRONTEND_URL}?error=no_member_role`);
        }

        const sessionToken = crypto.randomBytes(32).toString('hex');
        memberSessions.set(sessionToken, {
            user: {
                id: userData.id,
                username: userData.username,
                discriminator: userData.discriminator,
                avatar: userData.avatar
            },
            createdAt: Date.now()
        });

        res.redirect(`${FRONTEND_URL}?token=${sessionToken}&member=true`);

    } catch (error) {
        console.error('Member OAuth error:', error);
        res.redirect(`${FRONTEND_URL}?error=oauth_failed`);
    }
});

app.post('/api/verify-member', (req, res) => {
    const { token } = req.body;
    
    if (!token || !memberSessions.has(token)) {
        return res.json({ valid: false });
    }

    const session = memberSessions.get(token);
    
    if (Date.now() - session.createdAt > 7 * 24 * 60 * 60 * 1000) {
        memberSessions.delete(token);
        return res.json({ valid: false });
    }

    res.json({ 
        valid: true,
        user: session.user 
    });
});

// ============================================
// APPLICATION ENDPOINTS (DATABASE)
// ============================================

// GET all applications (Admin only)
app.get('/api/applications', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const token = authHeader.substring(7);
    const session = sessions.get(token);
    
    if (!session || !session.isAdmin) {
        return res.status(403).json({ error: 'Forbidden - Admin only' });
    }
    
    db.all('SELECT * FROM applications ORDER BY created_at DESC', [], (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        // Parse dynamic_answers JSON
        const applications = rows.map(row => ({
            ...row,
            dynamicAnswers: row.dynamic_answers ? JSON.parse(row.dynamic_answers) : null
        }));
        
        res.json({ applications });
    });
});

// POST new application (Member only)
app.post('/api/applications', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const token = authHeader.substring(7);
    const session = memberSessions.get(token);
    
    if (!session) {
        return res.status(403).json({ error: 'Forbidden - Member login required' });
    }
    
    const { nameIrl, nameIngame, discord, age, job, experience, why, discordId, discordUsername, dynamicAnswers } = req.body;
    
    if (!nameIrl || !nameIngame || !discord || !age || !job || !experience || !why) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const dynamicAnswersJson = dynamicAnswers ? JSON.stringify(dynamicAnswers) : null;
    
    const sql = `
        INSERT INTO applications (name_irl, name_ingame, discord, age, job, experience, why, discord_id, discord_username, dynamic_answers, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `;
    
    db.run(sql, [nameIrl, nameIngame, discord, age, job, experience, why, discordId, discordUsername, dynamicAnswersJson], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({ 
            success: true, 
            application: {
                id: this.lastID,
                name_irl: nameIrl,
                name_ingame: nameIngame,
                discord,
                age,
                job,
                experience,
                why,
                discord_id: discordId,
                discord_username: discordUsername,
                dynamicAnswers,
                status: 'pending',
                created_at: new Date().toISOString()
            }
        });
    });
});

// PATCH update application status (Admin only)
app.patch('/api/applications/:id', (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const token = authHeader.substring(7);
    const session = sessions.get(token);
    
    if (!session || !session.isAdmin) {
        return res.status(403).json({ error: 'Forbidden - Admin only' });
    }
    
    const { id } = req.params;
    const { status } = req.body;
    
    if (!status || !['approved', 'rejected', 'pending'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }
    
    const sql = `UPDATE applications SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
    
    db.run(sql, [status, id], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Application not found' });
        }
        
        db.get('SELECT * FROM applications WHERE id = ?', [id], (err, row) => {
            if (err) {
                return res.json({ success: true });
            }
            res.json({ 
                success: true, 
                application: {
                    ...row,
                    dynamicAnswers: row.dynamic_answers ? JSON.parse(row.dynamic_answers) : null
                }
            });
        });
    });
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/', (req, res) => {
    res.json({ 
        status: 'ok',
        service: 'VernexRP Backend',
        timestamp: new Date().toISOString(),
        bot: client.user ? { username: client.user.tag, ready: true } : { ready: false }
    });
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        bot: client.user ? { username: client.user.tag, ready: true } : { ready: false },
        database: 'SQLite',
        endpoints: {
            admin: '/api/auth/discord',
            member: '/api/auth/discord-member',
            applications: '/api/applications'
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Backend running on port ${PORT}`);
    console.log(`✅ Admin OAuth: /api/auth/discord`);
    console.log(`✅ Member OAuth: /api/auth/discord-member`);
    console.log(`✅ Applications API: /api/applications`);
    console.log(`✅ Discord Bot: ${DISCORD_BOT_TOKEN ? 'Aktiveret' : 'Deaktiveret'}`);
    console.log(`✅ Database: SQLite`);
});

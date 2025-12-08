const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const crypto = require('crypto');
const { Client, GatewayIntentBits, InteractionType } = require('discord.js');

if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const app = express();
app.use(cors());
app.use(express.json());

// Hent fra Railway environment variables
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const DISCORD_REDIRECT_URI_MEMBER = process.env.DISCORD_REDIRECT_URI_MEMBER;
const FRONTEND_URL = process.env.FRONTEND_URL;
const REQUIRED_GUILD_ID = process.env.REQUIRED_GUILD_ID;
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID;
const MEMBER_ROLE_ID = process.env.MEMBER_ROLE_ID;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN; // NYT!
const RESULT_WEBHOOK_URL = process.env.RESULT_WEBHOOK_URL; // NYT!

const sessions = new Map();
const memberSessions = new Map();

// ============================================
// DISCORD BOT SETUP
// ============================================

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages
    ]
});

client.on('ready', () => {
    console.log(`✅ Discord Bot er online som ${client.user.tag}`);
});

// Håndter button clicks fra Discord
client.on('interactionCreate', async (interaction) => {
    if (!interaction.isButton()) return;

    const [action, appId, discordId] = interaction.customId.split('_');
    
    // Tjek om brugeren har administrator rettigheder
    if (!interaction.member.permissions.has('Administrator')) {
        await interaction.reply({
            content: '❌ Du har ikke tilladelse til at håndtere ansøgninger!',
            ephemeral: true
        });
        return;
    }

    await interaction.deferUpdate();

    try {
        // Hent original besked data
        const originalEmbed = interaction.message.embeds[0];
        const applicantName = originalEmbed.fields.find(f => f.name === '👤 Navn IRL')?.value || 'Ukendt';
        const applicantIngame = originalEmbed.fields.find(f => f.name === '🎮 Navn Ingame')?.value || 'Ukendt';
        const job = originalEmbed.fields.find(f => f.name === '💼 Job')?.value || 'Ukendt';
        const discord = originalEmbed.fields.find(f => f.name === '💬 Discord')?.value || 'Ukendt';

        // Opdater original besked
        const updatedEmbed = {
            ...originalEmbed.data,
            color: action === 'approve' ? 3066993 : 15158332, // Grøn eller rød
            title: action === 'approve' ? '✅ Ansøgning Godkendt' : '❌ Ansøgning Afvist',
            fields: [
                ...originalEmbed.fields.map(f => ({ name: f.name, value: f.value, inline: f.inline })),
                {
                    name: '👮 Behandlet af',
                    value: `<@${interaction.user.id}> (${interaction.user.username})`,
                    inline: false
                }
            ],
            footer: {
                text: `${originalEmbed.footer?.text || ''} • Behandlet ${new Date().toLocaleString('da-DK')}`
            }
        };

        await interaction.message.edit({
            embeds: [updatedEmbed],
            components: [] // Fjern knapperne
        });

        // Send resultat til anden kanal
        if (RESULT_WEBHOOK_URL) {
            const statusText = action === 'approve' ? 'godkendt' : 'afvist';
            const statusEmoji = action === 'approve' ? '✅' : '❌';
            const color = action === 'approve' ? 3066993 : 15158332;
            const message = action === 'approve' 
                ? `Tillykke! Din ansøgning til **${job}** er blevet godkendt. 🎉` 
                : `Din ansøgning til **${job}** er desværre blevet afvist. Du kan prøve igen senere.`;

            const resultEmbed = {
                title: `${statusEmoji} Ansøgning ${statusText.charAt(0).toUpperCase() + statusText.slice(1)}`,
                color: color,
                description: message,
                fields: [
                    { name: '👤 Navn IRL', value: applicantName, inline: true },
                    { name: '🎮 Navn Ingame', value: applicantIngame, inline: true },
                    { name: '💬 Discord', value: discord, inline: true },
                    { name: '💼 Job', value: job, inline: true },
                    { name: '👮 Behandlet af', value: `<@${interaction.user.id}>`, inline: true },
                    { name: '📅 Behandlet', value: new Date().toLocaleString('da-DK'), inline: true }
                ],
                footer: {
                    text: `Ansøgnings ID: ${appId}`
                },
                timestamp: new Date().toISOString()
            };

            const content = discordId !== 'unknown' ? `<@${discordId}> ${message}` : message;

            await fetch(RESULT_WEBHOOK_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    content: content,
                    embeds: [resultEmbed]
                })
            });

            console.log(`✅ Ansøgning ${appId} ${statusText} af ${interaction.user.username}`);
        }

        // Send bekræftelse til admin
        await interaction.followUp({
            content: `✅ Ansøgning ${action === 'approve' ? 'godkendt' : 'afvist'} og sendt til resultat-kanalen!`,
            ephemeral: true
        });

    } catch (error) {
        console.error('Fejl ved håndtering af button click:', error);
        await interaction.followUp({
            content: '❌ Der opstod en fejl ved behandling af ansøgningen.',
            ephemeral: true
        });
    }
});

// Log in med Discord Bot
if (DISCORD_BOT_TOKEN) {
    client.login(DISCORD_BOT_TOKEN).catch(err => {
        console.error('❌ Kunne ikke logge ind med Discord Bot:', err);
    });
} else {
    console.warn('⚠️ DISCORD_BOT_TOKEN er ikke sat - bot funktionalitet deaktiveret');
}

// ============================================
// ADMIN ENDPOINTS
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
// MEMBER ENDPOINTS
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
// HEALTH CHECK
// ============================================

app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        bot: client.user ? { username: client.user.tag, ready: true } : { ready: false },
        endpoints: {
            admin: '/api/auth/discord',
            member: '/api/auth/discord-member'
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Backend running on port ${PORT}`);
    console.log(`✅ Admin OAuth: /api/auth/discord`);
    console.log(`✅ Member OAuth: /api/auth/discord-member`);
    console.log(`✅ Discord Bot: ${DISCORD_BOT_TOKEN ? 'Aktiveret' : 'Deaktiveret'}`);
});

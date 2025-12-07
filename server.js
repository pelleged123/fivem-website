const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Hent fra Railway environment variables
const DISCORD_CLIENT_ID = '1432421740713345025'; // Dit Client ID fra Discord
const DISCORD_CLIENT_SECRET = 'QuhbDh5ROWAMKpQDtHvo-OyKa-7ZstfN'; // Dit Client Secret
const DISCORD_REDIRECT_URI = 'https://fivem-website-production.up.railway.app/';
const FRONTEND_URL = 'https://vernex12.netlify.app'; // Dit Netlify link
const REQUIRED_GUILD_ID = '1421237887210623100'; // Dit Discord Server ID
const ADMIN_ROLE_ID = '1421472998027821137'; // Din Admin Rolle ID

const sessions = new Map();

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

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend running on port ${PORT}`);
});

const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const crypto = require('crypto');

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

const sessions = new Map();
const memberSessions = new Map();

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
    const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI_MEMBER)}&response_type=code&scope=identify%20guilds&state=${state}`;
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
});

const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3000/callback';
const GUILD_ID = process.env.DISCORD_GUILD_ID;
const ADMIN_ROLE_IDS = process.env.ADMIN_ROLE_IDS ? process.env.ADMIN_ROLE_IDS.split(',') : [];

app.get('/api/auth/discord', (req, res) => {
    const discordAuthUrl = 'https://discord.com/api/oauth2/authorize?client_id=' + CLIENT_ID + '&redirect_uri=' + encodeURIComponent(REDIRECT_URI) + '&response_type=code&scope=identify%20guilds%20guilds.members.read';
    res.json({ url: discordAuthUrl });
});

app.get('/callback', async (req, res) => {
    const code = req.query.code;

    if (!code) {
        return res.redirect('http://localhost:8000?error=no_code');
    }

    try {
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', 
            new URLSearchParams({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: REDIRECT_URI,
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            }
        );

        const access_token = tokenResponse.data.access_token;

        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: {
                Authorization: 'Bearer ' + access_token,
            },
        });

        const user = userResponse.data;

        const memberResponse = await axios.get('https://discord.com/api/users/@me/guilds/' + GUILD_ID + '/member', {
            headers: {
                Authorization: 'Bearer ' + access_token,
            },
        });

        const member = memberResponse.data;
        const userRoles = member.roles;

        const isAdmin = ADMIN_ROLE_IDS.some(roleId => userRoles.includes(roleId));

        const sessionToken = Buffer.from(user.id + ':' + Date.now()).toString('base64');

        if (!global.sessions) {
            global.sessions = {};
        }
        
        global.sessions[sessionToken] = {
            userId: user.id,
            username: user.username,
            discriminator: user.discriminator,
            avatar: user.avatar,
            isAdmin: isAdmin,
            roles: userRoles,
            expires: Date.now() + (24 * 60 * 60 * 1000),
        };

        res.redirect('http://localhost:8000?token=' + sessionToken + '&admin=' + isAdmin);

    } catch (error) {
        console.error('OAuth Error:', error.response ? error.response.data : error.message);
        res.redirect('http://localhost:8000?error=auth_failed');
    }
});

app.post('/api/verify', (req, res) => {
    const token = req.body.token;

    if (!token || !global.sessions || !global.sessions[token]) {
        return res.json({ valid: false, isAdmin: false });
    }

    const session = global.sessions[token];

    if (session.expires < Date.now()) {
        delete global.sessions[token];
        return res.json({ valid: false, isAdmin: false });
    }

    res.json({
        valid: true,
        isAdmin: session.isAdmin,
        user: {
            username: session.username,
            discriminator: session.discriminator,
            avatar: session.avatar,
        },
    });
});

app.post('/api/logout', (req, res) => {
    const token = req.body.token;
    
    if (token && global.sessions && global.sessions[token]) {
        delete global.sessions[token];
    }
    
    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log('Server running on http://localhost:' + PORT);
    console.log('Make sure your .env file is configured!');
});

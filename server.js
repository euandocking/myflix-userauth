const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken'); // Added this line

const app = express();
const PORT = process.env.PORT || 5000;

const MONGO_URI = process.env.MONGO_URI; // Use MONGO_URI if set, otherwise default to localhost

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

app.use(cors());
app.use(bodyParser.json());

// Middleware for token verification
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(403).json({ error: 'Token not provided.' });
    }

    jwt.verify(token, 'your_secret_key', (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token.' });
        }

        req.user = decoded;
        next();
    });
};

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid password.' });
        }

        // Password is valid, issue a token
        const token = jwt.sign({ userId: user._id, username: user.username }, 'your_secret_key', {
            expiresIn: '1h', // Set an expiration time for the token
        });

        res.status(200).json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Error during login.' });
    }
});

app.post('/api/users', async (req, res) => {
    const { username, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({ username, password: hashedPassword });

        const savedUser = await user.save();

        if (savedUser) {
            console.log('User saved successfully:', savedUser);
            res.status(201).json(savedUser);
        } else {
            console.error('Error saving user to the database. No response received.');
            res.status(500).json({ error: 'Error saving user to the database.' });
        }
    } catch (error) {
        console.error('Error saving user to the database:', error);
        res.status(500).json({ error: 'Error saving user to the database.' });
    }
});

// Example of a protected route
app.get('/api/protected-route', verifyToken, (req, res) => {
    // Access the user information from req.user
    res.json({ message: 'You have access to this protected route', user: req.user });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
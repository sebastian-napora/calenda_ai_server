const express = require('express');
const cors = require('cors');
const OpenAI = require('openai');
const fs = require('fs')
const dotenv = require('dotenv');
const multer = require('multer');
const axios = require("axios");

const cookieParser = require('cookie-parser')
const jwt = require('jwt-simple')
const AWS = require('aws-sdk');

const ssm = new AWS.SSM();

dotenv.config();

const upload = multer({ storage: multer.memoryStorage() });

const getParameter = async (parameterName) => {
    const params = {
        Name: parameterName,
        WithDecryption: true, // Decrypt SecureString values
    };

    try {
        const response = await ssm.getParameter(params).promise();
        return response.Parameter.Value;
    } catch (error) {
        console.error('Error getting parameter:', error);
        throw error;
    }
};


const port = process.env.PORT || 3000;

function logErrors(err, req, res, next) {
    console.error(err.stack)
    next(err)
};

function startServer() {
    const app = express();

    app.use(cors({
        origin: 'http://localhost:3022', credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        allowedHeaders: {
            'Content-Type': '*',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': true,
            'Access-Control-Allow-Methods': '*',
            'Access-Control-Allow-Headers': '*'

        }
    }))

    app.use(cookieParser())

    app.use(express.urlencoded({ extended: false }));
    app.use(express.json());

    app.post('/api/chat', async (req, res) => {
        const body = req.body;

        const apiKey = await getParameter('OPENAI_API_KEY');

        const chat = new OpenAI.OpenAI({
            apiKey: process?.env?.OPENAI_API_KEY || apiKey,
        });

        // Call the model by passing an array of messages.
        // In this case, it's a simple greeting
        // const { content } = await chat.invoke([
        //     new HumanMessage(
        //         message
        //     ),
        // ]);
        const chatCompletion = await chat.chat.completions.create({
            messages: [{ role: 'user', content: body.data.message }],
            model: 'gpt-3.5-turbo',
        });

        res.send({ content: chatCompletion.choices[0].message });
    });
    // ,,

    app.get('/helthcheck', async (req, res) => {
        conosole.info(req, 'helthcheck &&&&&&&&&')
        if (!req.cookies.accessToken) {
            return res.status(403).json({
                error: 'No credentials sent!'
            });
        }

        const parsedCookiesValue = JSON.parse(req.cookies.accessToken)

        if (!parsedCookiesValue) return res.status(403).json({
            error: 'Wrong credentials!'
        });

        const apiKey = await getParameter('AIRTABLE_API_KEY');

        const airtable = await axios.get(
            "https://api.airtable.com/v0/appfTsXOG4PMVPSW2/tbl3tXXLSuR9xrlRJ",
            {
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${process?.env?.VITE_AIRTABLE_API_KEY || apiKey}`,
                },
                params: {
                    filterByFormula: `type = 'secret'`,
                },
            }
        );

        const parsedResponse = JSON.parse(airtable.data.records[0].fields.user_details);

        const token = jwt.decode(parsedCookiesValue?.token, parsedResponse.secret);

        if (token !== parsedResponse.secret) {
            return res.status(403).json({
                error: 'Invalid token!'
            });
        }

        res.send({ hasAccess: true });
    });

    app.post('/login', async (req, res) => {
        const { username, password } = req.body;

        const apiKey = await getParameter('AIRTABLE_API_KEY');

        const airtable = await axios.get(
            "https://api.airtable.com/v0/appfTsXOG4PMVPSW2/tbl3tXXLSuR9xrlRJ",
            {
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${process?.env?.VITE_AIRTABLE_API_KEY || apiKey}`,
                },
                params: {
                    filterByFormula: `type = 'user'`,
                },
            }
        );

        const airtableSecret = await axios.get(
            "https://api.airtable.com/v0/appfTsXOG4PMVPSW2/tbl3tXXLSuR9xrlRJ",
            {
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${process?.env?.VITE_AIRTABLE_API_KEY || apiKey}`,
                },
                params: {
                    filterByFormula: `type = 'secret'`,
                },
            }
        );

        // const airtable = await axios.get(
        //     `https://api.airtable.com/v0/appfTsXOG4PMVPSW2/tbl3tXXLSuR9xrlRJ/${process.env.USER_ID}`,
        //     {
        //         headers: {
        //             "Content-Type": "application/json",
        //             Authorization: `Bearer ${process.env.VITE_AIRTABLE_API_KEY}`,
        //         },
        //     }
        // );

        const parsedUserResponse = JSON.parse(airtable.data.records[0].fields.user_details);
        const parsedSecretResponse = JSON.parse(airtableSecret.data.records[0].fields.user_details);
        const userCanUse = parsedUserResponse.name === username && parsedUserResponse.password === password;

        if (userCanUse && parsedSecretResponse) {
            const token = jwt.encode(parsedSecretResponse.secret, parsedSecretResponse.secret); // Replace with actual token generation

            // Create and set the cookie with secure attributes (HTTPS recommended)
            res.cookie('accessToken', JSON.stringify({ token }), {
                httpOnly: true, // Prevent client-side JavaScript access
                // secure: true,   // Only send over HTTPS (for production)
                maxAge: 900000 // Expires in 1 hour
            });
            return res.send({ hasAccess: true });
        } else {
            res.send({ hasAccess: false });
        }

        return res.send({ token: 'test' });
        // Check credentials against database
        const user = await User.findOne({ username });
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).send('Invalid credentials');
        }
        const token = jwt.sign({ userId: user._id }, 'secretKey', { expiresIn: '1h' });
        res.json({ token });
    });

    app.post('/api/audio/transcriptions', upload.single('audioFile'), async (req, res) => {
        if (!req.cookies.accessToken) {
            return res.status(403).json({
                error: 'No credentials sent!'
            });
        }

        const parsedCookiesValue = JSON.parse(req.cookies.accessToken)

        if (!parsedCookiesValue) return res.status(403).json({
            error: 'Wrong credentials!'
        });

        const airtableApiKey = await getParameter('AIRTABLE_API_KEY');

        const airtableSecret = await axios.get(
            "https://api.airtable.com/v0/appfTsXOG4PMVPSW2/tbl3tXXLSuR9xrlRJ",
            {
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${process?.env?.VITE_AIRTABLE_API_KEY || airtableApiKey}`,
                },
                params: {
                    filterByFormula: `type = 'secret'`,
                },
            }
        );

        const parsedSecretResponse = JSON.parse(airtableSecret.data.records[0].fields.user_details);

        if (!req.cookies.accessToken) {
            return res.status(403).json({
                error: 'No credentials sent!'
            });
        }

        const token = jwt.decode(parsedCookiesValue?.token, parsedSecretResponse.secret);

        if (token !== parsedSecretResponse.secret) {
            return res.status(403).json({
                error: 'Invalid token!'
            });
        }

        const buffer = Buffer.from(req?.file.buffer, 'hex');

        const file = new File([buffer], 'audioFile.mp3', {
            type: 'audio/mp3', // Mimetype for MP3 audio
            encoding: '7bit', // Encoding (may be different depending on file content)
        });


        const apiKey = await getParameter('OPENAI_API_KEY');

        const chat = new OpenAI.OpenAI({
            apiKey: process?.env?.OPENAI_API_KEY || apiKey,
        });

        const result = await chat.audio.transcriptions.create({
            file: file,
            model: 'whisper-1',
        });

        const chatCompletion = await chat.chat.completions.create({
            messages: [
                {
                    role: 'system', content: `
                    If user says "grudnia", then change this to number

                    example: 
                        grudnia - 12, styczeń - 1, luty - 2

                    Please assign value to categories (date,tooltip,method):
                        if user says select range between 1 and 10 grudnia 2024, then return two dates in format YYYY-MM-DD
                        and bettwen these dates 2024-12-01|2024-12-10 - category: "date"
                        if user says something about date, then return date, example: 1 stycznia 2024 - category: "date"
                        if user says content, then assigned text to category "tooltip", example: "urodziny Jasia"
                        if user says [zaktualizuj, aktualizuj, zmień, popraw] then assigned "patch" to category "method"
                        if user says [dodaj, dodaj nowy, nowy] then assigned "create" to category "method"
                        if user says [usuń, skasuj, remove] then assigned "delete" to category "method"

                    return json object with three keys with categories and proper values to them:
                    {
                        "date": date,
                        "tooltip": tooltip,
                        "method": method
                    }
                ` },
                { role: 'user', content: result.text }],
            model: 'gpt-3.5-turbo',

        });


        return res.send({ content: chatCompletion.choices[0].message.content });
    });


    app.use(logErrors);

    app.use((req, res, next) => {
        const error = new Error()
        error.status = 404
        error.message = 'Not found'
        next(error)
    })

    app.use((error, req, res, next) => {
        res.status(error.status || 400);
        res.json({
            error: {
                status: error.status || 400,
                message: "Something went wrong!" || error.message
            }
        });
    });

    app.listen(port, err => {
        if (err) {
            console.error(err);
            process.exit(1);
            return;
        };
        console.log(`Server listening on port ${port}`);
    });
};

startServer();

const ldap = require('ldapjs');
const express = require('express');
const session = require('express-session');
const oracledb = require('oracledb');
const mysql = require('mysql');
const mysql2 = require('mysql2/promise');
const path = require('path');
const sharp = require('sharp');
const request = require('request');
const compression = require('compression');
const fs = require('fs');
const fs1 = require('fs').promises;
const zlib = require('zlib');
const jwt = require('jsonwebtoken');
const rateLimit = require("express-rate-limit");
const { validate, validationResult } = require('express-validator');
const dbf = require('dbf');
const DBFParser = require('dbf-parser');
const Nodedbf = require('node-dbf');
const dbase = require('dbase');
const { exec } = require('child_process');
const timeout = require('express-timeout-handler');

const app = express();
app.use(express.json());
app.use(compression());
//app.use(cors()); // Enable CORS to allow cross-origin requests
//app.use(bodyParser.json()); // Parse JSON requests

// Set up rate limiting 
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // Limit each IP to 100 requests per windowMs  
});
app.use(limiter);

process.on('SIGINT', () => {
  console.log('Closing server');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

// Secret for signing JWTs
const secretKey = 'supersecretkey';

// Generate JWT 
function generateToken(user) {
  return jwt.sign({ data: user }, secretKey, { expiresIn: '1h' });
}

// Verify JWT token middleware
function verifyToken(req, res, next) {

// Get auth header value
const bearerHeader = req.headers['authorization'];

// Check if bearer is undefined
if(typeof bearerHeader !== 'undefined') {

    // Split at the space
    const bearer = bearerHeader.split(' ');

    // Get token from array
    const bearerToken = bearer[1];

    // Set the token
    req.token = bearerToken;
    
    // Next middleware
    next();

  } else {
    // Forbidden
    res.sendStatus(403);
  }

}

// Verify JWT token
function verifyJwt(token) {

  return new Promise((resolve, reject) => {

    jwt.verify(token, secretKey, (err, decoded) => {
      if(err) reject(err);

      resolve(decoded);
    });

  });

}

// Protected route  
app.get('/protected', verifyToken, async (req, res) => {

  const token = req.token;

  try {
    // Verify JWT
    const decoded = await verifyJwt(token);

    // Access granted
    res.json(decoded);

  } catch (err) {
    // Invalid token
    res.status(401).json('Invalid token');
  }

});

app.use(session({
	secret: 'your secret here',
	resave: false,
	saveUninitialized: true,
  }));


const API_KEY = 'AIzaSyB6-09PWaDzEGW475w4S3tfJm8nUj0g7Xk'; // Replace with your GPT API key
const apiUrl = 'https://generativelanguage.googleapis.com/v1beta3/models/text-bison-001:generateText?key=' + API_KEY;

app.post('/bslgpt', async (req, res) => {
  const userInput = req.body.userInput;
  console.log(userInput);

  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        prompt: {
          text: `Access info from my drive an Executive of bokaro steel plant is asking "${userInput} ?" respond like a private bot of Bokaro Steel Plant (BSL) (http://www.bokarosteel.com) trained on internal data, give actual references with heading of the document and page number, dont give any made up information by your own. only give information found in drive documents nothing else`,
        },
        temperature: 0.65,
        top_k: 50,
        top_p: 0.8,
        candidate_count: 1,
        max_output_tokens: 24650,
        stop_sequences: [],
        safety_settings: [
          { category: 'HARM_CATEGORY_DEROGATORY', threshold: 1 },
          { category: 'HARM_CATEGORY_TOXICITY', threshold: 1 },
          { category: 'HARM_CATEGORY_VIOLENCE', threshold: 2 },
          { category: 'HARM_CATEGORY_SEXUAL', threshold: 2 },
          { category: 'HARM_CATEGORY_MEDICAL', threshold: 2 },
          { category: 'HARM_CATEGORY_DANGEROUS', threshold: 2 }],
        
      }),
    });

    if (response.status === 200) {
		
      const data = await response.json();
      const responseText = data.candidates[0].output;
	  logToDatabase(userInput, responseText);
      res.json({ result: responseText });
    } else {
      res.status(response.status).json({ error: 'Failed to retrieve GPT response' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

function logToDatabase(userInput, responseText) {
	const db = mysql.createConnection({
      host: '10.143.106.145',
      user: 'steelbokaro',
      password: 'BokaroSteel@2021',
      database: 'bokaroplant'
    });
  const sql = 'INSERT INTO bslgpt_logs (user_input, bot_response) VALUES (?, ?)';
  const values = [userInput, responseText];

  db.query(sql, values, (err, results) => {
    if (err) {
      console.error('Error inserting into bslgpt_logs table:', err);
    } else {
      console.log('Logged input and response to database');
    }
  });
  db.end();
}


// Feedback API route
app.post('/feedback', (req, res) => {
	

  const { username, feedback } = req.body;
  
  // Validate input
  if(!feedback) {
    return res.status(400).send('message is required');
  }
  
  const db = mysql.createConnection({
      host: '10.143.106.145',
      user: 'steelbokaro',
      password: 'BokaroSteel@2021',
      database: 'bokaroplant'
    });

  // Insert feedback into db
  db.query(
    'INSERT INTO feedback (staffno, message) VALUES (?, ?)', 
    [username,feedback],
    (error, results) => {
      if(error) {
        console.error(error);
        res.status(500).send('Error saving feedback');
      } else {
        res.send('Feedback received'); 
      }
    }
  );
  db.end();

});

//app.listen(3000);

const server = app.listen(() => {
	console.log('Server is running on port', process.env.PORT || 80);
});

//server.listen(8443, () => {
//	console.log('Server is running on https://localhost:8443');
//});
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
const xlsx = require('xlsx');
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
const axios = require('axios');
const cors = require('cors');

const multer  = require('multer');

const app = express();
app.use(express.json());
app.use(compression());
app.use(cors()); // Enable CORS to allow cross-origin requests
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


  const storage = multer.diskStorage({
    
    destination: function (req, file, cb) {
      cb(null, 'D:/Bokarosteel/digitalisation/home/uploads/')
    },
    filename: function (req, file, cb) {
      // Get current date
      const currentDate = new Date();
      // Format date components
      const year = currentDate.getFullYear();
      // Add leading zero if necessary for month and day
      const month = String(currentDate.getMonth() + 1).padStart(2, '0');
      const day = String(currentDate.getDate()).padStart(2, '0');
      // Construct filename with formatted date
      const formattedDate = `${day}-${month}-${year}`;
      // Combine formatted date with original filename
      const filename = `${formattedDate}_${file.originalname}`;
      // Pass the filename to the callback
      cb(null, filename);
  }
  });

  const upload = multer({ storage: storage });
  // Route for handling file uploads

  app.post('/upload', upload.single('uploaded_doc'), (req, res) => {
    
    if (!req.file) {
      return res.status(400).send('No file uploaded.');
    }
    res.send('File uploaded successfully: ' + req.file.filename);
    
  });


app.post(
  '/login',
  timeout.handler({
    timeout: 10000, // Adjust the timeout value as needed (e.g., 10 seconds)
  }),
  validateInput,
  sanitizeInput,
  async (req, res) => {
    console.log('Inside Login');
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    try {
      const { username, password } = req.body;
      console.log(username);

      if (!username || !password) {
        return res.status(400).send('Username and password are required.');
      }

      const client = ldap.createClient({
        url: 'ldap://adc1.sailbsl.in:389',
      });

      const bindOptions = {
        bindDN: `${username}@sailbsl.in`,
        password,
      };

      const closeClient = () => {
        if (client) {
          client.unbind((err) => {
            if (err) {
              console.error('Error occurred while closing the LDAP client:', err);
            }
          });
        }
      };

      const handleLdapError = (err) => {
        console.error('Error occurred during LDAP operation:', err);
        res.status(401).send('Invalid username or password');
        closeClient();
      };

      client.on('error', (err) => {
        handleLdapError(err);
      });

      client.bind(bindOptions.bindDN, bindOptions.password, (err) => {
        if (err) {
          handleLdapError(err);
        } else {
          const token = jwt.sign({ id: username }, secretKey);
          res.send({ token });
          closeClient();
        }
      });
    } catch (error) {
      console.error('An error occurred:', error);
      res.status(500).send('An error occurred');
    }
  }
);




// Input validation middleware
function validateInput(req, res, next) {
  // Add validation checks
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ errors: errors.array() });
  }
  
  next();
}

// Sanitize input middleware  
function sanitizeInput(req, res, next) {
  // Sanitize inputs
  
  next();
}


app.get('/images', validateInput, sanitizeInput, verifyToken, (req, res) => {
  try {
    const db_bokarosteel = mysql.createConnection({
      host: '10.143.106.145',
      user: 'steelbokaro',
      password: 'BokaroSteel@2021',
      database: 'bokaroplant'
    });

    db_bokarosteel.query('SELECT * FROM bsl_upload_file where up_segment=\'slider\' and up_visible=1 AND CURDATE() between start_date and end_date ORDER BY upload_id DESC', (err, result) => {
      if (err) throw err;

      // Map result to array of image objects with id, url, and base64 data properties
      const images = result.map(async (row) => {
        // Read the image file from the file system or database (you may need to adjust this part based on your setup)
        const imageBase64 = await readImageFromFileSystemOrDatabase('D:\\new-bsl'+row.up_link);

        return {
          id: row.upload_id,
          url: 'http://bokarosteel.com' + row.up_link,
          base64: imageBase64,
        };
      });

      // Send image data as JSON response
      Promise.all(images).then((imageData) => {
        res.json(imageData);
        db_bokarosteel.end();
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('An error occurred');
  }
});

// Function to read image data from the file system or database
async function readImageFromFileSystemOrDatabase(imagePath) {  
  const imageBuffer = await fs1.readFile(imagePath);
  return imageBuffer.toString('base64');
}



 app.get('/announcement', (req, res) => {
  try {
    const db_bokarosteel = mysql.createConnection({
      host: '10.143.106.145',
      user: 'steelbokaro',
      password: 'BokaroSteel@2021',
      database: 'bokaroplant'
    });
    // Query the database for announcements
    db_bokarosteel.query('SELECT * FROM bsl_upload_file where up_segment=\'Announcement\' and up_visible=1 and CURDATE() between start_date and end_date ORDER BY upload_id DESC', (err, result) => {
      if (err) throw err;

      const file = result.map(row => ({
        id: row.upload_id,
        title: row.up_title,
        url: row.up_link
      }));

      
      res.json(file);
      db_bokarosteel.end();
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('An error occurred');
  }
});

app.get('/recent_upload',verifyToken, (req, res) => {
  try {
    const db_bokarosteel = mysql.createConnection({
      host: '10.143.106.145',
      user: 'steelbokaro',
      password: 'BokaroSteel@2021',
      database: 'bokaroplant'
    });
    // Query the database for announcements
    db_bokarosteel.query('SELECT * FROM dept_main where CURDATE() between up_date and for_time ORDER BY dept_id DESC LIMIT 20', (err, result) => {
      if (err) throw err;

      const file = result.map(row => ({
        id: row.dept_id,
        title: row.cnt_title,
        url: row.cnt_url,
        dept: row.dept_name
      }));

      
      res.json(file);
      db_bokarosteel.end();
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('An error occurred');
  }
});


app.get('/file', (req, res) => {
  try {
    const { url } = req.query;

    console.log(url);

    if (url.startsWith('/wp-content/')) {
      const filePath = 'D:\\new-bsl' + url;

      fs.readFile(filePath, (err, fileData) => {
        if (err) {
          console.error(err);
          return res.status(500).send('Error reading the file.');
        }

        // Convert the file data to a base64 string
        const base64FileData = Buffer.from(fileData).toString('base64');

        if (url.endsWith('.pdf')) {
          res.setHeader('Content-Type', 'application/pdf');
        } else if (url.endsWith('.doc') || url.endsWith('.docx')) {
          res.setHeader('Content-Type', 'application/msword');
        } else if (url.match(/\.(jpeg|jpg|png|gif)$/)) {
          res.setHeader('Content-Type', 'image/jpeg');
        }
        res.setHeader('Content-Disposition', 'inline; filename="file.pdf"');

        // Send the base64 string as the response
        res.send(base64FileData);
      });
    } else {
      res.status(400).send('Invalid URL.');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('An error occurred');
  }
});




app.post('/forget-password', async (req, res) => {
  try {
    const emailOrUsername = req.body.emailOrUsername;
    
    // Retrieve the user's mobile number from the AD server
    const mobileNumber = await getMobileNumberFromHRIS(emailOrUsername);
    console.log(mobileNumber);
    if (mobileNumber === 'Invalid') {
      res.status(400).json({ status: 'error', message: 'Invalid Staff Number or  mobile number doesnt exist ' });
      return;
    }else{
    
    // Generate a unique OTP
    const otp = Math.floor(100000 + Math.random() * 900000);
    
    const db_bokarosteel = mysql.createConnection({
      host: '10.143.106.145',
      user: 'steelbokaro',
      password: 'BokaroSteel@2021',
      database: 'bokaroplant'
    });
    
    // Store the OTP in your database along with the email address or username and an expiration time
    db_bokarosteel.query('INSERT INTO wp_sms(wp_smsto,wp_staffno,wp_email,wp_otp,wp_req_dt,wp_smsid) VALUES (?,?,?,?,?,1)', [mobileNumber,emailOrUsername,'' ,otp,new Date(),1], (error, results) => {
      if (error) throw error;
      
      const lastinsertId = JSON.stringify(results.insertId);
      
      const data = { lastinsertId: lastinsertId,mobileNumber: mobileNumber };
      res.json(data);
      
      // Send the OTP to the user's email address and mobile number
      sendOTP(mobileNumber, otp);
      
      db_bokarosteel.end();
    });
	}
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});


async function getMobileNumberFromHRIS(username) {

	let Oracleconnection;

	try {

	Oracleconnection = await oracledb.getConnection({

	user: 'pf',

	password: 'polar6bear',

	connectString: '10.143.106.117/RAC4'

	});

	const result = await Oracleconnection.execute(`SELECT MOB FROM hrs.perks_emp_view WHERE stno=:username and ROLL_STAT =:rollstatus`, [username,'Y']);

	if (result.rows.length > 0 && result.rows[0][0] != null) {

	return result.rows[0][0];

	} else {

	return 'Invalid';

	}

	} catch (err) {

	console.error(err);

	} finally {

	if (Oracleconnection) {

	try {

	await Oracleconnection.close();

	} catch (err) {

	console.error(err);

	}

	}

	}

}

async function getMobileNumberFromAD(username) {
  return new Promise((resolve, reject) => {
    const adminUsername = 'administrator@sailbsl.in';
    const adminPassword = 'Keyboard@1585';
    const client = ldap.createClient({
      url: 'ldap://adc1.sailbsl.in'
    });

    client.bind(adminUsername, adminPassword, (err) => {
      if (err) {
        reject(err);
      } else {
        const searchOptions = {
          filter: `(sAMAccountName=${username})`,
          attributes: ['telephoneNumber']
        };

        client.search('DC=sailbsl,DC=in', searchOptions, (err, res) => {
          if (err) {
            reject(err);
          } else {
            let mobileNumber;
            res.on('searchEntry', (entry) => {
				console.log(entry);
              mobileNumber = entry.object.telephoneNumber;
              resolve(mobileNumber);
            });

            res.on('end', () => {
              // User not found
              if (!mobileNumber) {
                reject(new Error('User not found'));
              }

              // Don't forget to unbind the client
              client.unbind();
            });
          }
        });
      }
    });
  });
}

async function test() {
  try {
	 
    const mobile = await getMobileNumberFromAD(parseInt(834821));
    console.log(mobile);
  } catch (error) {
    console.error(error);
  }
}

//test();


async function sendOTP(mobileNumber, otp) {
  // Send the OTP to the user's email address using your preferred method
  // ...
  // Send the OTP to the user's mobile number using a third-party service
  const url = 'https://http.myvfirst.com/smpp/sendsms';
  
  const data = {
    username: 'dgmicrohtptrn',
    password: 'Hjdg782@2',
    to: mobileNumber,
    from: 'DGMBSL',
    text: `Your OTP: ${otp} for Password Change. SMS from DG-BSL.`
	
  };
  
  const params = new URLSearchParams(data).toString();
  
  const options = {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  };
  
  fetch(url,options)
   .then(response => response.text())
   .then(result => console.log(result))
   .catch(error => console.error(error));
}

async function sendMsg(mobileNumber, name,id,prob) {
  // Send the OTP to the user's email address using your preferred method
  // ...
  // Send the OTP to the user's mobile number using a third-party service
  const url = 'https://http.myvfirst.com/smpp/sendsms';
  
  try{
  const data = {
    username: 'dgmicrohtptrn',
    password: 'Hjdg782@2',
    to: mobileNumber,
    from: 'DGMBSL',
    text: `Dear ${name}, Your complaint with ID: ${id}, regarding ${prob}, has been registered. Your call will be assigned to SE and shall be resolved. Contact HELPDESK MAX No. for PC %26 NETWORK- $maxno for further query. SMS from DG-BSL..`
	
  };
  
  const params = new URLSearchParams(data).toString();
  
  const options = {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  };
  
  fetch(url,options)
   .then(response => response.text())
   .then(result => console.log(result))
   .catch(error => console.error(error));
  }catch(err){
	  console.error(err);
  }
}

app.post('/verify-otp', async (req, res) => {
	const otp = req.body.otpCode;
	const lastinsertId = req.body.id;
	const mobile = req.body.mobile;
	const pass = req.body.newPassword;
	const dbConfig = {
	host: '10.143.106.145',
	user: 'steelbokaro',
	password: 'BokaroSteel@2021',
	database: 'bokaroplant',
	};
	
	let db_bokarosteel = await mysql.createConnection(dbConfig);
	
	const util = require('util');
	const query = util.promisify(db_bokarosteel.query).bind(db_bokarosteel);
	
	  const sql = 'SELECT wp_otp FROM wp_sms WHERE wp_smsuqid=?';
	 // const row = await db_bokarosteel.query(sql, parseInt(lastinsertId));
	 const rows = await query(sql, parseInt(lastinsertId));
		console.log(rows);
		console.log(rows[0].wp_otp);
		console.log(otp);
		

	  if (parseInt(otp) == parseInt(rows[0].wp_otp)) {
		  
		  console.log('inside if');
		const password = pass;
		const sql_upd = 'UPDATE wp_sms SET wp_otpverify=1,wp_password_set=1,wp_password=? WHERE wp_smsuqid=?';
		await db_bokarosteel.query(sql_upd, [password, parseInt(lastinsertId)]);
		//sendPass(mobile, password);
		res.status(200).send({ status: 'success' });
		db_bokarosteel.end();
	  } else {
		res.status(400).send({ status: 'error' });
	  }
  });


oracledb.createPool({
  user: 'pf',
  password: 'polar6bear',
  connectString: '10.143.106.117/RAC4',
  poolMin: 2, // Minimum number of connections to create
  poolMax: 10, // Maximum number of connections to create
  poolIncrement: 2, // Number of connections to create when needed
}).then(pool => {
  // Store the connection pool for later use
  app.locals.oraclePool = pool;
}).catch(err => {
  console.error('Failed to create Oracle connection pool:', err);
});


// Generate random hex color
function getRandomColor() {
  let letters = '0123456789ABCDEF';
  let color = '#';
  for (let i = 0; i < 6; i++) {
    color += letters[Math.floor(Math.random() * 16)];
  }
  return color;
}


app.get('/employeeInfoGraph',verifyToken, async (req, res) => {

  let connection;
  
  try {

    connection = await oracledb.getConnection({ 
	  user: 'pf',
      password: 'polar6bear',
      connectString: '10.143.106.117/RAC4',
    });

    const result = await connection.execute(
      `SELECT 
        CASE  
          WHEN GRADEP LIKE 'E%' THEN SUBSTR(GRADEP, 1, 2)
          WHEN GRADEP LIKE 'S%' AND LENGTH(GRADEP) = 2 THEN GRADEP
          WHEN GRADEP IN ('S10', 'S11', 'MTT') THEN GRADEP
        END AS GRADEP_GROUP, 
        COUNT(*) 
      FROM hrs.perks_emp_view
      GROUP BY
        CASE
          WHEN GRADEP LIKE 'E%' THEN SUBSTR(GRADEP, 1, 2)  
          WHEN GRADEP LIKE 'S%' AND LENGTH(GRADEP) = 2 THEN GRADEP
          WHEN GRADEP IN ('S10', 'S11', 'MTT') THEN GRADEP
        END
      ORDER BY GRADEP_GROUP`
    );
    
    res.json(result.rows);

  } catch (err) {
    console.error(err);
    res.status(500).send('Error querying Oracle database');

  } finally {
    if (connection) {  
      try {
        await connection.close();
      } catch (err) {
        console.error(err);
      }
    }
  }

});



app.post('/employeeInfo',verifyToken, async (req, res) => {
  const searchString = req.body.searchQuery;
  const Oracleconnection = await req.app.locals.oraclePool.getConnection();

  try {
    const query = `
      SELECT *
      FROM (
        SELECT *
        FROM hrs.perks_emp_view
        WHERE (stno LIKE :username)
          OR (FFNAME || ' ' || LNAME LIKE :username)
          OR (FFNAME || ' ' || LNAME || ' ' || DEP_NAME LIKE :username)
          OR (REGEXP_SUBSTR(FFNAME, '^[^[:space:]]+') || ' ' || LNAME LIKE :username)
          OR (REGEXP_SUBSTR(FFNAME, '^[^[:space:]]+') || ' ' || DEP_NAME LIKE :username)
          OR (FFNAME || ' ' || DEP_NAME LIKE :username)
          OR (LNAME || ' ' || DEP_NAME LIKE :username)
		  OR (GRADEP LIKE :username)
		  OR (DEP_NAME || ' ' || GRADEP LIKE :username)
      OR (DEP_NAME || ' ' || SECTION LIKE :username)
		  
        OR (mob LIKE :username)
      ORDER BY
        CASE
          WHEN GRADEP LIKE 'E%' THEN 1
          WHEN GRADEP LIKE 'S%' THEN 2
          ELSE 3
        END,
        CASE WHEN GRADEP = 'E1T' THEN 1 ELSE 0 END,
        LENGTH(GRADEP) DESC,
        GRADEP DESC,
		STNO ASC
      ) WHERE ROWNUM <= 100`;

    const result = await Oracleconnection.execute(query, [`%${searchString}%`, `%${searchString}%`, `%${searchString}%`, `%${searchString}%`, `%${searchString}%`, `%${searchString}%`, `%${searchString}%`, `%${searchString}%`]);

    const imageFolderPath = 'D:\\BSL\\CISF\\cisfPhoto';
    const rowsWithImages = await Promise.all(
      result.rows.map(async (row) => {
        const staffNumber = row[0];
        //const imagePath = path.join(imageFolderPath, `${staffNumber}.jpg`);
		let imagePath;
		try {
			imagePath = path.join(imageFolderPath, `${staffNumber}.jpg`);
		} catch (err) {
			console.error(`Error getting image for ${staffNumber}`, err); 
			return {
			  ...row,
			  image: '',
			}
		}
        let imageBase64 = '';

        if (imagePath && fs.existsSync(imagePath)) {
			
			let imageBuffer;
			try {
			  imageBuffer = await sharp(imagePath)
				.resize({ width: 200 }) 
				.toBuffer();
			} catch (err) {
			  console.error(`Error processing image ${imagePath}`, err);
			  return {
			  ...row,
			  image: '',
			}
			}
			
          
          imageBase64 = imageBuffer.toString('base64');
        }

        return {
          ...row,
          image: imageBase64,
        };
      })
    );

    res.json(rowsWithImages);
  } catch (err) {
    console.error(err);
  } finally {
    if (Oracleconnection) {
      try {
        await Oracleconnection.close();
      } catch (err) {
        console.error(err);
      }
    }
  }
});



app.post('/allEmployeeInfo',verifyToken, async (req, res) => {
  let Oracleconnection;
  const page = req.body.page || 1;
  const pageSize = req.body.pageSize || 10000;
  try {
    Oracleconnection = await oracledb.getConnection({
      user: 'pf',
      password: 'polar6bear',
      connectString: '10.143.106.117/RAC4',
    });

    const result = await Oracleconnection.execute(`
      SELECT *
      FROM hrs.perks_emp_view
    `);

    const imageFolderPath = 'D:\\BSL\\CISF\\cisfPhoto';
    const rowsWithImages = result.rows.map((row) => {
      const staffNumber = row[0]; // Assuming staff number is the first column in the result
      const imagePath = path.join(imageFolderPath, `${staffNumber}.jpg`); // Assuming images are in .jpg format
      let imageBase64 = '';

      if (fs.existsSync(imagePath)) {
        const imageBuffer = fs.readFileSync(imagePath);
        imageBase64 = imageBuffer.toString('base64');
      } else {
        console.error(`Image not found for staff number: ${staffNumber}`);
      }

      return {
        ...row,
        image: imageBase64,
      };
    });

    // Paginate the data
    const startIndex = (page - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    const paginatedData = rowsWithImages.slice(startIndex, endIndex);

    res.json(paginatedData);
  } catch (err) {
    console.error(err);
  } finally {
    if (Oracleconnection) {
      try {
        await Oracleconnection.close();
      } catch (err) {
        console.error(err);
      }
    }
  }
});

(async () => {
  try {
    await oracledb.createPool({
      user: 'pf',
      password: 'polar6bear',
      connectString: '10.143.106.117/RAC4',
      poolMin: 2,
      poolMax: 10,
      poolIncrement: 2
    });

    app.get('/birthdays',verifyToken, async (req, res) => {
      try {
        const connection = await oracledb.getConnection();

        const result = await connection.execute(
          `SELECT * FROM hrs.perks_emp_view WHERE TO_CHAR(BIRTH_DT, 'dd-mm') = TO_CHAR(SYSDATE, 'dd-mm') ORDER BY CASE WHEN GRADEP LIKE 'E%' THEN 1 WHEN GRADEP LIKE 'S%' THEN 2 ELSE 3 END,CASE WHEN GRADEP = 'E1T' THEN 1 ELSE 0 END, LENGTH(GRADEP) DESC, GRADEP DESC`
        );

        const imageFolderPath = 'D:\\BSL\\CISF\\cisfPhoto';

        const rowsWithImages = await Promise.all(
      result.rows.map(async (row) => {
        const staffNumber = row[0];
        //const imagePath = path.join(imageFolderPath, `${staffNumber}.jpg`);
		let imagePath;
		try {
			imagePath = path.join(imageFolderPath, `${staffNumber}.jpg`);
		} catch (err) {
			console.error(`Error getting image for ${staffNumber}`, err); 
			return {
			  ...row,
			  image: '',
			}
		}
        let imageBase64 = '';

        if (imagePath && fs.existsSync(imagePath)) {
			
			let imageBuffer;
			try {
			  imageBuffer = await sharp(imagePath)
				.resize({ width: 200 }) 
				.toBuffer();
			} catch (err) {
			  console.error(`Error processing image ${imagePath}`, err);
			  return {
			  ...row,
			  image: '',
			}
			}
			
          
          imageBase64 = imageBuffer.toString('base64');
        }

        return {
          ...row,
          image: imageBase64,
        };
      })
    );

        res.json(rowsWithImages);
        await connection.close();
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: err.message });
      }
    });

    
  } catch (err) {
    console.error(err);
  }
})();

(async () => {
  try {
    await oracledb.createPool({
      user: 'pf',
      password: 'polar6bear',
      connectString: '10.143.106.117/RAC4',
      poolMin: 2,
      poolMax: 10,
      poolIncrement: 2
    });

    app.get('/retirements',verifyToken, async (req, res) => {
      try {
        const connection = await oracledb.getConnection();

        const result = await connection.execute(
          `SELECT * FROM hrs.perks_emp_view WHERE TO_CHAR(TO_DATE(BIRTH_DT, 'DD-MM-RR'), 'MM') = TO_CHAR(CURRENT_DATE, 'MM') AND TO_CHAR(TO_DATE(BIRTH_DT, 'DD-MM-RR'), 'YYYY') = TO_CHAR(CURRENT_DATE, 'YYYY') - 60 ORDER BY CASE WHEN GRADEP LIKE 'E%' THEN 1 WHEN GRADEP LIKE 'S%' THEN 2 ELSE 3 END,CASE WHEN GRADEP = 'E1T' THEN 1 ELSE 0 END, LENGTH(GRADEP) DESC, GRADEP DESC`
        );

        const imageFolderPath = 'D:\\BSL\\CISF\\cisfPhoto';

        const rowsWithImages = await Promise.all(
      result.rows.map(async (row) => {
        const staffNumber = row[0];
        //const imagePath = path.join(imageFolderPath, `${staffNumber}.jpg`);
		let imagePath;
		try {
			imagePath = path.join(imageFolderPath, `${staffNumber}.jpg`);
		} catch (err) {
			console.error(`Error getting image for ${staffNumber}`, err); 
			return {
			  ...row,
			  image: '',
			}
		}
        let imageBase64 = '';

        if (imagePath && fs.existsSync(imagePath)) {
			
			let imageBuffer;
			try {
			  imageBuffer = await sharp(imagePath)
				.resize({ width: 200 }) 
				.toBuffer();
			} catch (err) {
			  console.error(`Error processing image ${imagePath}`, err);
			  return {
			  ...row,
			  image: '',
			}
			}  
          imageBase64 = imageBuffer.toString('base64');
        }

        return {
          ...row,
          image: imageBase64,
        };
      })
    );

        res.json(rowsWithImages);
        await connection.close();
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: err.message });
      }
    });

    
  } catch (err) {
    console.error(err);
  }
})();

app.post('/employee', verifyToken ,async (req, res) => {
  const searchString = req.body.username;
  let Oracleconnection; // Define Oracleconnection outside the try block

  try {
    Oracleconnection = await oracledb.getConnection({
      user: 'pf',
      password: 'polar6bear',
      connectString: '10.143.106.117/RAC4',
    });

    const result = await Oracleconnection.execute(
      `SELECT * FROM hrs.perks_emp_view WHERE stno = :username`, [searchString]
    );

    if (
      searchString.includes("834821") ||
      searchString.includes("817372") ||
      searchString.includes("798845") ||
      searchString.includes("795023") ||
      searchString.includes("834467") ||
      searchString.includes("809395") ||
      searchString.includes("687220") ||
      searchString.includes("770596") ||
      searchString.includes("688898")
      

    ) {
      result.eis = true;
    } else {
      result.eis = false;
    }

    res.json(result);
  } catch (err) {
    console.error(err);
  } finally {
    if (Oracleconnection) {
      try {
        await Oracleconnection.close();
      } catch (err) {
        console.error(err);
      }
    }
  }
});

app.get('/getCategory',verifyToken, async (req, res) => {
  let Oracleconnection;
  try {
    Oracleconnection = await oracledb.getConnection({
      user: 'bokarosteel',
      password: 'bokarosteel123',
      connectString: '10.143.11.45/ractsh',
    });

    const result = await Oracleconnection.execute(
      `Select MAIN_CAT_ID,MAIN_CAT_NAME from INCIDENT_MAIN_CAT_MAST where MAINT_TEAM IN ('200000','300000','500000','666000','700000') ORDER BY MAIN_CAT_ID`
    );
    res.json(result);
	
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: err.message });
  } finally {
    if (Oracleconnection) {
      try {
        await Oracleconnection.close();
      } catch (err) {
        console.error(err);
      }
    }
  }
});

app.get('/getRCategory',verifyToken, async (req, res) => {
  let Oracleconnection;
  try {
    Oracleconnection = await oracledb.getConnection({
      user: 'bokarosteel',
      password: 'bokarosteel123',
      connectString: '10.143.11.45/ractsh',
    });

    const result = await Oracleconnection.execute(
      `Select MAIN_CAT_ID,MAIN_CAT_NAME from INCIDENT_MAIN_CAT_MAST where MAINT_TEAM IN ('111000') ORDER BY MAIN_CAT_ID`
    );
    res.json(result);
	
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: err.message });
  } finally {
    if (Oracleconnection) {
      try {
        await Oracleconnection.close();
      } catch (err) {
        console.error(err);
      }
    }
  }
});


app.post('/getSubCategory',verifyToken, async (req, res) => {
  const searchString = req.body.itemValue;
  try {
    Oracleconnection = await oracledb.getConnection({
      user: 'bokarosteel',
      password: 'bokarosteel123',
      connectString: '10.143.11.45/ractsh',
    });
	//console.log(searchString);
   const result = await Oracleconnection.execute(
    `SELECT SUB_CAT_ID,SUB_CAT_NAME FROM INCIDENT_SUB_CAT_MAST WHERE MAIN_CAT_ID = :username Order by ID ASC`,[searchString]);

   res.json(result);
	
  } catch (err) {
    console.error(err);
  } finally {
    if (Oracleconnection) {
      try {
        await Oracleconnection.close();
      } catch (err) {
        console.error(err);
      }
    }
  }
});



app.post('/make',verifyToken, async (req, res) => {
  const searchString = req.body.itemValue;
  try {
    Oracleconnection = await oracledb.getConnection({
      user: 'bokarosteel',
      password: 'bokarosteel123',
      connectString: '10.143.11.45/ractsh',
    });
	//console.log(searchString);
   const result = await Oracleconnection.execute(
    `SELECT ID,MAKE FROM INCIDENT_MAKE_MASTER WHERE MAIN_CAT_ID = :username`,[searchString]);

   res.json(result);
	
  } catch (err) {
    console.error(err);
  } finally {
    if (Oracleconnection) {
      try {
        await Oracleconnection.close();
      } catch (err) {
        console.error(err);
      }
    }
  }
});


app.post('/complain',verifyToken, async (req, res) => {
  const data = req.body;
  let assgn_to1;
 
  console.log(data.main_cat);

  try {
    Oracleconnection = await oracledb.getConnection({
      user: 'bokarosteel',
      password: 'bokarosteel123',
      connectString: '10.143.11.45/ractsh',
	  autoCommit: true, // Enable auto-commit
    });

// Check if a complaint with the same STNO, main_cat, and sub_cat already exists
	const checkResult = await Oracleconnection.execute(
	  `SELECT COUNT(*) AS COUNT FROM INCIDENT WHERE STNO = :stno AND PROB_CAT = :main_cat AND PROB_SUB_CAT = :sub_cat AND STATUS=0`,
	  { stno: data.stno, main_cat: data.main_cat, sub_cat: data.sub_cat }
	);

	if (checkResult.rows[0][0] > 0) {
	  // Complaint already exists
	  res.json({ message: 'Complaint already exists for the same category' });
	} else {
	  // Insert new complaint
	  // ...
    if (['28', '30', '31', '32', '33', '34', '35'].includes(data.main_cat)) {
      assgn_to1 = '111000';
    } else if (data.main_cat === '4' && data.sub_cat === '9') {
      assgn_to1 = '700000';
    } else if (data.make ==='') {
      const result = await Oracleconnection.execute(
        `SELECT MAINT_TEAM FROM INCIDENT_SUB_CAT_MAST WHERE MAIN_CAT_ID = :main_cat AND SUB_CAT_ID = :sub_cat`,
        { main_cat: data.main_cat, sub_cat: data.sub_cat }
      );
      assgn_to1 = result.rows[0][0];
    } else {
      const result = await Oracleconnection.execute(
        `SELECT AGENCY_CODE FROM INCIDENT_MAKE_MASTER WHERE MAIN_CAT_ID = :main_cat AND ID = :make`,
        { main_cat: data.main_cat, make: data.make }
      );
      assgn_to1 = result.rows[0][0];
    }
    const lastIdResult = await Oracleconnection.execute(
      `SELECT MAX(ID) AS LAST_ID FROM INCIDENT where id>80631`
    );
	
    const lastId = parseInt(lastIdResult.rows[0][0]) || 0;
    const newId = lastId + 1; 
	
    const result = await Oracleconnection.execute(
      `INSERT INTO INCIDENT (ID, STNO, NAME, DESIG, DEPT, MOBILE, EMAIL, LOCATION, MAXNO, AREA, SAPYN,
        DOMYN, AVYN, PROB_CAT, PROB_SUB_CAT, REMARKS, ASSGN_TO, STATUS, CREATED, CREATED_BY, MAKE,
        IP_ADDR, OS_TYPE, ENOTE_NO, SERIAL_NO,DOCUMENT)
        VALUES (:id, :stno, :name, :desig, :dept, :mobile, :email, :location, :maxno, :area, :sapyn,
        :domyn, :avyn, :prob_cat, :prob_sub_cat, :remarks, :assgn_to, :status,
        TO_TIMESTAMP(:created, 'YYYY-MM-DD"T"HH24:MI:SS.ff3"Z"'), :created_by, :make, :ip_addr, :os_type, :enote_no, :serial_no, :document)`,
      {
        id: newId, 
        stno: data.stno,
        name: data.name,
        desig: data.desig,
        dept: data.dept,
        mobile: data.mob,
        email: data.email,
        location: data.location,
        maxno: data.maxno,
        area: data.area,
        sapyn: data.sapyn,
        domyn: data.domyn,
        avyn: data.avyn,
        prob_cat: data.main_cat,
        prob_sub_cat: data.sub_cat,
        remarks: data.remarks,
        assgn_to: assgn_to1,
        status: data.status,
        created: data.created,
        created_by: data.created_by,
        make: data.make,
        ip_addr: data.ip_addr,
        os_type: data.os_type,
        enote_no: data.enote_no,
        serial_no: data.serial_no,
        document:data.document,
      }
    );
	
	//console.log(result);
	await Oracleconnection.commit();
	sendMsg(data.mob,data.name,newId,data.remarks);
	
	const selectResult = await Oracleconnection.execute(
		  `SELECT * FROM INCIDENT WHERE ID = :id`,
		  { id: newId }
		);
		//console.log(selectResult.rows);

    res.json(selectResult.rows);
	}
  } catch (err) {
    console.error(err);
  } finally {
    if (Oracleconnection) {
      try {
        await Oracleconnection.close();
      } catch (err) {
        console.error(err);
      }
    }
  }
});


app.get('/complaints/:stno', async (req, res) => {

  try {

    const QUERY = `
      SELECT 
        i.ID, 
        i.Created,
        mc.MAIN_CAT_NAME AS CAT_NAME,
        sc.SUB_CAT_NAME AS SUB_CAT_NAME,
        CASE
          WHEN i.STATUS = 0 THEN 'New'
          WHEN i.STATUS = 1 THEN 'In Progress' 
          WHEN i.STATUS = 2 THEN 'Forwarded'
          WHEN i.STATUS = 3 THEN 'Closed'  
        END AS STATUS  
      FROM (
        SELECT DISTINCT i.ID
        FROM INCIDENT i
        WHERE i.STNO = :stno AND i.status IN (0, 1, 2)  
      ) ids
      JOIN INCIDENT i ON i.ID = ids.ID
      JOIN INCIDENT_MAIN_CAT_MAST mc ON i.PROB_CAT = mc.MAIN_CAT_ID 
      JOIN INCIDENT_SUB_CAT_MAST sc ON i.PROB_CAT = sc.MAIN_CAT_ID AND i.PROB_SUB_CAT = sc.SUB_CAT_ID
      ORDER BY i.ID DESC
    `;
    
    const connection = await oracledb.getConnection({
      user: 'bokarosteel',
      password: 'bokarosteel123',
      connectString: '10.143.11.45/ractsh'
    });

    const stno = req.params.stno;

    const result = await connection.execute(QUERY, { stno }, {
      outFormat: oracledb.OUT_FORMAT_OBJECT  
    });

    connection.close();

    res.json(result.rows);

  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching complaints'); 
  }

});
app.get('/Rcomplaints/:stno', async (req, res) => {

  try {

    const QUERY = `
      SELECT 
        i.ID, 
        i.Created,
        i.LOCATION,
        mc.MAIN_CAT_NAME AS CAT_NAME,
        CASE
          WHEN i.STATUS = 0 THEN 'New'
          WHEN i.STATUS = 1 THEN 'In Progress' 
          WHEN i.STATUS = 2 THEN 'Forwarded'
          WHEN i.STATUS = 3 THEN 'Closed'  
        END AS STATUS  
      FROM (
        SELECT DISTINCT i.ID
        FROM INCIDENT i
        WHERE i.STNO = :stno AND i.status IN (0, 1, 2)  AND ASSGN_TO = '111000'
      ) ids
      JOIN INCIDENT i ON i.ID = ids.ID
      JOIN INCIDENT_MAIN_CAT_MAST mc ON i.PROB_CAT = mc.MAIN_CAT_ID
      ORDER BY i.ID DESC
    `;
    
    const connection = await oracledb.getConnection({
      user: 'bokarosteel',
      password: 'bokarosteel123',
      connectString: '10.143.11.45/ractsh'
    });

    const stno = req.params.stno;

    const result = await connection.execute(QUERY, { stno }, {
      outFormat: oracledb.OUT_FORMAT_OBJECT  
    });

    connection.close();

    res.json(result.rows);

  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching complaints'); 
  }

});

const { spawn } = require('child_process');

app.get('/eis', async (req, res) => {
  try {
    // Read Text Files (asynchronously)
    const emdnow = await fs1.readFile('C:\\PPC\\emdnow.txt', 'utf8');
    const bf1 = await fs1.readFile('C:\\PPC\\bf1.txt', 'utf8');
    const bf2 = await fs1.readFile('C:\\PPC\\bf2.txt', 'utf8');
    const bf3 = await fs1.readFile('C:\\PPC\\bf3.txt', 'utf8');
    const bf4 = await fs1.readFile('C:\\PPC\\bf4.txt', 'utf8');
    const bf5 = await fs1.readFile('C:\\PPC\\bf5.txt', 'utf8');



    // ... (Similarly read other text files)

    // Parse Text File Data
    const emdnowData = emdnow.trim().split(',');
    const bf1Data = bf1.trim().split(',');
    const bf2Data = bf2.trim().split(',');
    const bf3Data = bf3.trim().split(',');
    const bf4Data = bf4.trim().split(',');
    const bf5Data = bf5.trim().split(',');
    // ... (Similarly parse other text files)



    // Read Excel data
    const ppchrlyData = await readExcelData('C:\\PPC\\ppchrly.xlsx');
    const ppcdelayData = await readExcelData('C:\\PPC\\ppcdelay.xlsx');

    //const ppchrlyLastRow = ppchrlyData.pop(); // Remove & get the last row
   // const ppcdelayLastRow = ppcdelayData.pop();
    

    // Create the Response Object
    const responseData = {
      textFileData: {
        emdnow: emdnowData,
        bf1: bf1Data,
        bf2: bf2Data,
        bf3: bf3Data,
        bf4: bf4Data,
        bf5: bf5Data,
        // ... add other parsed text file data
      },
      dbfData: {
        ppchrly: ppchrlyData,
        ppcdelay: ppcdelayData
      }
    };

    // Send the Response
    res.json(responseData); 
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Helper function for reading Excel data asynchronously
async function readExcelData(filePath) {
  try {
    const fileBuffer = await fs1.readFile(filePath);
    const workbook = xlsx.read(fileBuffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    return xlsx.utils.sheet_to_json(worksheet);
  } catch (error) {
    console.error('Error parsing Excel data:', error);
    throw error; // Re-throw the error to the main catch block
  }
}


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


//-------------------BSLGPT--------
const bodyParser = require('body-parser');
const {
  GoogleGenerativeAI,
  HarmCategory,
  HarmBlockThreshold,
} = require('@google/generative-ai');

app.use(bodyParser.json());

const MODEL_NAME = 'gemini-pro';
const API_KEY2 = 'AIzaSyB6-09PWaDzEGW475w4S3tfJm8nUj0g7Xk';
const GroqAPI ='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';

async function generateResponse(userInput, chatHistory) {
  const genAI = new GoogleGenerativeAI(API_KEY2);

  const generationConfig = {
    temperature: 0.9,
    topK: 1,
    topP: 1,
    maxOutputTokens: 1048576,
  };

  const safetySettings = [
    {
      category: HarmCategory.HARM_CATEGORY_HARASSMENT,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
      category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
      category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
      category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
  ];

  const model = genAI.getGenerativeModel({ model: MODEL_NAME, generation_config : generationConfig, safety_settings: safetySettings});

  

  
  try {
    // Ensure chatHistory is an array
    const chatHistoryArray = Array.isArray(chatHistory) ? chatHistory : [];

    const chat = model.startChat(history= chatHistoryArray
    );

    const result = await chat.sendMessage(userInput);
    const response = result.response;
    logToDatabase(userInput,response.text())
    return response.text();
  } catch (error) {
    console.error(error);
    return 'Internal server error';
  }
};

const { Groq } = require('groq-sdk');
const groq = new Groq({ apiKey: GroqAPI });

async function generateGroqResponse(userInput, chatHistory) {
  try {
    // Ensure chatHistory is an array
    const chatHistoryArray = Array.isArray(chatHistory) ? chatHistory : [];

    // Stage 1: Prepare chat history for GROQ
    const groqChatHistory = chatHistoryArray.map(message => {
      if(message.role =='model') {message.role ='assistant';}
      return {
        role: message.role,
        content: message.parts.text
      };
    });

    const userArray =
    [{
      role: "user",
      content: userInput
    }];


    console.log(groqChatHistory);
    console.log(userArray);
    // Stage 2: Call GROQ API to generate response
    const chatCompletion = await groq.chat.completions.create({
      messages: userArray,
      model: 'mixtral-8x7b-32768',
      temperature: 0.9,
      max_tokens: 1048576,
      top_p: 1,
      stream: false,
      stop: null
    });

    let response = '';
    for await (const chunk of chatCompletion) {
      response += chunk.choices[0]?.delta?.content || '';
    }

    return response;
  } catch (error) {
    console.error(error);
    return 'Internal server error';
  }
}

app.post('/grocgpt', async (req, res) => {
  
  const originalUserInput = req.body.userInput;
  const chatHistory = req.body.history;

  console.log("inside bslgpt");

  if (!originalUserInput) {
    return res.status(400).json({ error: 'Missing User Input' });
  }

  const MAX_HISTORY_TOKENS = 500;
  const trimmedHistory = Array.isArray(chatHistory) ? chatHistory.slice(-MAX_HISTORY_TOKENS) : [];


  try {
    const responseText = await generateGroqResponse(originalUserInput, trimmedHistory);
    res.json({ result: responseText });
  } catch (error) {
    console.error('Error in processing request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});





app.post('/bslgpt', async (req, res) => {
  const originalUserInput = req.body.userInput;
  const chatHistory = req.body.history;


  const MAX_HISTORY_TOKENS = 500; // Customize this value
  const chatHistoryArray = Array.isArray(chatHistory) ? chatHistory : [];

  // Trim based on number of tokens (you might need a tokenizer function)
  const trimmedHistory = chatHistoryArray.slice(-MAX_HISTORY_TOKENS); 


  if (!originalUserInput) {
    return res.status(400).json({ error: 'Missing user input' });
  }

const originalUserInput1 = ` I am an employee of Bokaro Steel Plant,: "${originalUserInput} at bokaro steel plant?",answer like a private chatbot of Bokaro Steel plant from information available on internet`;


  try {
    // const responseText = await generateResponse(
    //   modifiedUserInput,
    //   trimmedHistory
    // );

  // Stage 1: Get Original Response 
  const responseText = await generateResponse(originalUserInput1, trimmedHistory);

  //const responseText = await generateResponse(originalResponse);


    res.json({ result: responseText });
  } catch (error) {
    console.error('Error in processing request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

//-------------BSLGPT----------------

//-------------------GOR--------

async function generateResponseGOR(userInput, chatHistory) {
  const genAI = new GoogleGenerativeAI(API_KEY2);

  const generationConfig = {
    temperature: 0.9,
    topK: 1,
    topP: 1,
    maxOutputTokens: 1048576,
  };

  const safetySettings = [
    {
      category: HarmCategory.HARM_CATEGORY_HARASSMENT,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
      category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
      category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
      category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
  ];

  const model = genAI.getGenerativeModel({ model: MODEL_NAME, generation_config : generationConfig, safety_settings: safetySettings});

  try {
    // Ensure chatHistory is an array
    const chatHistoryArray = Array.isArray(chatHistory) ? chatHistory : [];
    const chat = model.startChat(history=chatHistoryArray);
    const result = await chat.sendMessage(userInput);
    const response = result.response;
    return response.text();
  } catch (error) {
    console.error(error);
    return 'Internal server error';
  }
}


app.post('/gorgpt', async (req, res) => {
  const originalUserInput = req.body.userInput;
  const chatHistory = req.body.history;

  console.log('Original User Input:', originalUserInput);
  console.log('Chat History:', chatHistory);

  if (!originalUserInput) {
    return res.status(400).json({ error: 'Missing user input' });
  }

  const modifiedUserInput = `An Employee of Rajasthan Government is saying "${originalUserInput} ?" respond like a private bot of Government of Rajasthan trained on all Circulars of Govenment of Rajasthan , give minimilistic response which is true feels like human conversation`;

  try {
    const responseText = await generateResponseGOR(
      modifiedUserInput,
      chatHistory
    );
    res.json({ result: responseText });
  } catch (error) {
    console.error('Error in processing request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

//-------------GOR----------------

//-------edesk login-----
const https = require('https');

app.post('/edesklogin', async (req, res) => {
  console.log('in edesk login');
  try {
      const { username, password } = req.body;

      console.log(username);

      // Check if username and password are provided
      if (!username || !password) {
          return res.status(400).json({ success: false, message: 'Username and password are required' });
      }

      // Make a request to the Edesk API
     
      const response = await axios.post('https://edesk.sailbsl.in/api/token/', {
          username,
          password
      }, {
          httpsAgent: new https.Agent({ rejectUnauthorized: true }),
          timeout: 10000
      });
      const token = jwt.sign({ id: username }, secretKey);
      console.log(token);
      // If the request is successful, return a success message
      //console.log(token);
      res.json({ success: true, message: 'API call successful', data: response.data, token:token });
  } catch (error) {
      // If there's an error, return an error message
      console.error('Error:', error.message);
      res.status(500).json({ success: false, message: 'An error occurred' });
  }
});

//---edesk


const server = app.listen(3000, '10.143.106.145', () => {
  console.log('Server is running on port 3000');
});

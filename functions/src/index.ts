

  const {onRequest} = require("firebase-functions/v2/https");

  const mailgun = require('mailgun-js');

  // The Firebase Admin SDK to access Firestore.
  const {initializeApp} = require("firebase-admin/app");
  const {getFirestore} = require("firebase-admin/firestore");
  const {getAuth} = require("firebase-admin/auth")
  initializeApp();
  const jwt = require('jsonwebtoken');
  import * as dotenv from 'dotenv'
  dotenv.config() 


  const express = require('express');
  const app = express();
  const db = getFirestore();

  // Middleware to authenticate Firebase users

  // Middleware to authenticate requests using JWT
  const authenticate = (req:any, res:any, next:any) => {
    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith('Bearer ')) {
      return res.status(401).send({ message: 'Unauthorized' });
    }
    //const jwtSecret = process.env.JWT_SECRET;
    const jwtSecret = process.env.JWT
    const token = authorization.split('Bearer ')[1];
    console.log(jwtSecret +"token: "+token)

    const JWT_SECRET = jwtSecret;

    jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }, (err:any, decoded:any) => {
      if (err) {
        return res.status(403).send({ message: 'Forbidden', error: err.message });
      }
      console.log(decoded); // Proceed if valid
      next();

    });
    
  };
    
    // Apply the authentication middleware to all routes
    app.use(authenticate);
    app.use(express.json());

    

    app.get('/:id', (req:any, res:any) => {
      // Only authenticated users can access this route
      res.send({ message: 'Authenticated user can access this route', userId: req.user.uid });
    });
    
    app.post('/', (req:any, res:any) => {
      // Handle creation logic

      res.send({ message: 'New widget created!' });
    });


    // POST request handler for creating a new user
  app.post('/createUser', async (req:any, res:any) => {
      const { email, password } = req.body;
    
      if (!email || !password) {
        return res.status(400).send({ message: 'Email and password are required' });
      }
    
      try {
        // Check if the user already exists in Firestore
        const userSnapshot = await db.collection('users').where('email', '==', email).get();
    
        if (!userSnapshot.empty) {
          return res.status(400).send({ message: 'User already exists' });
        }
    
        // Create the new user in Firebase Auth
        const userRecord = await getAuth()
        .createUser({
          email,
          password,
        });
    
        // Save the user in Firestore with verified set to false
        await db.collection('users').doc(userRecord.uid).set({
          email,
          verified: false,
        });
    
        // Send the verification email
        await sendVerificationEmail(email, userRecord.uid, res);
    
        return res.status(201).send({
          message: 'User created successfully. Please verify your email.',
          uid: userRecord.uid,
        });
      } catch (error) {
        console.error('Error creating user:', error);
      
        // Check if error is an instance of Error
        if (error instanceof Error) {
          return res.status(500).send({ message: 'Error creating user', error: error.message });
        } else {
          // Handle case where error is not an instance of Error
          return res.status(500).send({ message: 'An unknown error occurred' });
        }
      }
    });

    // Helper function to send a verification email
  const sendVerificationEmail = async (email: string, uid: string, res:any) => {
    async function sendCustomEmailVerification(email: string, link: string){
      const mailgunApiKey = process.env.MAILGUNAPIKEY;
      const mailgunDomain = process.env.MAILGUNDOMAIN;
      
      const mg = mailgun({ apiKey: mailgunApiKey, domain: mailgunDomain });

      // Example usage of Mailgun


    const sendEmail = (email: string, subject: string, html: string) => {
      const data = {
        from: 'hello@mail.quantumcompass.xyz',
        to: email,
        subject: subject,
        html: html,
      };
      
      return mg.messages().send(data);
    
    }
    let html = "Welcome 🚀🌓! Please verify your email 👉<a href='"+link+"'>Click Here to Verify</a>"
  await sendEmail(email, "Welcome to Quantum Compass",html)

  }
    try{
    const user = await getAuth().getUserByEmail(email);
    if (true) {
  console.log(user+ ": user")

      const actionCodeSettings = {
        url: 'https://api.quantumcompass.xyz/verify/'+uid, // This is the URL the user will be redirected to after verifying
        handleCodeInApp: true, // Whether the verification should be handled in the app
      };
      
      getAuth()
    .generateEmailVerificationLink(email, actionCodeSettings)
    .then((link:string) => {
      return  sendCustomEmailVerification(email, link);
      console.log('Verification email sent.'); // The verification email is sent by Firebase
      console.log(link); // This is the link, but Firebase sends the email
    })
    .catch((error:any) => {
      console.error('Error sending verification email:', error);
    });



      return true;
    }
    return false;
  }catch(err){
    return res.status(201).send({isAnEmailErr: err})
  }
  };
    
    
    // Expose Express API as a Firebase Cloud Function
    exports.wid = onRequest(app);
    


const express = require('express');
const app = express();
const cors = require('cors');
const port = process.env.API_PORT || 4444;

const bcrypt = require('bcrypt');
const saltRounds = 13;

const users = require('./data').users;

//handle json body request
app.use(express.json());
app.use(cors());

// WARNING DATA FROM CLIENT NOT BEING SANITIZED

app.post('/register', async (req, res) => {
  //get the email and password from req.body
  //check for no duplicate email
  let userMatch = users.find((user) => req.body.email === user.email);
  if (!userMatch) {
    //TODO: hash the password with bcrypt.hash()
    let passHash = await bcrypt.hash(req.body.password, saltRounds);
    //add to the users data
    let newUser = {
      _id: Date.now(),
      email: req.body.email,
      password: passHash,
    };
    users.push(newUser);
    console.log('Full user list', users);
    //send a response
    res.status(201).send({ data: newUser });
  } else {
    res
      .status(400)
      .send({ error: { code: 400, message: 'Email address already used' } });
  }
});

app.post('/login', async (req, res) => {
  //get the email and password from req.body
  //find the match for the email
  let userMatch = users.find((user) => req.body.email === user.email);
  if (userMatch) {
    //validate the password using bcrypt
    let submittedPass = req.body.password; //plain text from browser
    let savedPass = userMatch.password; //that has been hashed
    //TODO: use bcrypt.compare() to actually hash and compare the password
    const passwordDidMatch = await bcrypt.compare(submittedPass, savedPass);
    if (passwordDidMatch) {
      res.status(200).send({ data: { token: 'this is a pretend token' } });
    } else {
      res.status(401).send({
        error: { code: 401, message: 'invalid username or password.' },
      });
    }
  } else {
    //cause a delay to hide the fact that there was no match
    let fakePass = `$2b$${saltRounds}$invalidusernameaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`;
    await bcrypt.compare(submittedPass, fakePass);
    //to slow down the process
    res
      .status(401)
      .send({ error: { code: 401, message: 'invalid username or password.' } });
  }
});

app.listen(port, function (err) {
  if (err) {
    console.error('Failure to launch server');
    return;
  }
  console.log(`Listening on port ${port}`);
});

/**
 * With a ~2GHz processor approximation...
 * 2^rounds of hashing
 * 
rounds=8 : ~40 hashes/sec
rounds=9 : ~20 hashes/sec
rounds=10: ~10 hashes/sec
rounds=11: ~5  hashes/sec
rounds=12: 2-3 hashes/sec
rounds=13: ~1 sec/hash
rounds=14: ~1.5 sec/hash
rounds=15: ~3 sec/hash
rounds=25: ~1 hour/hash
rounds=31: 2-3 days/hash
 */

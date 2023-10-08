const express = require('express');
const cors = require("cors");
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const passport = require('passport')
const profile = require('./routes/api/profile')
const auth = require('./routes/api/auth')

const port = 8000;
const app = express();

// middleware for bodyparser
app.use(bodyParser.urlencoded({extended: false}))
app.use(cors());

const settings = require("./config/settings")
const db = settings.mongoDBUrl

mongoose
    .connect(db)
    .then(() => console.log("MongoDB connected succesfully."))
    .catch((err) => console.log(err))


// actual routes
app.use('/api/profile', profile)
app.use('/api/auth', auth)


app.get('/', (req, res) => {
    res.send("Project is Running");
 
});

// Config for JWT strategy
require('./strategies/jsonwtStrategy')(passport)
/**
 * @api {get} Handles all not found URLs.
 */
app.get('*', function (req, res) {
    res.render('error', { title: 'Error', message: 'Wrong Route' });
});



app.listen(port, () => {
    console.log(`App is running at port: ${port}`);
});

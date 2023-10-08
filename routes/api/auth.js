const express = require('express')
const bcrypt = require('bcryptjs')
var cookie = require('cookie-parser')
const jwt = require('jsonwebtoken')
const passport = require('passport')

// getting setting
const settings = require('../../config/settings')

const router = express.Router()

const Manager = require('./../../models/Manager')
const Supervisor = require('./../../models/Supervisor')
const Resident = require('./../../models/Resident')
const Security = require('./../../models/Security')

router.use(cookie())


//@type     -   GET
//@route    -   /api/profile
//@desc     -   Just for testing
//@access   -   PUBLIC
router.get('/', (req, res) => res.send('Auth related routes'))

// Route to register a user. URL : /api/auth/register
router.post('/register/manager', (req, res) => {
    // check if username is already in collection.
    Manager
        .findOne({username: req.body.username})
        .then(person => {
            if (person) {
                res.status(400).send('Username already there.')
            } else {
                
                const person = Manager({
                    name: req.body.name,
                    username: req.body.username,
                    password: req.body.password
                })

                // encrypting the password using bcryptjs
                bcrypt.genSalt(10, (err, salt) => {
                    // salt is provided in salt variable.
                    bcrypt.hash(person.password, salt, (err, hash) => {
                        if(err) {
                            return res.status(400).send('Not Registered, Contact Admin!')
                        }
                        else {
                            // hashed password
                            person.password = hash

                            // add new person with hashed password.
                            person
                                .save()
                                .then(person => res.send('Manager added successfully.'))
                                .catch(err => res.send(err.message))
                        }
                    })
                })
            }
        })
        .catch(err => res.send(err))
})

router.post('/login', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    try {
        // Try to find the user in the manager collection
        const manager = await Manager.findOne({ username: username });

        if (manager) {
            // User found in the manager collection, compare the password
            const isCompared = await bcrypt.compare(password, manager.password);

            if (isCompared) {
                // Authentication successful, generate token
                const payload = {
                    id: manager.id,
                    name: manager.name,
                    username: manager.username,
                    role: 'manager'
                };

                const token = jwt.sign(payload, settings.secret, { expiresIn: 3600 });

                return res.json({
                    success: true,
                    role: 'manager',
                    token: 'Bearer ' + token
                });
            } else {
                return res.status(401).send('Password is not correct');
            }
        } else {
            // User not found in the manager collection, try supervisor collection
            const supervisor = await Supervisor.findOne({ username: username });

            if (supervisor) {
                // User found in the supervisor collection, compare the password
                const isCompared = await bcrypt.compare(password, supervisor.password);

                if (isCompared) {
                    // Authentication successful, generate token
                    const payload = {
                        id: supervisor.id,
                        name: supervisor.name,
                        username: supervisor.username,
                        role: 'supervisor'
                    };

                    const token = jwt.sign(payload, settings.secret, { expiresIn: 3600 });

                    return res.json({
                        success: true,
                        role: 'supervisor',
                        token: 'Bearer ' + token
                    });
                } else {
                    return res.status(401).send('Password is not correct');
                }
            } else {
                // Try resident collection
                const resident = await Resident.findOne({ username: username });

                if (resident) {
                    // User found in the resident collection, compare the password
                    const isCompared = await bcrypt.compare(password, resident.password);

                    if (isCompared) {
                        // Authentication successful, generate token
                        const payload = {
                            id: resident.id,
                            name: resident.name,
                            username: resident.username,
                            role: 'resident'
                        };

                        const token = jwt.sign(payload, settings.secret, { expiresIn: 3600 });

                        return res.json({
                            success: true,
                            role: 'resident',
                            name: resident.name,
                            token: 'Bearer ' + token
                        });
                    } else {
                        return res.status(401).send('Password is not correct');
                    }
                } else {
                    // Try security collection
                    const security = await Security.findOne({ username: username });

                    if (security) {
                        // User found in the security collection, compare the password
                        const isCompared = await bcrypt.compare(password, security.password);

                        if (isCompared) {
                            // Authentication successful, generate token
                            const payload = {
                                id: security.id,
                                name: security.name,
                                username: security.username,
                                role: 'security'
                            };

                            const token = jwt.sign(payload, settings.secret, { expiresIn: 3600 });

                            return res.json({
                                success: true,
                                role: 'security',
                                token: 'Bearer ' + token
                            });
                        } else {
                            return res.status(401).send('Password is not correct');
                        }
                    } else {
                        // User not found in any collection
                        return res.status(400).send('Username does not exist.');
                    }
                }
            }
        }
    } catch (error) {
        console.error('Error:', error);
        return res.status(500).send('Internal Server Error');
    }
});

router.get(
    '/get',
    passport.authenticate('jwt', { session: false }), // middleware from passport-jwt
    async(req, res) => {
    res.send("Protected Route")
})


// Route to register a user. URL : /api/auth/register
router.post('/register/supervisor',
passport.authenticate('jwt', { session: false }), // middleware from passport-jwt
 (req, res) => {
    // check if username is already in collection.
    const type = req.body.type;
    const username = req.body.username;
    
    if(type && username)
    {
        const supervisorPromise = Supervisor.findOne({ username });
        const residentPromise = Resident.findOne({ username });
        const securityPromise = Security.findOne({ username });
    
    Promise.all([supervisorPromise, residentPromise, securityPromise])
        .then(([supervisor, resident, security]) => {
            if (supervisor || resident || security) {
                //flag = 1;
                return res.send("Username already exists.")
            }
            // Continue with your logic based on the flag value
            else
            {
                if(type === 'supervisor')
                {
        
                    const person = Supervisor({
                        name: req.body.name,
                        username: req.body.username,
                        password: req.body.password
                    })
    
                    // encrypting the password using bcryptjs
                    bcrypt.genSalt(10, (err, salt) => {
                        // salt is provided in salt variable.
                        bcrypt.hash(person.password, salt, (err, hash) => {
                            if(err) {
                                return res.status(400).send('Not Registered, Contact Admin!')
                            }
                            else {
                                // hashed password
                                person.password = hash
    
                                // add new person with hashed password.
                                person
                                    .save()
                                    .then(supervisor => {
                                        const payload = {
                                            id: supervisor.id,
                                            name: supervisor.name,
                                            username: supervisor.username,
                                            role: 'supervisor'
                                        };
                    
                                        const token = jwt.sign(payload, settings.secret, { expiresIn: 3600 });
                    
                                        return res.json({
                                            success: true,
                                            role: 'supervisor',
                                            token: 'Bearer ' + token
                                        });
                                    })
                                    .catch(err => res.send(err.message))
                            }
                        })
                    })
        }
        else if(type === 'resident')
        {
                    const person = Resident({
                        name: req.body.name,
                        username: req.body.username,
                        password: req.body.password
                    })
    
                    // encrypting the password using bcryptjs
                    bcrypt.genSalt(10, (err, salt) => {
                        // salt is provided in salt variable.
                        bcrypt.hash(person.password, salt, (err, hash) => {
                            if(err) {
                                return res.status(400).send('Not Registered, Contact Admin!')
                            }
                            else {
                                // hashed password
                                person.password = hash
    
                                // add new person with hashed password.
                                person
                                    .save()
                                    .then(resident => {
                                        const payload = {
                                            id: resident.id,
                                            name: resident.name,
                                            username: resident.username,
                                            role: ''
                                        };
                    
                                        const token = jwt.sign(payload, settings.secret, { expiresIn: 3600 });
                    
                                        return res.json({
                                            success: true,
                                            role: 'resident',
                                            name: resident.name,
                                            token: 'Bearer ' + token
                                        });
                                    })
                                    .catch(err => res.send(err.message))
                            }
                        })
                    })
        }
        else if(type === 'security')
        {
                    const person = Security({
                        name: req.body.name,
                        username: req.body.username,
                        password: req.body.password
                    })
    
                    // encrypting the password using bcryptjs
                    bcrypt.genSalt(10, (err, salt) => {
                        // salt is provided in salt variable.
                        bcrypt.hash(person.password, salt, (err, hash) => {
                            if(err) {
                                return res.status(400).send('Not Registered, Contact Admin!')
                            }
                            else {
                                // hashed password
                                person.password = hash
    
                                // add new person with hashed password.
                                person
                                    .save()
                                    .then(security => { 
                                        const payload = {
                                        id: security.id,
                                        name: security.name,
                                        username: security.username,
                                        role: 'security'
                                    };
    
                                    const token = jwt.sign(payload, settings.secret, { expiresIn: 3600 });
                                        return res.json({
                                            success: true,
                                            role: 'security',
                                            token: 'Bearer ' + token
                                        });
                                    })
                                    .catch(err => res.send(err.message))
                            }
                        })
                    })
        }
            }
        })
        .catch(err => {
            // Handle errors if any of the findOne operations fail
            console.error(err);
        });
     
    }
    else
    {
        res.send("Fields cannot be empty")
    }
        
})


module.exports = router
const express = require('express')
const router = express.Router()


//@type     -   GET
//@route    -   /api/profile
//@desc     -   Just for testing
//@access   -   PUBLIC
router.get('/', (req, res) => res.send('Profile related routes'))


module.exports = router
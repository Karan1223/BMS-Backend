const mongoose = require('mongoose')
const Schema = mongoose.Schema

const SecuritySchema = new Schema({
    name:
    {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
})

module.exports = Security = mongoose.model('security', SecuritySchema)
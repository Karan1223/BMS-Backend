const mongoose = require('mongoose')
const Schema = mongoose.Schema

const ResidentSchema = new Schema({
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

module.exports = Resident = mongoose.model('resident', ResidentSchema)
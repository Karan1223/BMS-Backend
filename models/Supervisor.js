const mongoose = require('mongoose')
const Schema = mongoose.Schema

const SupervisorSchema = new Schema({
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

module.exports = Supervisor = mongoose.model('supervisor', SupervisorSchema)
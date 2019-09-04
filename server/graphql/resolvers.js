const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const User = require('../models/user');

module.exports = {
    createUser: async function({ userInput }, req) {
        const errors = [];
        if(!validator.isEmail(userInput.email)) {
            errors.push({message: 'Invalid email!'});
        }        
        if (
            validator.isEmpty(userInput.password) ||
            !validator.isLength(userInput.password, {min: 5})
        ) {
            errors.push({message: 'Password too short'})
        }
        const existingUser = await User.findOne({ email: userInput.email });
        if (existingUser) {
            const error = new Error('User exists already!');
            throw error;
        }
        if (errors.length > 0) {
            const error = new Error('Invalid Input');
            error.data = errors;
            error.code = 422;
            throw error;
        }
        const hashedPw = await bcrypt.hash(userInput.password, 12);
        const user = new User({
            email: userInput.email,
            name: userInput.name,
            password: hashedPw
        });
        const createdUser = await user.save();
        return { ...createdUser._doc, _id: createdUser._id.toString() };
    },
    login: async function({email, password}) {
        const user = await User.findOne({email: email});
        if (!user) {
            const error = new Error('User not found.');
            errror.code = 401;
            throw error;
        }
        const isEqual = await bcrypt.compare(password, user.password);
        if (!isEqual) {
            const error = new Error('Password is not correct.');
            error.code = 401;
            throw error;
        }
        const token = jwt.sign(
            { 
                userId: user._id.toString(),
                email: user.email
            }, 
            process.env.SECRET, 
            {expiresIn: '1h'}
        );
        return {token: token, userId: user._id.toString()};
    }
};
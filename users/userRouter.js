const express = require("express")
const Users = require('./userModel')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { restrict } = require('./userMiddleware')

const router = express.Router()

router.get("/", (req, res, next) => {
	res.json({
		message: "its go time 🔥  ",
	})
})
//✅ welcome - initial test on server

router.post('/api/register', async (req, res, next) => {
    try {
     const { username, password, department } = req.body
     const user = await Users.findBy({username})

     if(user) {
         return res.status(409).json({
             message:'username already taken, try again'
         })
     }
     const newUser = Users.add({
         username,
         // hash the password with a time complexity of "14"
         password: await bcrypt.hash(password, 14),
         department
     })

     res.status(201).json(newUser)

    } catch(err){
        next(err)
    }
})
//✅ Creates a user using the information sent inside the body of the request. Hash the password before saving the user to the database.

router.post('/api/login', async (req, res, next) => {
    try {
        const { username, password, department } = req.body
        const user = await Users.findBy({username})

        if(!user){
            return res.status(401).json({
                message:'You shall not pass!'
            })
        }

        // hash the password again and see if it matches what we have in the database
        const passwordValid = await bcrypt.compare(password, user.password)

        if(!passwordValid){
            return res.status(401).json({
                message:'You shall not pass!'
            })
        }
        //create a token
        const token = jwt.sign({
            userId: user.id,
            userDept: user.department,
        }, process.env.JWT_SECRET )

        res.cookie('token', token)

        res.json({
            message: `Welcome ${user.username}`
        })
    } catch (err) {
        next(err)
    }
})
//✅ Use the credentials sent inside the body to authenticate the user. On successful login, create a new JWT with the user id as the subject and send it back to the client. If login fails, respond with the correct status code and the message: 'You shall not pass!'

router.get('/api/users', restrict('athletics'), async (req, res, next) => {
    try {
        res.json(await Users.find())
    } catch (err) {
        next(err)
    }
})
//✅ If the user is logged in, respond with an array of all the users contained in the database. If the user is not logged in respond with the correct status code and the message: 'You shall not pass!'.


module.exports = router
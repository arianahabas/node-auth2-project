const jwt = require('jsonwebtoken')


function restrict() {
	return async (req, res, next) => {
		try {

			//get the token value from a cookie, which is automatically sent from the client
			const token = req.cookies.token

			if (!token) {
				return res.status(401).json({
					message: "invalid credentials"
				})
			}
			//make sure the signature on the token is valid and still matches the payload
			//we need to use the same secreet string that was used to sign the token
			jwt.verify(token, process.env.JWT_SECRET , (err, decoded) => {
				if(err){
					return res.status(401).json({
						message: "invalid credentials"
					})
				}

				// if(role && roles.indexOf(decoded.userRole) < roles.indexOf(role)) {
				// 	return res.status(401).json({
				// 		message: "invalid credentials"
				// 	})
				// }
				
				//make the tokens decoded payload avialable to other middleware functions or route handlers, in case we want to use it for something
				req.token = decoded
				console.log(decoded)

				//at this point we know the token is valid and the user is authorized
				next()
			})

		} catch(err) {
			next(err)
		}
	}
}

module.exports = {
	restrict,
}
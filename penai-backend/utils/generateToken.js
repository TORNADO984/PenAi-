const jwt = require('jsonwebtoken');

/**
 * Generate a signed JWT token for a given user ID.
 * Token expires in 30 days.
 */
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  });
};

module.exports = generateToken;

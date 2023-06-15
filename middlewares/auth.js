const jwt = require('jsonwebtoken');
const Unauthorized = require('../utils/response-errors/Unauthorized');

// eslint-disable-next-line consistent-return
module.exports = (req, res, next) => {
  const { authorization } = req.headers;

  if (!authorization || !authorization.startsWith('Bearer ')) {
    return next(new Unauthorized('Для доступа необходима авторизация'));
  }

  let payload;
  const userToken = authorization.replace('Bearer ', '');

  try {
    payload = jwt.verify(userToken, 'token-generate-key');
  } catch (_) {
    return next(new Unauthorized('Для доступа необходима авторизация'));
  }

  req.user = payload;
  next();
};

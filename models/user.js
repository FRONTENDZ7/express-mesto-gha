const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const validator = require('validator');

const Unauthorized = require('../utils/response-errors/Unauthorized');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    default: 'Жак-Ив Кусто',
    minlength: 2,
    maxlength: 30,
  },
  about: {
    type: String,
    default: 'Исследователь океана',
    minlength: 2,
    maxlength: 30,
  },
  avatar: {
    type: String,
    default:
      'https://s3-eu-north-1.amazonaws.com/static.epitafii.ru/wp-content/uploads/2014/01/%D1%84%D0%BE%D1%82%D0%BE-%D0%96%D0%B0%D0%BA-%D0%98%D0%B2-%D0%9A%D1%83%D1%81%D1%82%D0%BE-1.jpg',
    minlength: 4,
    validate: {
      validator: (correct) => validator.isURL(correct),
      message: 'Ошибка загрузки аватара',
    },
  },
  email: {
    type: String,
    minlength: 4,
    maxlength: 50,
    validate: {
      validator: (correct) => validator.isEmail(correct),
      message: 'Почта абонента введена неверно',
    },
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
    select: false,
  },
});

// eslint-disable-next-line func-names
userSchema.statics.findUserByCredentials = function (email, password) {
  return this.findOne({ email })
    .select('+password')
    .then((selectedUser) => {
      if (!selectedUser) {
        return Promise.reject(
          new Unauthorized('Имя пользователя или (-и) пароль введены неверно'),
        );
      }
      return bcrypt.compare(password, selectedUser.password).then((correct) => {
        if (!correct) {
          return Promise.reject(
            new Unauthorized('Имя пользователя или (-и) пароль введены неверно'),
          );
        }
        return selectedUser;
      });
    });
};

module.exports = mongoose.model('user', userSchema);

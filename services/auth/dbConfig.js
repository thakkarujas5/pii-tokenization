const sequelize = require('sequelize');


const db = new sequelize(
    'pii',
    'auth_service',
    'auth_password',
    {
        dialect: 'mysql',
        logging: true
    }
)

module.exports = db;
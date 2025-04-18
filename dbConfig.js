const sequelize = require('sequelize');


const db = new sequelize(
    'pii',
    'root',
    'drago1234',
    {
        dialect: 'mysql',
        logging: true
    }
)

module.exports = db;
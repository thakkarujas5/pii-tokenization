const sequelize = require('sequelize');


const db = new sequelize(
    'pii',
    'data_manager_service',
    'data_manager_password',
    {
        dialect: 'mysql',
        logging: true
    }
)

module.exports = db;
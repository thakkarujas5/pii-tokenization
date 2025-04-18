const sequelize = require('sequelize');


const db = new sequelize(
    'pii',
    'vault_service',
    'vault_password',
    {
        dialect: 'mysql',
        logging: true
    }
)

module.exports = db;
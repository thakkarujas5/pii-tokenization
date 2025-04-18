const db = require('../dbCOnfig');
const { DataTypes } = require('sequelize');

const ClientModel = db.define('Clients', {
    customer_id: {
        type: DataTypes.STRING(10),
        primaryKey: true,
        allowNull: false
    },
    password: {
        type: DataTypes.STRING(60),
        allowNull: false
    },
    scopes: {
        type: DataTypes.JSON,
        allowNull: true
    },
    userType: {
        type: DataTypes.STRING(32),
        allowNull: false
    }
}, {
    timestamps: false
});

module.exports = ClientModel;
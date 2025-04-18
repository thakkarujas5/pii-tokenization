const db = require('../dbCOnfig');
const { DataTypes } = require('sequelize');

const EncryptedDataModel = db.define('EncryptedData', {
    customer_id: {
        type: DataTypes.STRING(10),
        allowNull: false,
        primaryKey: true
    },
    data: {
        type: DataTypes.STRING(2048),
        allowNull: false
    },
    level: {
        type: DataTypes.STRING(20),
        allowNull: false,
        primaryKey: true
    }
}, {
    timestamps: false
});

module.exports = EncryptedDataModel;

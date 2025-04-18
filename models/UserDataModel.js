const db = require('../dbCOnfig');
const { DataTypes } = require('sequelize');

const UserDataModel = db.define('UserData', {
    customer_id: {
        type: DataTypes.STRING(10),
        primaryKey: true,
        allowNull: false
    },
    firstname: {
        type: DataTypes.STRING(64),
        allowNull: false
    },
    lastname: {
        type: DataTypes.STRING(64),
        allowNull: false
    },
    dob: {
        type: DataTypes.DATE,
        allowNull: false
    },
    pincode: {
        type: DataTypes.STRING(64),
        allowNull: false
    },
    address: {
        type: DataTypes.STRING(256),
        allowNull: false
    },
    mobile: {
        type: DataTypes.STRING(64),
        allowNull: false
    },
    age: {
        type: DataTypes.INTEGER,
        allowNull: false
    }
}, {
    timestamps: false
});

module.exports = UserDataModel;
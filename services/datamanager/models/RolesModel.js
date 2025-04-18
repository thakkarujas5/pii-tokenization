const db = require('../dbConfig');
const { DataTypes } = require('sequelize');

const RolesModel = db.define('Roles', {
    role_id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        allowNull: false,
        autoIncrement: true
    },
    roleName: {
        type: DataTypes.STRING(64),
        allowNull: false
    },
    scopes: {
        type: DataTypes.JSON,
        allowNull: false
    }
}, {
    timestamps: false
});

module.exports = RolesModel;

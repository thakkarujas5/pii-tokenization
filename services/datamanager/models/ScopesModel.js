const db = require('../dbConfig');
const { DataTypes } = require('sequelize');

const ScopesModel = db.define('Scopes', 
    {
        name: {
            type: DataTypes.STRING(64),
            allowNull: false,
            primaryKey: true
        }
    }, {
        timestamps: false
    }
);

module.exports = ScopesModel;

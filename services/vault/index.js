const express = require('express');
const db = require('./dbConfig');
const EncryptedDataModel = require('./models/EncryptedDataModel');
const UserDataModel = require('./models/UserDataModel');
const dotenv = require('dotenv');
const crypto = require('crypto');
const { SecretsManagerClient, GetSecretValueCommand} = require('@aws-sdk/client-secrets-manager');

const app = express();

dotenv.config();

app.listen('5005', () => {
    console.log('Listening')
})

app.use(express.json());

async function initializeFieldMappings() {
    const fieldToLevelMapping = {};
    
    try {
        // Get all models from sequelize
        const modelNames = Object.keys(db.models);

        for (const modelName of modelNames) {
            const model = db.models[modelName];
            
            // Get all attributes of the model
            const attributes = Object.keys(model.rawAttributes);
            
            // Add each attribute to the mapping
            attributes.forEach(attr => {
                // Skip certain common fields that shouldn't be encrypted
                if (!['customer_id'].includes(attr)) {
                    fieldToLevelMapping[attr] = modelName;
                }
            });
        }

        return fieldToLevelMapping;
    } catch (err) {
        console.error('Error initializing field mappings:', err);
        throw err;
    }
}

async function initializeColumnMappings() {
    const mapping = {};
    
    try {
        // Get all models from sequelize
        const models = db.models;

        
        for (const [modelName, model] of Object.entries(models)) {
            // Skip certain models that shouldn't be included in the mapping
            if (['EncryptedData', 'Roles', 'Scopes'].includes(modelName)) {
                continue;
            }
            
            // Get all attributes of the model
            const attributes = Object.keys(model.rawAttributes);
            
            // Add each attribute to the mapping
            attributes.forEach(attr => {
                // Skip certain common fields
                if (!['customer_id', 'role_id', 'createdAt', 'updatedAt'].includes(attr)) {
                    mapping[attr] = {
                        table: model,
                        model: modelName
                    };
                }
            });
        }

        return mapping;
    } catch (err) {
        console.error('Error initializing column mappings:', err);
        throw err;
    }
}

async function initializeColumnTypes() {
    const typeMapping = {};
    const { DataTypes } = require('sequelize');
    
    try {
        // Get all models from sequelize
        const models = db.models;
        
        for (const [modelName, model] of Object.entries(models)) {
            // Skip certain models that shouldn't be included in the mapping
            if (['EncryptedData', 'Roles', 'Scopes'].includes(modelName)) {
                continue;
            }
            
            // Get all attributes and their types
            const attributes = model.rawAttributes;
            
            for (const [attrName, attrData] of Object.entries(attributes)) {
                // Skip certain common fields
                if (!['customer_id', 'role_id', 'createdAt', 'updatedAt'].includes(attrName)) {
                    // Map Sequelize types to simplified types
                    let type = 'string'; // default type

                    if (attrData.type instanceof DataTypes.INTEGER ||
                        attrData.type instanceof DataTypes.FLOAT ||
                        attrData.type instanceof DataTypes.DECIMAL) {
                        type = 'number';
                    } else if (attrData.type instanceof DataTypes.DATE) {
                        type = 'date';
                    } else if (attrData.type instanceof DataTypes.BOOLEAN) {
                        type = 'boolean';
                    }

                    typeMapping[attrName] = {
                        type: type,
                        model: modelName
                    };
                }
            }
        }

        return typeMapping;
    } catch (err) {
        console.error('Error initializing column types:', err);
        throw err;
    }
}

let globalFieldToLevelMapping = {};
let columnToTableMapping = {};
let columnTypeMapping = {};

(async() => {

    try {
        globalFieldToLevelMapping = await initializeFieldMappings();
        columnToTableMapping = await initializeColumnMappings();
        columnTypeMapping = await initializeColumnTypes();

        const secretsManagerClient = new SecretsManagerClient({
            credentials: {
                accessKeyId: process.env.ACCESS_KEY_ID,
                secretAccessKey: process.env.SECRET_ACCESS_KEY
            },
            region: 'ap-south-1'
        });

        const response = await secretsManagerClient.send(
            new GetSecretValueCommand({
                SecretId: process.env.SECRET_NAME
            })
        );

        const secrets = JSON.parse(response.SecretString);

        process.env.AES_SECRET_KEY = secrets.AES_SECRET_KEY;
        process.env.AES_IV = secrets.AES_IV;

    } catch (err) {
        console.log(err);
    }
})()


function encrypt(text) {
    
    // Convert hex strings back to buffers
    const keyBuffer = Buffer.from(process.env.AES_SECRET_KEY, 'hex');
    const ivBuffer = Buffer.from(process.env.AES_IV, 'hex');
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    
    // Encrypt the data
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
}

function decrypt(encryptedData) {
    
    // Convert hex strings back to buffers
    const keyBuffer = Buffer.from(process.env.AES_SECRET_KEY, 'hex');
    const ivBuffer = Buffer.from(process.env.AES_IV, 'hex');
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    
    // Decrypt the data
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

app.post('/encryptData', async (req,res) => {

    const { customer_id, fields } = req.body;
    let t = null;

    try {

        const fieldsByLevel = {};

        for (const [fieldName, value] of Object.entries(fields)) {
            const level = globalFieldToLevelMapping[fieldName];
            
            if (!level) {
                return res.status(400).json({
                    message: `Invalid field: ${fieldName}. No level mapping found.`,
                    available_fields: Object.keys(globalFieldToLevelMapping)
                });
            }

            if (!fieldsByLevel[level]) {
                fieldsByLevel[level] = [];
            }
            
            fieldsByLevel[level].push({
                name: fieldName,
                value: value
            });
        }

         t = await db.transaction();

        // Process each level
        for (const level of Object.keys(fieldsByLevel)) {
            const levelFields = fieldsByLevel[level];
            
            if (levelFields.length === 0) continue;

            // Check if encryption already exists for this level
            const existingEncryption = await EncryptedDataModel.findOne({
                where: { 
                    customer_id: customer_id,
                    level: level
                }
            });

            // Create data string for this level
            const dataObject = {};
            levelFields.forEach(field => {
                dataObject[field.name] = field.value;
            });

            const dataString = JSON.stringify(dataObject);
            const encryptedData = encrypt(dataString);

            if (existingEncryption) {
                await existingEncryption.update({
                    data: encryptedData
                }, {
                    transaction: t
                });
            } else {
                await EncryptedDataModel.create({
                    customer_id: customer_id,
                    data: encryptedData,
                    level: level
                }, {
                    transaction: t
                });
            }
        }

        await t.commit();

        return res.status(200).json({
            message: "Data encrypted and stored successfully",
            customer_id: customer_id,
            processed_levels: Object.keys(fieldsByLevel)
        });


    } catch (err) {

        console.log(err);
        if (t) await t.rollback();
        return res.status(500).json({message: "Internal Server Error!"});

    }
});

app.post('/getDecryptedData', async (req, res) => {
    try {
        const { customer_id, level } = req.body;

        // Validate level exists in our mapping
        const validLevels = [...new Set(Object.values(globalFieldToLevelMapping))];
        if (!validLevels.includes(level)) {
            return res.status(400).json({
                message: "Invalid level. Must be one of: " + validLevels.join(', ')
            });
        }

        const encryptedRecord = await EncryptedDataModel.findOne({
            where: { 
                customer_id,
                level
            }
        });

        if (!encryptedRecord) {
            return res.status(404).json({
                message: `No encrypted data found for level ${level}`
            });
        }

        const decryptedString = decrypt(encryptedRecord.data);
        const decryptedData = JSON.parse(decryptedString);

        return res.status(200).json({
            message: "Data retrieved and decrypted successfully",
            level: level,
            data: decryptedData
        });

    } catch (err) {
        console.log(err);
        return res.status(500).json({message: "Internal Server Error!"});
    }
});
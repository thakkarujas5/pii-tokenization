const express = require('express');
const bcrypt = require('bcrypt');
const UserDataModel = require('./models/UserDataModel');
const ClientModel = require('./models/ClientModel');
const db = require('./dbConfig');
const axios = require('axios');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const { SecretsManagerClient, GetSecretValueCommand} = require('@aws-sdk/client-secrets-manager');

const app = express();

app.listen('5003', () => {
    console.log('Listening')
});

app.use(express.json())

dotenv.config();


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

let fixedSalt = null;

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

        fixedSalt = secrets.salt;
        process.env.SECRET_KEY = secrets.SECRET_KEY;


    } catch (err) {
        console.log(err);
    }
})()



function hashWithFixedSalt(password) {
    return bcrypt.hashSync(password, fixedSalt);
}


app.post('/createUser', async(req, res) => {

    const userType = req.body.userType;

    let t = null;
    try {

        const existingClient = await UserDataModel.findOne({
            where: {
                mobile: req.body.mobile
            }
        });

        if (existingClient) {
            return res.status(400).json({
                message: "User with this mobile number already exists"
            });
        }

        // Generate and validate unique customer ID
        let customerID;
        let isUnique = false;
        
        while (!isUnique) {
            // Generate 10 digit number
            customerID = Math.floor(1000000000 + Math.random() * 9000000000).toString();
            
            // Check if it exists in either UserData or Client tables
            const existingUser = await Promise.all([
                UserDataModel.findByPk(customerID),
                ClientModel.findByPk(customerID)
            ]);

            if (!existingUser[0] && !existingUser[1]) {
                isUnique = true;
            }
        }


        const hashedFirstName = hashWithFixedSalt(req.body.firstname);
        const hashedLastName = hashWithFixedSalt(req.body.lastname);
        //const hashedDob = await bcrypt.hash(req.body.dob, saltRounds);
        const hashedPincode = hashWithFixedSalt(req.body.pincode);
        const hashedAddress = hashWithFixedSalt(req.body.address);
        const hashedMobile = hashWithFixedSalt(req.body.mobile);
        const hashedPassword =  hashWithFixedSalt(req.body.password);
        // Create user data with the generated customer ID

        t = await db.transaction();

        if(userType === "CUSTOMER") {
            await UserDataModel.create({
                customer_id: customerID,
                firstname: hashedFirstName,
                lastname: hashedLastName,
                dob: req.body.dob,
                pincode: hashedPincode,
                address: hashedAddress,
                mobile: hashedMobile,
                age: req.body.age
            }, {
                transaction: t
            });
        }

        await ClientModel.create({
            customer_id: customerID,
            password: hashedPassword,
            scopes: userType === "CUSTOMER" ? ["*"]: null,
            userType: userType
        }), {
            transaction: t
        };

        const encryptionPayload = {
            customer_id: customerID,
            fields: {
                firstname: req.body.firstname,
                lastname: req.body.lastname,
                dob: req.body.dob,
                pincode: req.body.pincode,
                address: req.body.address,
                mobile: req.body.mobile,
                age: req.body.age
            }
        };

        await axios.post('http://localhost:5005/encryptData', encryptionPayload);

        await t.commit();

        return res.status(200).json({
            message: "User created successfully",
            customer_id: customerID
        });
    } catch (err) {
        console.log(err);
        await t.rollback();
        return res.status(500).json({message: "Internal Server Error!"});
    }
})

app.post('/login', async (req,res) => {

    const customer_id = req.body.customer_id;
    const password = hashWithFixedSalt(req.body.password);

    try {

        const client = await ClientModel.findOne({
            where: {
                customer_id: customer_id,
                password: password
            }
        });

        if (!client) {
            return res.status(404).json({message: "Incorrect login credentials"});
        }

        const token = jwt.sign({
            customer_id: customer_id
        }, process.env.SECRET_KEY, {
            expiresIn: '4h'
        });

        return res.status(200).json({
            message: "Login Successful",
            token: token
        });

    } catch (err) {
        console.log(err);
        return res.status(500).json({message: "Internal Server Error!"});
    }
});

app.get('/verify', async (req, res) => {

    const token = req.headers.authorization.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);

        return res.status(200).json({customer_id: decoded.customer_id});
    } catch (err) {
        return res.status(500).json({message: "Incorrect token"});
    }
});
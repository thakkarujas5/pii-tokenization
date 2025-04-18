const express = require('express');
const crypto = require('crypto');
const dotenv = require('dotenv');
const db = require('./dbConfig');
const bcrypt = require('bcrypt');
const ClientModel = require('./models/ClientModel');
const RolesModel = require('./models/RolesModel');
const UserData = require('./models/UserDataModel');
const ScopesModel = require('./models/ScopesModel');
const axios = require('axios');
const { SecretsManagerClient, GetSecretValueCommand} = require('@aws-sdk/client-secrets-manager');

const app = express();

dotenv.config();

app.listen('5004', () => {
    console.log('Listening')
});

let fixedSalt = null;

function hashWithFixedSalt(password) {
    return bcrypt.hashSync(password, fixedSalt);
}

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

})()

async function validateAndGetScopes(customer_id) {
    const client = await ClientModel.findByPk(customer_id);
    if (!client) {
        throw new Error("Customer not found");
    }

    const directScopes = client.scopes.filter(scope => !scope.startsWith('assume:')) || [];
    const roleNames = client.scopes
        .filter(scope => scope.startsWith('assume:'))
        .map(scope => scope.replace('assume:', ''));

    const roles = await RolesModel.findAll({
        where: {
            roleName: roleNames
        }
    });

    const customerScopes = [
        ...directScopes,
        ...roles.flatMap(role => role.scopes)
    ];

    return [...new Set(customerScopes)]; // Returns unique scopes
}

// Helper function to check if user has permission for a specific scope
const hasPermission = (requiredScope, uniqueCustomerScopes) => {
    // Add this check first - if user has global wildcard permission, allow everything
    if (uniqueCustomerScopes.includes('*')) return true;

    // Rest of the existing permission checks
    if (uniqueCustomerScopes.includes(requiredScope)) return true;

    const [model, action, field] = requiredScope.split(':');
    const wildcardScopes = [
        `${model}:${action}:*`,  // e.g., userdata:read:*
        `${model}:*:${field}`,   // e.g., userdata:*:firstname
        `${model}:*:*`,          // e.g., userdata:*:*
        `*:${action}:${field}`,  // e.g., *:read:firstname
        `*:${action}:*`,         // e.g., *:read:*
        `*:*:${field}`,          // e.g., *:*:firstname
        '*:*:*'                  // Full wildcard
    ];

    return wildcardScopes.some(wildcardScope => uniqueCustomerScopes.includes(wildcardScope));
};

function validateFields(search, customerScopes) {
    const allowedFields = [];
    const deniedFields = [];
    
    search.forEach(field => {
        if (!columnToTableMapping[field.name]) {
            deniedFields.push(field.name);
            return;
        }

        const requiredScope = `${columnToTableMapping[field.name].model.toLowerCase()}:read:${field.name}`;
        if (hasPermission(requiredScope, customerScopes)) {
            allowedFields.push(field);
        } else {
            deniedFields.push(field.name);
        }
    });

    return { allowedFields, deniedFields };
}


async function getMatchingCustomerIds(tableQueries, operation = 'AND') {
    const customerIdResults = await Promise.all(
        Object.values(tableQueries).map(query => 
            query.model.findAll({
                where: query.whereClause,
                attributes: ['customer_id']
            })
        )
    );
    console.log(tableQueries.UserData.whereClause);
    //console.log(customerIdResults);
    // For AND operation, find customer_ids that exist in all results
    if (operation === 'AND') {
        const customerIdSets = customerIdResults.map(results => 
            new Set(results.map(result => result.customer_id))
        );
        
        return [...customerIdSets.reduce((acc, curr) => 
            new Set([...acc].filter(x => curr.has(x)))
        )];
    }
    
    // For OR operation, combine all unique customer_ids
    return [...new Set(
        customerIdResults.flat().map(result => result.customer_id)
    )];
}


function buildTableQueries(allowedFields, customer_id = null, operation = 'AND') {
    const tableQueries = {};
    
    // Group fields by table first
    const fieldsByTable = allowedFields.reduce((acc, field) => {
        const tableInfo = columnToTableMapping[field.name];
        if (!acc[tableInfo.model]) {
            acc[tableInfo.model] = [];
        }
        acc[tableInfo.model].push(field);
        return acc;
    }, {});

    console.log(fieldsByTable);
    // Build queries for each table
    for (const [modelName, fields] of Object.entries(fieldsByTable)) {
        const tableInfo = columnToTableMapping[fields[0].name];

        const conditions = fields.map(field => {
            // Get the field type from columnTypeMapping
            const fieldType = columnTypeMapping[field.name]?.type;
            
            if (Array.isArray(field.value) && field.value.length > 0) {
                // For numeric and boolean fields, don't hash the values
                const values = fieldType === 'number' || fieldType === 'boolean' 
                    ? field.value.map(val => fieldType === 'number' ? Number(val) : val === 'true')
                    : field.value.map(val => hashWithFixedSalt(val));

                return {
                    [field.name]: {
                        [db.Sequelize.Op.in]: values
                    }
                };
            } else if (field.value && field.value[0]) {
                // For numeric and boolean fields, don't hash the value
                const value = fieldType === 'number' ? Number(field.value[0]) 
                    : fieldType === 'boolean' ? field.value[0] === 'true'
                    : hashWithFixedSalt(field.value[0]);

                return {
                    [field.name]: value
                };
            }
        }).filter(Boolean);

        console.log(conditions);
        tableQueries[modelName] = {
            model: tableInfo.table,
            whereClause: {
                [operation === 'OR' ? db.Sequelize.Op.or : db.Sequelize.Op.and]: conditions
            },
            attributes: ['customer_id']
        };

        // Add customer_id constraint if provided
        if (customer_id) {
            tableQueries[modelName].whereClause = {
                [db.Sequelize.Op.and]: [
                    { customer_id },
                    tableQueries[modelName].whereClause
                ]
            };
        }
    }

    return tableQueries;
}

async function getDecryptedDataForCustomer(customer_id, requestedFields) {
    // Get all required levels for the requested fields
    const requiredLevels = [...new Set(
        requestedFields.map(field => globalFieldToLevelMapping[field])
    )];

    // Get decrypted data for each level
    const levelDataResults = await Promise.all(
        requiredLevels.map(level => 
            axios.post('http://localhost:5005/getDecryptedData', {
                customer_id,
                level
            })
        )
    );

    // Combine all level data
    const combinedData = {
        customer_id,
        ...levelDataResults.reduce((acc, response) => ({
            ...acc,
            ...response.data.data
        }), {})
    };

    // Filter to only include requested fields
    return Object.keys(combinedData)
        .filter(key => requestedFields.includes(key) || key === 'customer_id')
        .reduce((obj, key) => {
            obj[key] = combinedData[key];
            return obj;
        }, {});
}

async function executeOperation(operation, matchingCustomerIds, requestedFields) {
    if (matchingCustomerIds.length === 0) {
        return {
            message: "No matching records found",
            results: operation === 'count' ? 0 : []
        };
    }

    switch (operation.toLowerCase()) {
        case 'query':
            return {
                message: "Query completed successfully",
                results: await Promise.all(
                    matchingCustomerIds.map(cid => 
                        getDecryptedDataForCustomer(cid, requestedFields)
                    )
                )
            };
            
        case 'count':
            return {
                message: "Count operation completed successfully",
                results: matchingCustomerIds.length
            };
            
        case 'avg':
        case 'sum':
            // Get all data first
            const allData = await Promise.all(
                matchingCustomerIds.map(cid => 
                    getDecryptedDataForCustomer(cid, requestedFields)
                )
            );
            
            // Calculate aggregates for each numeric field
            const results = {};
            
            requestedFields.forEach(field => {
                const values = allData
                    .map(data => Number(data[field]))
                    .filter(val => !isNaN(val));
                
                if (values.length === 0) {
                    results[field] = null;
                    return;
                }

                if (operation === 'avg') {
                    results[field] = values.reduce((a, b) => a + b, 0) / values.length;
                } else { // sum
                    results[field] = values.reduce((a, b) => a + b, 0);
                }
            });
            
            return {
                message: `${operation} operation completed successfully`,
                results: results
            };
            
        default:
            throw new Error(`Unsupported operation: ${operation}`);
    }
}

app.post('/search', async (req, res) => {

    const apiScopes = ["userdata:read:firstname", "userdata:read:lastname", "userdata:read:pincode"];

    try {
        let customer_id = req.body.customer_id;
        const search = req.body.search.fields;
        const operation = req.body.search.operation?.toLowerCase() || 'query';
        const whereOperation = req.body.search.whereOperation;
        const operationFields = req.body.search.operationFields || [];

        const validOperations = ['query', 'count', 'avg', 'sum'];
        if (!validOperations.includes(operation)) {
            return res.status(400).json({
                message: `Invalid operation. Must be one of: ${validOperations.join(', ')}`,
                valid_operations: validOperations
            });
        }

        // New validation for aggregate operations
        if (['avg', 'sum'].includes(operation)) {
            if (!operationFields || operationFields.length === 0) {
                const numericFields = Object.entries(columnTypeMapping)
                    .filter(([_, info]) => info.type === 'number')
                    .map(([field, _]) => field);

                return res.status(400).json({
                    message: `${operation} operation requires at least one numeric field`,
                    available_numeric_fields: numericFields,
                    example: {
                        "search": {
                            "operation": operation,
                            "operationFields": ["field1", "field2"],
                            "fields": [/* where conditions */]
                        }
                    }
                });
            }

            // Validate that all operation fields are numeric
            const typeErrors = operationFields.map(field => {
                const fieldInfo = columnTypeMapping[field];
                if (!fieldInfo) {
                    return {
                        field: field,
                        error: 'Field does not exist'
                    };
                }
                if (fieldInfo.type !== 'number') {
                    return {
                        field: field,
                        error: `${operation} operation can only be performed on numeric fields`,
                        expected: 'number',
                        actual: fieldInfo.type,
                        model: fieldInfo.model
                    };
                }
                return null;
            }).filter(Boolean);

            if (typeErrors.length > 0) {
                return res.status(400).json({
                    message: "Invalid operation fields",
                    errors: typeErrors
                });
            }
        }

        const uniqueCustomerScopes = await validateAndGetScopes(customer_id);
 
        const missingScopes = apiScopes.filter(scope => !hasPermission(scope, uniqueCustomerScopes));
        if (missingScopes.length > 0) {
            return res.status(403).json({
                message: "Insufficient permissions",
                missing_scopes: missingScopes
            });
        }

        const { allowedFields, deniedFields } = validateFields(search, uniqueCustomerScopes);

        if (deniedFields.length > 0) {
            return res.status(403).json({
                message: "Access denied for some fields",
                denied_fields: deniedFields,
                required_scopes: deniedFields.map(field => {
                    const model = columnToTableMapping[field]?.model.toLowerCase() || 'unknown';
                    return `${model}:read:${field}`;
                })
            });
        }

        const tableQueries = buildTableQueries(allowedFields, null, whereOperation);

        const matchingCustomerIds = await getMatchingCustomerIds(tableQueries, whereOperation);

        const fieldsToRetrieve = operation === 'query' ? 
        search.map(f => f.name) : 
        operationFields;
    
        const operationResult = await executeOperation(operation, matchingCustomerIds, fieldsToRetrieve);
        
        return res.status(200).json({
            message: "Search completed",
            results: operationResult
        });

    } catch (err) {
        console.log(err);
        return res.status(500).json({message: "Internal Server Error!"});
    }
})
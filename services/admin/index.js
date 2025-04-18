const express = require('express');
const ScopesModel = require('../../models/ScopesModel');
const RolesModel = require('../../models/RolesModel');
const ClientModel = require('../../models/ClientModel');
const { createClient } = require('redis');

const app = express();

app.listen('5002', () => {
    console.log('Listening')
});

const redisClient = createClient({
    url: 'redis://localhost:6379'
});


app.use(express.json())


app.post('/addScope', async (req, res) => {

    try {
        await ScopesModel.create({
            name: req.body.name
        });

        return res.status(200).json({message: "Created Successfully"});

    } catch (err) {
        console.log(err);
        return res.status(500).json({message: "Internal Server Error!"});
    }
});

app.post('/addRole', async (req,res) => {

    try {
        const requestedScopes = req.body.scopes;
        const existingScopes = await ScopesModel.findAll({
            where: {
                name: requestedScopes
            }
        });

        if (existingScopes.length !== requestedScopes.length) {
            return res.status(400).json({
                message: "One or more scopes are invalid"
            });
        }

        await RolesModel.upsert({
            roleName: req.body.name,
            scopes: requestedScopes
        });

        return res.status(200).json({
            message: "Role created successfully"
        });
    } catch (err) {
        console.log(err);
        return res.status(500).json({message: "Internal Server Error!"});
    }
});

app.post('/assignScopes', async (req, res) => {

    try {

        const customer_id = req.body.customer_id;
        const scopes = req.body.scopes;

        const client = await ClientModel.findByPk(customer_id);
        if (!client) {
            return res.status(404).json({
                message: "Customer not found"
            });
        }

        // Separate roles and direct scopes
        const roleScopes = scopes.filter(scope => scope.startsWith('assume:'))
            .map(scope => scope.replace('assume:', ''));
        const directScopes = scopes.filter(scope => !scope.startsWith('assume:'));

        // Validate roles
        const existingRoles = await RolesModel.findAll({
            where: {
                roleName: roleScopes
            }
        });

        // Find invalid roles
        const validRoleNames = existingRoles.map(role => role.roleName);
        const invalidRoles = roleScopes.filter(role => !validRoleNames.includes(role));

        // Validate direct scopes
        const existingScopes = await ScopesModel.findAll({
            where: {
                name: directScopes
            }
        });

        // Find invalid scopes
        const validScopeNames = existingScopes.map(scope => scope.name);
        const invalidScopes = directScopes.filter(scope => !validScopeNames.includes(scope));

        // If there are any invalid roles or scopes, return error with details
        if (invalidRoles.length > 0 || invalidScopes.length > 0) {
            const errorResponse = {
                message: "Validation failed",
                errors: {}
            };

            if (invalidRoles.length > 0) {
                errorResponse.errors.invalid_roles = invalidRoles.map(role => `assume:${role}`);
            }

            if (invalidScopes.length > 0) {
                errorResponse.errors.invalid_scopes = invalidScopes;
            }

            return res.status(400).json(errorResponse);
        }

        // Collect all scopes (direct scopes + scopes from roles)
        const allScopes = [...directScopes];
        existingRoles.forEach(role => {
            allScopes.push(...role.scopes);
        });

        // Remove duplicates if any
        const uniqueScopes = [...new Set(allScopes)];

        // Update client's scopes
        await client.update({
            scopes: scopes
        });

        return res.status(200).json({
            message: "Scopes assigned successfully",
            assigned_scopes: scopes
        });
    } catch (err) {
        console.log(err);
        return res.status(500).json({message: "Internal Server Error!"});
    }
})

app.get('/test', async (req, res) => {

    await redisClient.connect();
    
    const x = await redisClient.get('scopes');

    await redisClient.disconnect();

    console.log(JSON.parse(x));
    return res.status(200).json({message: "done"});
})

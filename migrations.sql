CREATE TABLE UserData (
    customer_id VARCHAR(10) PRIMARY KEY,
    firstname VARCHAR(64) NOT NULL,
    lastname VARCHAR(64) NOT NULL,
    dob DATETIME(3) NOT NULL,
    pincode VARCHAR(64) NOT NULL,
    address VARCHAR(256) NOT NULL,
    mobile VARCHAR(64) NOT NULL
);

CREATE TABLE Clients (
    customer_id VARCHAR(10) PRIMARY KEY,
    password VARCHAR(60) NOT NULL,
    scopes JSON NULL,
    userType VARCHAR(32) NOT NULL
);

CREATE TABLE Roles (
    role_id INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
    roleName VARCHAR(64) NOT NULL,
    scopes JSON
);

CREATE TABLE Scopes (
    name VARCHAR(64) PRIMARY KEY NOT NULL
);

CREATE TABLE EncryptedData (
    customer_id VARCHAR(10) NOT NULL,
    data VARCHAR(2048) NOT NULL,
    level VARCHAR(20) NOT NULL,

    PRIMARY KEY(customer_id, level)
);
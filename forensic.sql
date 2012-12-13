CREATE DATABASE arf CHARACTER SET utf8;

CREATE TABLE arfEmail (
emailId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
feedbackType ENUM('auth-failure'),
emailType ENUM('normal','bounce','auto-replied'),
reported INT DEFAULT '0',
originalMailFromLocalId INT,
originalMailFromDomainId INT,
originalRcptToLocalId INT,
originalRcptToDomainId INT,
arrivalDate DATETIME,
messageId VARCHAR(255),
authenticationResults varchar(255),
sourceIp VARBINARY(16),
sourceDomainId INT,
sourceAsn BIGINT,
countryCode CHAR(2),
deliveryResult ENUM('none','quarantine','reject'),
authFailure ENUM('dmarc'),
reportedDomainID INT,
originalFromLocalId INT,
originalFromDomainId INT,
subject VARCHAR(255),
content TEXT,
INDEX (emailType),
INDEX (originalMailFromDomainId),
INDEX (originalRcptToDomainId),
INDEX (arrivalDate),
INDEX (sourceIp),
INDEX (sourceDomainId),
INDEX (sourceAsn),
INDEX (reportedDomainID),
INDEX (subject)
);

CREATE TABLE emailLocal (
emailLocalId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
emailLocal VARCHAR(255) UNIQUE,
INDEX (emailLocal)
);

CREATE TABLE domain (
domainId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
domain VARCHAR(255) UNIQUE,
INDEX (domain)
);

CREATE TABLE emailUrl (
emailUrlId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
emailId INT,
urlId INT,
INDEX (emailId),
INDEX (urlId)
);

CREATE TABLE url (
urlId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
firstSeen DATETIME NULL,
lastSeen DATETIME NULL,
urlIp VARBINARY(16),
urlDomainId INT,
urlAsn BIGINT,
urlCountryCode CHAR(2),
url VARCHAR(1000),
INDEX url (url(255)),
INDEX (urlIp),
INDEX (urlDomainId),
INDEX (urlAsn)
);

CREATE TABLE emailFile (
emailFileId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
emailId INT,
fileId INT,
INDEX (emailId),
INDEX (fileId)
);

CREATE TABLE file (
fileId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
firstSeen DATETIME NULL,
lastSeen DATETIME NULL,
hash VARCHAR(255) UNIQUE,
filename VARCHAR(255),
INDEX (hash)
);
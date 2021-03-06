-- ################################
-- USER MANAGER TABLES
-- ################################

CREATE TABLE website_customer_account(
    		website_customer_account_id INTEGER IDENTITY(1,1) NOT NULL,
		EMAIL VARCHAR(100) NOT NULL,
		WEBSITE_CONFIG_ID INT NOT NULL,
    		PASSWORD_ENCRYPTED VARCHAR(256) NOT NULL,
		PASSWORD_DATETIME DATETIME NOT NULL,
    		PRIMARY KEY (website_customer_account_id, EMAIL, WEBSITE_CONFIG_ID )
    	);

insert into website_customer_account (email,WEBSITE_CONFIG_ID,PASSWORD_ENCRYPTED,PASSWORD_DATETIME) values ('admin',1,'admin','2015-04-01 07:35:58');

--CREATE TABLE   UM_TENANT_

IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_TENANT]') AND TYPE IN (N'U'))
CREATE TABLE UM_TENANT (
			UM_ID INTEGER IDENTITY(1,1) NOT NULL,
			UM_DOMAIN_NAME VARCHAR(255) NOT NULL,
	        UM_EMAIL VARCHAR(255),
            UM_ACTIVE BIT DEFAULT 0,
	        UM_CREATED_DATE DATETIME NOT NULL,
	        UM_USER_CONFIG VARBINARY(MAX),
			PRIMARY KEY (UM_ID),
			UNIQUE(UM_DOMAIN_NAME));

IF EXISTS (SELECT NAME FROM SYSINDEXES WHERE NAME = 'INDEX_UM_TENANT_UM_DOMAIN_NAME')
DROP INDEX UM_TENANT.INDEX_UM_TENANT_UM_DOMAIN_NAME
CREATE INDEX INDEX_UM_TENANT_UM_DOMAIN_NAME ON UM_TENANT (UM_DOMAIN_NAME); 

--CREATE TABLE   UM_USER

IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_USER]') AND TYPE IN (N'U'))
CREATE TABLE  UM_USER (
             UM_ID INTEGER IDENTITY(1,1) NOT NULL,
             UM_USER_NAME VARCHAR(255) NOT NULL,
             UM_USER_PASSWORD VARCHAR(255) NOT NULL,
             UM_SALT_VALUE VARCHAR(31),
             UM_REQUIRE_CHANGE BIT DEFAULT 0,
             UM_CHANGED_TIME DATETIME NOT NULL,
             UM_TENANT_ID INTEGER DEFAULT 0,
             PRIMARY KEY (UM_ID, UM_TENANT_ID),
             UNIQUE(UM_USER_NAME, UM_TENANT_ID)
);

--CREATE TABLE   UM_DOMAIN
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_DOMAIN]') AND TYPE IN (N'U'))
CREATE TABLE UM_DOMAIN(
            UM_DOMAIN_ID INTEGER IDENTITY(1,1) NOT NULL,
            UM_DOMAIN_NAME VARCHAR(255),
            UM_TENANT_ID INTEGER DEFAULT 0,
            PRIMARY KEY (UM_DOMAIN_ID, UM_TENANT_ID)
);


--CREATE TABLE   UM_SYSTEM_USER
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_SYSTEM_USER]') AND TYPE IN (N'U'))
CREATE TABLE UM_SYSTEM_USER ( 
             UM_ID INTEGER IDENTITY(1,1) NOT NULL, 
             UM_USER_NAME VARCHAR(255) NOT NULL, 
             UM_USER_PASSWORD VARCHAR(255) NOT NULL,
             UM_SALT_VALUE VARCHAR(31),
             UM_REQUIRE_CHANGE  BIT DEFAULT 0,
             UM_CHANGED_TIME DATETIME NOT NULL,
             UM_TENANT_ID INTEGER DEFAULT 0, 
             PRIMARY KEY (UM_ID, UM_TENANT_ID), 
             UNIQUE(UM_USER_NAME, UM_TENANT_ID)
); 


--CREATE TABLE   UM_USER_ATTRIBUTE

IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_USER_ATTRIBUTE]') AND TYPE IN (N'U'))
CREATE TABLE  UM_USER_ATTRIBUTE (
             UM_ID INTEGER IDENTITY(1,1) NOT NULL,
			UM_ATTR_NAME VARCHAR(255) NOT NULL,
			UM_ATTR_VALUE VARCHAR(1024),
			UM_PROFILE_ID VARCHAR(255),
			UM_USER_ID INTEGER,
            UM_TENANT_ID INTEGER DEFAULT 0,
			FOREIGN KEY (UM_USER_ID, UM_TENANT_ID) REFERENCES UM_USER(UM_ID, UM_TENANT_ID),
			PRIMARY KEY (UM_ID, UM_TENANT_ID));

--CREATE TABLE   UM_ROLE

IF NOT  EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_ROLE]') AND TYPE IN (N'U'))
CREATE TABLE UM_ROLE (
             UM_ID INTEGER IDENTITY(1,1) NOT NULL,
             UM_ROLE_NAME VARCHAR(255) NOT NULL,
             UM_TENANT_ID INTEGER DEFAULT 0,
		     UM_SHARED_ROLE BIT DEFAULT 0,
             PRIMARY KEY (UM_ID, UM_TENANT_ID),
             UNIQUE(UM_ROLE_NAME, UM_TENANT_ID)
);


--CREATES TABLE UM_MODULE
IF NOT  EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_MODULE]') AND TYPE IN (N'U'))
CREATE TABLE UM_MODULE(
	UM_ID INTEGER  IDENTITY(1,1) NOT NULL,
	UM_MODULE_NAME VARCHAR(100),
	UNIQUE(UM_MODULE_NAME),
	PRIMARY KEY(UM_ID)
);

IF NOT  EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_MODULE_ACTIONS]') AND TYPE IN (N'U'))
CREATE TABLE UM_MODULE_ACTIONS(
	UM_ACTION VARCHAR(255) NOT NULL,
	UM_MODULE_ID INTEGER NOT NULL,
	PRIMARY KEY(UM_ACTION, UM_MODULE_ID),
	FOREIGN KEY (UM_MODULE_ID) REFERENCES UM_MODULE(UM_ID) ON DELETE CASCADE
);


--CREATE TABLE UM_PERMISSION

IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_PERMISSION]') AND TYPE IN (N'U'))
CREATE TABLE  UM_PERMISSION (
             UM_ID INTEGER IDENTITY(1,1) NOT NULL,
             UM_RESOURCE_ID VARCHAR(255) NOT NULL,
             UM_ACTION VARCHAR(255) NOT NULL,
             UM_TENANT_ID INTEGER DEFAULT 0,
		     UM_MODULE_ID INTEGER DEFAULT 0,
             PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

IF EXISTS (SELECT name FROM sysindexes WHERE name = 'INDEX_UM_PERMISSION_UM_RESOURCE_ID_UM_ACTION')
DROP INDEX UM_PERMISSION.INDEX_UM_PERMISSION_UM_RESOURCE_ID_UM_ACTION
CREATE INDEX INDEX_UM_PERMISSION_UM_RESOURCE_ID_UM_ACTION ON UM_PERMISSION (UM_RESOURCE_ID, UM_ACTION, UM_TENANT_ID);

--CREATE TABLE UM_ROLE_PERMISSION

IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_ROLE_PERMISSION]') AND TYPE IN (N'U'))
CREATE TABLE  UM_ROLE_PERMISSION (
             UM_ID INTEGER IDENTITY(1,1) NOT NULL,
             UM_PERMISSION_ID INTEGER NOT NULL,
             UM_ROLE_NAME VARCHAR(255) NOT NULL,
             UM_IS_ALLOWED SMALLINT NOT NULL,
             UM_TENANT_ID INTEGER DEFAULT 0,
	     UM_DOMAIN_ID INTEGER, 
             UNIQUE (UM_PERMISSION_ID, UM_ROLE_NAME, UM_TENANT_ID, UM_DOMAIN_ID),
             FOREIGN KEY (UM_PERMISSION_ID, UM_TENANT_ID) REFERENCES UM_PERMISSION(UM_ID, UM_TENANT_ID),
	     FOREIGN KEY (UM_DOMAIN_ID, UM_TENANT_ID) REFERENCES UM_DOMAIN(UM_DOMAIN_ID, UM_TENANT_ID) ON DELETE CASCADE,
             PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

--CREATE TABLE UM_USER_PERMISSION
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_USER_PERMISSION]') AND TYPE IN (N'U'))
CREATE TABLE  UM_USER_PERMISSION (
             UM_ID INTEGER IDENTITY(1,1) NOT NULL,
             UM_PERMISSION_ID INTEGER NOT NULL,
             UM_USER_NAME VARCHAR(255) NOT NULL,
             UM_IS_ALLOWED SMALLINT NOT NULL,
             UM_TENANT_ID INTEGER DEFAULT 0,
             UNIQUE (UM_PERMISSION_ID, UM_USER_NAME, UM_TENANT_ID),
             FOREIGN KEY (UM_PERMISSION_ID, UM_TENANT_ID) REFERENCES UM_PERMISSION(UM_ID, UM_TENANT_ID),
             PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

-- create table UM_USER_ROLE
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_USER_ROLE]') AND TYPE IN (N'U'))
CREATE TABLE  UM_USER_ROLE (
             UM_ID INTEGER IDENTITY(1,1) NOT NULL,
             UM_ROLE_ID INTEGER NOT NULL,
             UM_USER_ID INTEGER NOT NULL,
             UM_TENANT_ID INTEGER DEFAULT 0,
             UNIQUE (UM_USER_ID, UM_ROLE_ID, UM_TENANT_ID),
             FOREIGN KEY (UM_ROLE_ID, UM_TENANT_ID) REFERENCES UM_ROLE(UM_ID, UM_TENANT_ID),
             FOREIGN KEY (UM_USER_ID, UM_TENANT_ID) REFERENCES UM_USER(UM_ID, UM_TENANT_ID),
             PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_SHARED_USER_ROLE]') AND TYPE IN (N'U'))
CREATE TABLE UM_SHARED_USER_ROLE(
    UM_ROLE_ID INTEGER NOT NULL,
    UM_USER_ID INTEGER NOT NULL,
    UM_USER_TENANT_ID INTEGER NOT NULL,
    UM_ROLE_TENANT_ID INTEGER NOT NULL,
    UNIQUE(UM_USER_ID,UM_ROLE_ID,UM_USER_TENANT_ID, UM_ROLE_TENANT_ID),
    FOREIGN KEY(UM_ROLE_ID,UM_ROLE_TENANT_ID) REFERENCES UM_ROLE(UM_ID,UM_TENANT_ID) ON DELETE CASCADE ,
    FOREIGN KEY(UM_USER_ID,UM_USER_TENANT_ID) REFERENCES UM_USER(UM_ID,UM_TENANT_ID) ON DELETE CASCADE
);

IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_ACCOUNT_MAPPING]') AND TYPE IN (N'U'))
CREATE TABLE UM_ACCOUNT_MAPPING(
	UM_ID INTEGER IDENTITY(1,1),
	UM_USER_NAME VARCHAR(255) NOT NULL,
	UM_TENANT_ID INTEGER NOT NULL,
	UM_USER_STORE_DOMAIN VARCHAR(100),
	UM_ACC_LINK_ID INTEGER NOT NULL,
	UNIQUE(UM_USER_NAME, UM_TENANT_ID, UM_USER_STORE_DOMAIN, UM_ACC_LINK_ID),
	FOREIGN KEY (UM_TENANT_ID) REFERENCES UM_TENANT(UM_ID) ON DELETE CASCADE,
	PRIMARY KEY (UM_ID)
);


-- create table UM_DIALECT
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_DIALECT]') AND TYPE IN (N'U'))
CREATE TABLE UM_DIALECT(
       	    UM_ID INTEGER IDENTITY(1, 1),
            UM_DIALECT_URI VARCHAR(255),
            UM_TENANT_ID INTEGER DEFAULT 0,
            UNIQUE(UM_DIALECT_URI, UM_TENANT_ID),
            PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

-- create table UM_CLAIM
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_CLAIM]') AND TYPE IN (N'U'))
CREATE TABLE UM_CLAIM(
       	UM_ID INTEGER IDENTITY(1, 1),
            UM_DIALECT_ID INTEGER,
            UM_CLAIM_URI VARCHAR(255), 
            UM_DISPLAY_TAG VARCHAR(255), 
            UM_DESCRIPTION VARCHAR(255), 
	    UM_MAPPED_ATTRIBUTE_DOMAIN VARCHAR(255),
            UM_MAPPED_ATTRIBUTE VARCHAR(255), 
            UM_REG_EX VARCHAR(255), 
            UM_SUPPORTED SMALLINT, 
            UM_REQUIRED SMALLINT, 
            UM_DISPLAY_ORDER INTEGER, 
	    UM_CHECKED_ATTRIBUTE SMALLINT,
	    UM_READ_ONLY SMALLINT,
            UM_TENANT_ID INTEGER DEFAULT 0,
	    UNIQUE(UM_DIALECT_ID, UM_CLAIM_URI, UM_TENANT_ID,UM_MAPPED_ATTRIBUTE_DOMAIN), 
            FOREIGN KEY(UM_DIALECT_ID, UM_TENANT_ID) REFERENCES UM_DIALECT(UM_ID, UM_TENANT_ID), 
            PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

-- create table UM_PROFILE_CONFIG
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_PROFILE_CONFIG]') AND TYPE IN (N'U'))
CREATE TABLE UM_PROFILE_CONFIG(
       	UM_ID INTEGER IDENTITY(1, 1),
            UM_DIALECT_ID INTEGER, 
            UM_PROFILE_NAME VARCHAR(255), 
            UM_TENANT_ID INTEGER DEFAULT 0,
            FOREIGN KEY(UM_DIALECT_ID, UM_TENANT_ID) REFERENCES UM_DIALECT(UM_ID, UM_TENANT_ID), 
            PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

-- create table UM_CLAIM_BEHAVIOR
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_CLAIM_BEHAVIOR]') AND TYPE IN (N'U'))
CREATE TABLE UM_CLAIM_BEHAVIOR(
       	    UM_ID INTEGER IDENTITY(1, 1),
            UM_PROFILE_ID INTEGER, 
            UM_CLAIM_ID INTEGER, 
            UM_BEHAVIOUR SMALLINT,
            UM_TENANT_ID INTEGER DEFAULT 0, 
            FOREIGN KEY(UM_PROFILE_ID, UM_TENANT_ID) REFERENCES UM_PROFILE_CONFIG(UM_ID, UM_TENANT_ID), 
            FOREIGN KEY(UM_CLAIM_ID, UM_TENANT_ID) REFERENCES UM_CLAIM(UM_ID, UM_TENANT_ID), 
            PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

-- create table UM_HYBRID_ROLE
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_HYBRID_ROLE]') AND TYPE IN (N'U'))
CREATE TABLE UM_HYBRID_ROLE(
            UM_ID INTEGER IDENTITY(1, 1),
            UM_ROLE_NAME VARCHAR(255),
            UM_TENANT_ID INTEGER DEFAULT 0,
            PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

-- create table UM_HYBRID_USER_ROLE
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_HYBRID_USER_ROLE]') AND TYPE IN (N'U'))
CREATE TABLE UM_HYBRID_USER_ROLE(
            UM_ID INTEGER IDENTITY(1, 1) NOT NULL,
            UM_USER_NAME VARCHAR(255),
            UM_ROLE_ID INTEGER NOT NULL,
            UM_TENANT_ID INTEGER DEFAULT 0,
            UM_DOMAIN_ID INTEGER,
            UNIQUE (UM_USER_NAME, UM_ROLE_ID, UM_TENANT_ID, UM_DOMAIN_ID),
            FOREIGN KEY (UM_ROLE_ID, UM_TENANT_ID) REFERENCES UM_HYBRID_ROLE(UM_ID, UM_TENANT_ID),
	    FOREIGN KEY (UM_DOMAIN_ID, UM_TENANT_ID) REFERENCES UM_DOMAIN(UM_DOMAIN_ID, UM_TENANT_ID) ON DELETE CASCADE,
            PRIMARY KEY (UM_ID, UM_TENANT_ID)
);
-- create table UM_SYSTEM_ROLE
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_SYSTEM_ROLE]') AND TYPE IN (N'U'))
CREATE TABLE UM_SYSTEM_ROLE(
            UM_ID INTEGER IDENTITY(1, 1) NOT NULL,
            UM_ROLE_NAME VARCHAR(255),
            UM_TENANT_ID INTEGER DEFAULT 0,
            PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

-- create table UM_SYSTEM_USER_ROLE
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_SYSTEM_USER_ROLE]') AND TYPE IN (N'U'))
CREATE TABLE UM_SYSTEM_USER_ROLE(
            UM_ID INTEGER IDENTITY(1, 1),
            UM_USER_NAME VARCHAR(255),
            UM_ROLE_ID INTEGER NOT NULL,
            UM_TENANT_ID INTEGER DEFAULT 0,
            UNIQUE (UM_USER_NAME, UM_ROLE_ID, UM_TENANT_ID),
            FOREIGN KEY (UM_ROLE_ID, UM_TENANT_ID) REFERENCES UM_SYSTEM_ROLE(UM_ID, UM_TENANT_ID),
            PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

-- create table UM_HYBRID_USER_ROLE
IF NOT EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[dbo].[UM_HYBRID_REMEMBER_ME]') AND TYPE IN (N'U'))
CREATE TABLE UM_HYBRID_REMEMBER_ME(
            UM_ID INTEGER IDENTITY(1, 1),
			UM_USER_NAME VARCHAR(255) NOT NULL,
			UM_COOKIE_VALUE VARCHAR(1024),
			UM_CREATED_TIME DATETIME,
            UM_TENANT_ID INTEGER DEFAULT 0,
			PRIMARY KEY (UM_ID, UM_TENANT_ID)
);

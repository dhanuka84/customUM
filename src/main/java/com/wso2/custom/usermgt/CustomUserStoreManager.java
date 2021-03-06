package com.wso2.custom.usermgt;
 
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
/*import org.jasypt.util.password.StrongPasswordEncryptor;*/
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;
 
public class CustomUserStoreManager extends JDBCUserStoreManager {
   private static Log log = LogFactory.getLog(CustomUserStoreManager.class);
 
   // You must implement at least one constructor
   public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties, ClaimManager
           claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
           throws UserStoreException {
       super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
       log.info("CustomUserStoreManager initialized...");
   }
 
   @Override
   public boolean doAuthenticate(String userName, Object credential) throws UserStoreException {
       boolean isAuthenticated = false;
       if (userName != null && credential != null) {
           try {
               String candidatePassword = (String) credential;
 
               Connection dbConnection = null;
               ResultSet rs = null;
               PreparedStatement prepStmt = null;
               String sql = null;
               dbConnection = this.getDBConnection();
               dbConnection.setAutoCommit(false);
               // get the SQL statement used to select user details
               sql = this.realmConfig.getUserStoreProperty("SelectUserSQLCustom");
               if (log.isDebugEnabled()) {
                   log.debug(sql);
               }
 
               prepStmt = dbConnection.prepareStatement(sql);
               prepStmt.setString(1, userName);
               rs = prepStmt.executeQuery();
               if (rs.next()) {
                   String storedPassword = rs.getString(2);
                   isAuthenticated = candidatePassword.equalsIgnoreCase(storedPassword);
               }
               log.info(userName + " is authenticated? " + isAuthenticated);
           } catch (SQLException exp) {
               log.error("Error occurred while retrieving user authentication info.", exp);
               throw new UserStoreException("Authentication Failure");
           }
       }
       return isAuthenticated;
   }
 
   @Override
	public void addUser(String userName, Object credential, String[] roleList,
			Map<String, String> claims, String profileName)
			throws UserStoreException {
		super.addUser(userName, credential, roleList, claims, profileName);
		
	}
   
   
}
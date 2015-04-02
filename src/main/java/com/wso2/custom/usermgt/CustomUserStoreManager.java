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
   // This instance is used to generate the hash values
   /*private static StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();*/
 
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
              /* // check whether tenant id is used
               if (sql.contains("")) {
                   prepStmt.setInt(2, this.tenantId);
               }
 */
               rs = prepStmt.executeQuery();
               if (rs.next()) {
                   String storedPassword = rs.getString(2);
 
                   // check whether password is expired or not
                 /*  boolean requireChange = rs.getBoolean(5);
                   Timestamp changedTime = rs.getTimestamp(6);
                   GregorianCalendar gc = new GregorianCalendar();
                   gc.add(GregorianCalendar.HOUR, -24);
                   Date date = gc.getTime();
                   if (!(requireChange && changedTime.before(date))) {
                       // compare the given password with stored password using jasypt
                       //isAuthenticated = passwordEncryptor.checkPassword(candidatePassword, storedPassword);
                	   isAuthenticated = candidatePassword.equalsIgnoreCase(storedPassword);
                   }*/
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
 
   /*@Override
   protected String preparePassword(String password, String saltValue) throws UserStoreException {
       if (password != null) {
           // ignore saltValue for the time being
           log.info("Generating hash value using jasypt...");
           return passwordEncryptor.encryptPassword(password);
       } else {
           log.error("Password cannot be null");
           throw new UserStoreException("Authentication Failure");
       }
   }*/
}